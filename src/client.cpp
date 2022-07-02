#include "buf_pool.hpp"
#include "common.hpp"
#include "compress.hpp"
#include "http_parser.hpp"
#include "http_response.hpp"
#include "networking.hpp"
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <getopt.h>
#include <iostream>
#include <map>
#include <string_view>
#include <tuple>

#define REQUEST_MAX_SIZE (1 << 12)
#define READ_BUF_SIZE (1 << 16)

static thread_local buffer::buf_pool buf_p;
static thread_local std::map<
    std::uint64_t,
    std::tuple<networking::connection_t, http::http_parser, std::uint64_t>>
    http_connection_map;
static std::atomic<int> request_count{0};
typedef struct bench_args {
  int threads = 1;
  int connections = 1;
  int requests = 1'000;
  compression::compression_algo algorithm = compression::NONE;
  const char *file = "bundle.js";
  const char *ip = "127.0.0.1";
  uint16_t port = 3'000;
} bench_args_t;
static bench_args_t bench_args;

static int send_request(networking::connection *const connection,
                        const char *const file,
                        const compression::compression_algo comp_alg) noexcept {
  if (unlikely(buf_p.rent_buf(connection->write_buf.buf, REQUEST_MAX_SIZE)))
    return 1;

  const auto iovec_idx = connection->write_buf.buf.vecs.size() - 1;
  const auto &iovec = connection->write_buf.buf.vecs[iovec_idx];

  const ssize_t ret = std::snprintf(
      static_cast<char *>(iovec.iov_base), iovec.iov_len,
      "GET /%s HTTP/1.1\r\nUser-Agent: comp_net_bench_client/1.0\r\nAccept: "
      "text/html, image/jpeg, application/json, "
      "application/javascript\r\nAccept-Encoding: %s\r\nConnection: "
      "Keep-Alive\r\n\n",
      file, http::compression_algo_to_str(comp_alg));

  if (unlikely(unlikely(ret < 0) || unlikely(ret > iovec.iov_len))) {
    connection->event_interest = networking::CLOSE;
    return 1;
  }

  buf_p.resize_buf(connection->write_buf.buf, iovec_idx, ret);

  connection->event_interest = networking::SEND;
  return 0;
}

static int on_connection_connected_cb(networking::connection *const connection,
                                      const int res) noexcept {
  if (unlikely(res))
    return 1;
  return send_request(connection, bench_args.file, bench_args.algorithm);
}

static int on_connection_sent_cb(networking::connection *const connection,
                                 const ssize_t res) noexcept {
  // give back write buf
  buf_p.hand_back_buf(connection->write_buf.buf);
  connection->write_buf.nbytes_written = 0;

  if (unlikely(buf_p.rent_buf(connection->read_buf.buf, READ_BUF_SIZE)))
    return 1;

  // wait for response
  connection->event_interest = networking::RECEIVE;
  return 0;
}

bool headers_parsed = false;

static int on_connection_recvd_cb(networking::connection *const connection,
                                  const ssize_t res) noexcept {
  const auto pair_it = http_connection_map.find(connection->user_data);
  if (pair_it == std::end(http_connection_map))
    return 1;
  auto &http_connection = pair_it->second;

  if (unlikely(std::get<1>(http_connection).get_state() == http::DONE))
    // previous request was completed
    std::get<1>(http_connection) = http::http_parser(&connection->read_buf.buf);

  auto &response = std::get<1>(http_connection);

  if (unlikely(response.get_state() != http::PARSED)) {
    response.parse_response_header();
    if (likely(response.get_state() == http::PARSED)) {
#ifdef BENCH_DEBUG_PRINT
      response.print_header();
#endif
    } else {
      // header is too large or not parsable
      goto err;
    }
  }

  if (response.get_total_response_size() <= connection->read_buf.nbytes_read) {
#ifdef BENCH_DEBUG_PRINT
    std::cout << "completed " << std::get<2>(http_connection)
              << ". request for connection with id " << connection->user_data
              << std::endl;
#endif
    ++std::get<2>(http_connection);
    request_count.fetch_add(1, std::memory_order_relaxed);
    response.set_state(http::DONE);
    buf_p.hand_back_buf(connection->read_buf.buf);
    connection->read_buf.nbytes_read = 0;
    return send_request(connection, bench_args.file, bench_args.algorithm);
  }
  // extend buf
  if (unlikely(buf_p.rent_buf(connection->read_buf.buf, READ_BUF_SIZE)))
    return 1;
  connection->event_interest = networking::RECEIVE;
  return 0;
err:
  connection->event_interest = networking::CLOSE;
  return 1;
}

static int on_connection_closed(networking::connection *const connection,
                                const int res) noexcept {
  buf_p.hand_back_buf(connection->read_buf.buf);
  buf_p.hand_back_buf(connection->write_buf.buf);
  return 0;
}

static const char *const shortopts = "t:c:a:f:i:p:n:h";
static const struct option long_options[] = {
    {"threads", required_argument, NULL, 't'},
    {"connections", required_argument, NULL, 'c'},
    {"algorithm", required_argument, NULL, 'a'},
    {"file", required_argument, NULL, 'f'},
    {"ip", required_argument, NULL, 'i'},
    {"port", required_argument, NULL, 'p'},
    {"requests", required_argument, NULL, 'n'},
    {"help", no_argument, NULL, 'h'}};
static const char *const usage =
    "Usage: %s [--threads (-t) <number of threads>] [--connections (-c) "
    "<number of concurrent connections>] [--algorithm (-a) <compression "
    "algorithm (none|deflate|lz4)>] [--file <file to request>] [--ip <ip "
    "to request against>] [--port <port to request against>] [--requests "
    "<number of requests to perform>] [--help (-h)]\n";

constexpr void to_lower(char *str) noexcept {
  for (; *str; ++str)
    *str = tolower(*str);
}

static inline void read_bench_args(const int argc, char *const *argv,
                                   bench_args_t *const bench_args) noexcept {
  int option_index = 0, opt;
  while ((opt = getopt_long(argc, argv, shortopts, long_options,
                            &option_index)) != -1) {
    switch (opt) {
    case 't':
      bench_args->threads = std::atoi(optarg);
      break;
    case 'c':
      bench_args->connections = std::atoi(optarg);
      break;
    case 'a': {
      to_lower(optarg);
      if (!std::strcmp(optarg, "deflate")) {
        bench_args->algorithm = compression::DEFLATE;
        break;
      }
      if (!std::strcmp(optarg, "lz4")) {
        bench_args->algorithm = compression::LZ4;
        break;
      }
      if (!std::strcmp(optarg, "") || !std::strcmp(optarg, "none")) {
        bench_args->algorithm = compression::NONE;
        break;
      }
      goto err;
    }
    case 'f':
      bench_args->file = optarg;
      break;
    case 'i':
      bench_args->ip = optarg;
      break;
    case 'p':
      bench_args->port = std::atoi(optarg);
      break;
    case 'n':
      bench_args->requests = std::atoi(optarg);
      break;
    case 'h':
      printf(usage, argv[0]);
      exit(EXIT_SUCCESS);
      break;
    default:
    err:
      fprintf(stderr, usage, argv[0]);
      exit(EXIT_FAILURE);
    }
  }
}

int main(int argc, char *const *const argv) noexcept {
  read_bench_args(argc, argv, &bench_args);

  networking::loop_config_t loop_config = {.mode = networking::CLIENT};
  if (networking::loop_init(&loop_config))
    std::perror(nullptr);

  for (std::int64_t n = 0; n < bench_args.connections; ++n) {
    networking::connection_t connection = {
        .conn_fd = -1,
        .read_buf.nbytes_read = 0,
        .write_buf.nbytes_written = 0,
        .on_connected_cb = on_connection_connected_cb,
        .on_recvd_cb = on_connection_recvd_cb,
        .on_sent_cb = on_connection_sent_cb,
        .on_closed_cb = on_connection_closed,
        .user_data = std::uint64_t(n),
    };

    const auto pair = http_connection_map.emplace(
        n, std::make_tuple(connection, http::http_parser(nullptr), 0));
    if (likely(!pair.second))
      std::cout << "error adding connection with id: " << n << std::endl;
    auto &http_connection = pair.first->second;
    std::get<1>(http_connection) =
        http::http_parser(&std::get<0>(http_connection).read_buf.buf);
    if (unlikely(networking::establish_connection_to_addr(
            &loop_config, &std::get<0>(http_connection), bench_args.ip,
            bench_args.port)))
      std::perror(nullptr);
  }
  const auto start = std::chrono::high_resolution_clock::now();
  while (likely(likely(!networking::loop(&loop_config) &&
                       likely(request_count.load(std::memory_order_relaxed) <
                              bench_args.requests))))
    ;
  const auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> elapsed = end - start;
  std::cout << "elapsed time: " << elapsed.count() << "s\n";
  for (const auto &pair : http_connection_map)
    close(std::get<0>(pair.second).conn_fd);
  networking::loop_destruct(&loop_config);
  return 0;
}