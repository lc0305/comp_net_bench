#include "buf_pool.hpp"
#include "common.hpp"
#include "compress.hpp"
#include "file_cache.hpp"
#include "http_parser.hpp"
#include "http_response.hpp"
#include "networking.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <getopt.h>
#include <iostream>
#include <map>
#include <thread>

#define MAX_NUM_THREADS 64
#define READ_BUF_SIZE (1 << 12)

struct http_connection {
  networking::connection connection;
  http::http_parser current_http_request;

  inline http_connection(networking::connection connection)
      : connection(connection), current_http_request(&connection.read_buf.buf) {
  }
};

static thread_local std::map<std::uint64_t, http_connection> http_connections;
static std::atomic<std::uint64_t> connection_id{0};
static file::file_cache *file_c = nullptr;
static thread_local int current_thread = 0;
static thread_local buffer::buf_pool buf_p;

static int on_connection_accepted_cb(networking::connection *const connection,
                                     const int res) noexcept {
  if (unlikely(res <= 0)) {
    http_connections.erase(connection->user_data);
    return 0;
  }
  if (unlikely(buf_p.rent_buf(connection->read_buf.buf, READ_BUF_SIZE)))
    return 1;

  // lets start reading
  connection->event_interest = networking::RECEIVE;

#ifdef BENCH_DEBUG_PRINT
  std::cout << "[worker " << current_thread
            << "] accepted connection with fd: " << connection->conn_fd
            << " and id: " << connection->user_data << std::endl;
#endif
  return 0;
}

#define RESPONSE_HEADER_MAX_SIZE (1 << 12)

#ifdef BENCH_DEBUG_PRINT
static thread_local double time_spent_compressing = 0.0;
#endif

static int on_connection_recvd_cb(networking::connection *const connection,
                                  const ssize_t nbytes) noexcept {
  if (unlikely(nbytes <= 0))
    goto err;
  {
    const uint64_t connection_id = connection->user_data;

    const auto http_con_it = http_connections.find(connection_id);

    if (unlikely(http_con_it == std::end(http_connections)))
      goto err;

    http_connection &http_conn = http_con_it->second;

    if (likely(http_conn.current_http_request.get_state() == http::DONE))
      http_conn.current_http_request =
          http::http_parser(&connection->read_buf.buf);

    http_conn.current_http_request.parse_request_header();

    switch (http_conn.current_http_request.get_state()) {
    case http::PARSED: {
      const auto url = http_conn.current_http_request.get_url();
#ifdef BENCH_DEBUG_PRINT
      std::cout << "url: " << url << std::endl;
#endif
      const auto file_data = file_c->get_file(url);

      if (unlikely(file_data.buf == nullptr)) {
        // return 404
        auto &write_buf = connection->write_buf.buf;
        if (unlikely(buf_p.rent_buf(write_buf, RESPONSE_HEADER_MAX_SIZE)))
          goto err;

        auto response = http::http_response(connection->write_buf);

        std::size_t final_header_buf_size;
        if (unlikely((final_header_buf_size =
                          response.build_header(http::NOT_FOUND)) == 0))
          goto err;

        const auto header_buf_idx = write_buf.vecs.size() - 1;
        const auto &header_iov = write_buf.vecs[header_buf_idx];

        if (likely(final_header_buf_size != header_iov.iov_len))
          buf_p.resize_buf(write_buf, header_buf_idx, final_header_buf_size);

#ifdef BENCH_DEBUG_PRINT
        response.print_header();
#endif
      } else {

        const auto compression_algo =
            http_conn.current_http_request.get_compression_algo();

        auto &write_buf = connection->write_buf.buf;

        if (unlikely(buf_p.rent_buf(write_buf, RESPONSE_HEADER_MAX_SIZE)))
          goto err;

        const auto initial_content_buf_size =
            1 << ceiled_log2(file_data.size + sizeof(CR_LF));
        if (unlikely(buf_p.rent_buf(write_buf, initial_content_buf_size)))
          goto err;

#ifdef BENCH_DEBUG_PRINT
        http_conn.current_http_request.print_header();
        std::cout << "file_size: " << file_data.size << std::endl;
        std::cout << "initial_content_buf_size: " << initial_content_buf_size
                  << std::endl;
#endif

        const auto content_buf_idx = write_buf.vecs.size() - 1,
                   header_buf_idx = content_buf_idx - 1;
        const auto &content_iov = write_buf.vecs[content_buf_idx],
                   &header_iov = write_buf.vecs[header_buf_idx];
#ifdef BENCH_DEBUG_PRINT
        const auto start = std::chrono::high_resolution_clock::now();
#endif
        std::size_t compressed_size;
        while (unlikely((compressed_size = compress_buf(
                             file_data.buf, file_data.size,
                             static_cast<char *>(content_iov.iov_base),
                             content_iov.iov_len - sizeof(CR_LF),
                             compression_algo)) == 0)) {
          const auto new_buf_log2 = ceiled_log2(content_iov.iov_len) + 1;
          if (unlikely(new_buf_log2 > buffer::LOG2_1073741824))
            // something went wrong
            goto err;
          if (unlikely(buf_p.resize_buf(write_buf, content_buf_idx,
                                        1 << new_buf_log2)))
            goto err;
        }
#ifdef BENCH_DEBUG_PRINT
        {
          const auto end = std::chrono::high_resolution_clock::now();
          const std::chrono::duration<double> elapsed_duration = end - start;
          const double elapsed = elapsed_duration.count();
          time_spent_compressing += elapsed;
          std::printf("[worker %d] time spent compressing: %lf (total: %lf)\n",
                      current_thread, elapsed, time_spent_compressing);
        }
#endif

        auto response = http::http_response(connection->write_buf);

        std::size_t final_content_buf_size;
        if (unlikely((final_content_buf_size =
                          response.build_content(compressed_size)) == 0))
          goto err;

        if (likely(final_content_buf_size != content_iov.iov_len))
          buf_p.resize_buf(write_buf, content_buf_idx, final_content_buf_size);

        std::size_t final_header_buf_size;
        if (unlikely((final_header_buf_size = response.build_header(
                          http::OK, compressed_size, compression_algo,
                          file_data.type)) == 0))
          goto err;

        if (likely(final_header_buf_size != header_iov.iov_len))
          buf_p.resize_buf(write_buf, header_buf_idx, final_header_buf_size);

#ifdef BENCH_DEBUG_PRINT
        response.print_header();
#endif
      }

      // give back read_buf
      buf_p.hand_back_buf(connection->read_buf.buf);
      connection->read_buf.nbytes_read = 0;
      // lets start writing the result
      connection->event_interest = networking::SEND;
      break;
    }
    case http::PENDING: {
      if (unlikely(buf_p.rent_buf(connection->read_buf.buf, READ_BUF_SIZE)))
        goto err;
      connection->event_interest = networking::RECEIVE;
      break;
    }
    // should not happen
    case http::DONE:
    case http::ERROR:
      goto err;
    }
  }
  return 0;

err:
#ifdef BENCH_DEBUG_PRINT
  std::cout << "error closing connection " << connection->user_data
            << std::endl;
#endif
  connection->event_interest = networking::CLOSE;
  return 1;
}

static int on_connection_sent_cb(networking::connection *const connection,
                                 const ssize_t nbytes) noexcept {
  if (unlikely(nbytes < 0)) {
    connection->event_interest = networking::CLOSE;
    return 0;
  }
  if (likely(connection->write_buf.nbytes_written ==
             get_buf_size(connection->write_buf.buf))) {
    // give back write buf
    buf_p.hand_back_buf(connection->write_buf.buf);
    connection->write_buf.nbytes_written = 0;

    const uint64_t connection_id = connection->user_data;

    const auto http_con_it = http_connections.find(connection_id);

    if (unlikely(http_con_it == std::end(http_connections)))
      return 1;

    http_con_it->second.current_http_request.set_state(http::DONE);

    if (unlikely(buf_p.rent_buf(connection->read_buf.buf, READ_BUF_SIZE)))
      return 1;
    connection->event_interest = networking::RECEIVE;
  } else {
    // write again
    connection->event_interest = networking::SEND;
  }
  return 0;
}

static int on_connection_closed_cb(networking::connection *const connection,
                                   const int res) noexcept {
  buf_p.hand_back_buf(connection->read_buf.buf);
  buf_p.hand_back_buf(connection->write_buf.buf);
#ifdef BENCH_DEBUG_PRINT
  std::cout << "closed connection with fd: " << connection->conn_fd
            << " and id: " << connection->user_data << std::endl;
#endif
  http_connections.erase(connection->user_data);
  return 0;
}

static networking::connection *before_connection_accept_cb() noexcept {
  const auto new_connection_id =
      connection_id.fetch_add(1, std::memory_order_relaxed);
  const auto res = http_connections.emplace(
      new_connection_id, http_connection({
                             .conn_fd = -1,
                             .read_buf.nbytes_read = 0,
                             .write_buf.nbytes_written = 0,
                             .on_accepted_cb = on_connection_accepted_cb,
                             .on_recvd_cb = on_connection_recvd_cb,
                             .on_sent_cb = on_connection_sent_cb,
                             .on_closed_cb = on_connection_closed_cb,
                             .user_data = new_connection_id,
                         }));
  if (likely(res.second)) {
    // required because request starts uninitialized in broken state
    res.first->second.current_http_request.set_state(http::DONE);
    return &res.first->second.connection;
  }
  return nullptr;
}

typedef struct bench_args {
  const char *public_folder = "./public";
  int threads = 1;
  uint16_t port = 3'000;
} bench_args_t;
static bench_args_t bench_args;
static const char *const shortopts = "t:f:p:h";
static const struct option long_options[] = {
    {"threads", required_argument, NULL, 't'},
    {"public_folder", required_argument, NULL, 'f'},
    {"port", required_argument, NULL, 'p'},
    {"help", no_argument, NULL, 'h'}};
static const char *const usage =
    "Usage: %s [--threads (-t) <number of threads>] [--public_folder <public "
    "folder with static files>] [--port "
    "<port to listen on>] [--help (-h)]\n";

static inline void read_bench_args(const int argc, char *const *argv,
                                   bench_args_t *const bench_args) noexcept {
  int option_index = 0, opt;
  while ((opt = getopt_long(argc, argv, shortopts, long_options,
                            &option_index)) != -1) {
    switch (opt) {
    case 't':
      bench_args->threads = std::atoi(optarg);
      if (unlikely(bench_args->threads > MAX_NUM_THREADS))
        exit(EXIT_FAILURE);
      break;
    case 'f':
      bench_args->public_folder = optarg;
      break;
    case 'p':
      bench_args->port = std::atoi(optarg);
      break;
    case 'h':
      printf(usage, argv[0]);
      exit(EXIT_SUCCESS);
      break;
    default:
      fprintf(stderr, usage, argv[0]);
      exit(EXIT_FAILURE);
    }
  }
}

inline void init() noexcept {
  file_c = new file::file_cache(bench_args.public_folder);
  register_before_connection_accept_cb(before_connection_accept_cb);
}

static void worker(const int thread_id) noexcept {
  current_thread = thread_id;
  networking::loop_config_t loop_config = {.mode = networking::SERVER,
                                           .server.addr = 0,
                                           .server.port = bench_args.port};
  if (unlikely(networking::loop_init(&loop_config))) {
    std::cout << "Error initializing networking loop" << std::endl;
    return;
  }
  std::printf("[worker %d] serving static files: %s\n[worker %d] listening on "
              "port: %d\n",
              current_thread, bench_args.public_folder, current_thread,
              bench_args.port);
  std::fflush(stdout);
  while (likely(!networking::loop(&loop_config)))
    ;
  networking::loop_destruct(&loop_config);
}

int main(int argc, char *const *const argv) noexcept {
  read_bench_args(argc, argv, &bench_args);
  init();

  std::vector<std::thread> thread_handles;
  for (int i = 1; i < bench_args.threads; ++i) {
    thread_handles.emplace_back(std::thread(worker, i));
  }
  worker(0);

  for (auto &thread_handle : thread_handles)
    thread_handle.join();
  return 0;
}