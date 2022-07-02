#include "buf_pool.hpp"
#include "common.hpp"
#include "http_parser.hpp"
#include "http_response.hpp"
#include "networking.hpp"
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <string_view>
#include <tuple>

#define READ_BUF_SIZE (1 << 16)

static const char request_payload[] =
    "GET /IMG_2693.jpeg HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\nAccept: "
    "text/html,image/jpeg\r\nAccept-Encoding: lz4\r\nConnection: "
    "Keep-Alive\r\n\n";

static thread_local buffer::buf_pool buf_p;
static thread_local std::map<
    std::uint64_t,
    std::tuple<networking::connection_t, http::http_parser, std::uint64_t>>
    http_connection_map;

static int send_request(networking::connection *const connection) noexcept {
  const std::size_t request_payload_size = sizeof(request_payload);
  if (unlikely(buf_p.rent_buf(connection->write_buf.buf, request_payload_size)))
    return 1;

  const auto iovec_idx = connection->write_buf.buf.vecs.size() - 1;
  const auto &iovec = connection->write_buf.buf.vecs[iovec_idx];

  std::memcpy(iovec.iov_base, request_payload, request_payload_size);

  connection->event_interest = networking::SEND;
  return 0;
}

static int on_connection_connected_cb(networking::connection *const connection,
                                      const int res) noexcept {
  if (unlikely(res))
    return 1;
  return send_request(connection);
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
    //#ifdef BENCH_DEBUG_PRINT
    std::cout << "completed " << std::get<2>(http_connection)
              << ". request for connection with id " << connection->user_data
              << std::endl;
    //#endif
    ++std::get<2>(http_connection);
    response.set_state(http::DONE);
    buf_p.hand_back_buf(connection->read_buf.buf);
    connection->read_buf.nbytes_read = 0;
    return send_request(connection);
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

int main(int argc, const char *const *const argv) noexcept {
  networking::loop_config_t loop_config = {.mode = networking::CLIENT};
  if (networking::loop_init(&loop_config))
    std::perror(nullptr);

  const std::uint64_t n_connections = 50;
  for (std::uint64_t n = 0; n < n_connections; ++n) {
    networking::connection_t connection = {
        .conn_fd = -1,
        .read_buf.nbytes_read = 0,
        .write_buf.nbytes_written = 0,
        .on_connected_cb = on_connection_connected_cb,
        .on_recvd_cb = on_connection_recvd_cb,
        .on_sent_cb = on_connection_sent_cb,
        .on_closed_cb = on_connection_closed,
        .user_data = n,
    };

    const auto pair = http_connection_map.emplace(
        n, std::make_tuple(connection, http::http_parser(nullptr), 0));
    if (likely(!pair.second))
      std::cout << "error adding connection with id: " << n << std::endl;
    auto &http_connection = pair.first->second;
    std::get<1>(http_connection) =
        http::http_parser(&std::get<0>(http_connection).read_buf.buf);
    if (unlikely(networking::establish_connection_to_addr(
            &loop_config, &std::get<0>(http_connection), "127.0.0.1", 3'000)))
      std::perror(nullptr);
  }
  while (likely(!networking::loop(&loop_config)))
    ;
  networking::loop_destruct(&loop_config);
  return 0;
}