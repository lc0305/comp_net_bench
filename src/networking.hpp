#ifndef __NETWORKING_H__
#define __NETWORKING_H__

#include "common.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <functional>
#include <inttypes.h>
#include <iostream>
#include <netinet/in.h>
#include <numeric>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <vector>

#ifdef __linux__
#include <liburing.h>
#elif defined(__MACH__)
#error "platform not supported (yet)"
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>
#else
#error "platform not supported"
#endif

#define MAX_PENDING_CONNECTIONS (1 << 8)

// #ifdef __cplusplus
// extern "C" {
// #endif
namespace networking {

typedef struct buf {
  std::vector<iovec> vecs;
  std::vector<iovec> vecs_mut;
} buf_t;

inline std::size_t get_buf_size(const buf_t &buf) noexcept {
  return std::accumulate(
      std::begin(buf.vecs), std::end(buf.vecs), std::size_t{0},
      [](const std::size_t current_size, const iovec &io_vec) {
        return current_size + io_vec.iov_len;
      });
}

typedef struct read_buf {
  buf_t buf;
  size_t nbytes_read;
} read_buf_t;

typedef struct write_buf {
  buf_t buf;
  size_t nbytes_written;
} write_buf_t;

typedef enum loop_mode : uint8_t {
  SERVER,
  CLIENT,
} loop_mode_t;

typedef enum connection_state {
  CONNECT_PENDING,
  CONNECTED,
  ACCEPT_PENDING,
  ACCEPTED,
  REFUSED,
  CLOSE_PENDING,
  CLOSED,
} connection_state_t;

typedef enum event_interest {
  NONE,
  RECEIVE,
  SEND,
  CLOSE,
} event_interest_t;

typedef enum event_state {
  NOP,
  CONNECTING,
  ACCEPTING,
  RECEIVING,
  SENDING,
  CLOSING,
} event_state_t;

typedef struct connection {
  struct sockaddr_in sock_addr;
  socklen_t addr_len;
  int conn_fd;
  connection_state_t conn_state;
  event_interest_t event_interest;
  event_state_t event_state;
  read_buf_t read_buf;
  write_buf_t write_buf;
  union {
    int (*on_accepted_cb)(struct connection *connection, int res);
    int (*on_connected_cb)(struct connection *connection, int res);
  };
  int (*on_recvd_cb)(struct connection *connection, ssize_t nbytes);
  int (*on_sent_cb)(struct connection *connection, ssize_t nbytes);
  int (*on_closed_cb)(struct connection *connection, int res);
  uint64_t user_data;
} connection_t;

typedef connection_t *(*before_connection_accept_cb_t)();
typedef connection_t *(*before_connection_connect_cb_t)();

static int listening_socket_init(uint32_t addr, uint16_t port) noexcept {
  const int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (unlikely(sock_fd == -1))
    goto err_socket;

  {
    const int enable = 1;
    if (unlikely(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                            &enable, sizeof(enable)) < 0))
      goto err_socket;
  }

  {
    struct sockaddr_in srv_addr;
    std::memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = htonl(addr);
    if (unlikely(bind(sock_fd,
                      reinterpret_cast<const struct sockaddr *>(&srv_addr),
                      sizeof(srv_addr)) < 0))
      goto err_socket;
  }
  if (unlikely(listen(sock_fd, MAX_PENDING_CONNECTIONS) < 0))
    goto err_socket;

  return sock_fd;

err_socket:
  close(sock_fd);
  perror(nullptr);
  return -1;
}

static before_connection_accept_cb_t before_connection_accept = nullptr;
inline int register_before_connection_accept_cb(
    before_connection_accept_cb_t before_connection_accept_cb) noexcept {
  before_connection_accept = before_connection_accept_cb;
  return 0;
}

#ifdef __linux__

#define IO_URING_QUEUE_DEPTH (1 << 12)

inline int
add_accept_sqe_for_connection(struct io_uring *const ring,
                              int listening_sock_fd,
                              connection_t *const connection) noexcept {
  struct io_uring_sqe *const sqe = io_uring_get_sqe(ring);
  connection->addr_len = sizeof(connection->sock_addr);
  io_uring_prep_accept(
      sqe, listening_sock_fd,
      reinterpret_cast<struct sockaddr *>(&connection->sock_addr),
      &connection->addr_len, 0);
  io_uring_sqe_set_data(sqe, connection);
  connection->conn_state = ACCEPT_PENDING;
  connection->event_state = ACCEPTING;
  return 0;
}

inline int
add_connect_sqe_for_connection(struct io_uring *const ring,
                               int connecting_sock_fd,
                               connection_t *const connection) noexcept {
  struct io_uring_sqe *const sqe = io_uring_get_sqe(ring);
  connection->addr_len = sizeof(connection->sock_addr);
  io_uring_prep_connect(
      sqe, connecting_sock_fd,
      reinterpret_cast<struct sockaddr *>(&connection->sock_addr),
      connection->addr_len);
  io_uring_sqe_set_data(sqe, connection);
  connection->conn_fd = connecting_sock_fd;
  connection->conn_state = CONNECT_PENDING;
  connection->event_state = CONNECTING;
  return 0;
}

inline int
add_read_sqe_for_connection(struct io_uring *const ring,
                            connection_t *const connection) noexcept {
  struct io_uring_sqe *const sqe = io_uring_get_sqe(ring);
  size_t should_be_read = 0;
  const size_t nbytes_read = connection->read_buf.nbytes_read;
  buf_t *const buf = &connection->read_buf.buf;
  for (size_t i = 0; i < buf->vecs.size(); ++i) {
    const size_t iov_len = buf->vecs[i].iov_len;
    should_be_read += iov_len;
    if (likely(should_be_read >= nbytes_read)) {
      const size_t delta_missing = should_be_read - nbytes_read,
                   offset_in_iov = iov_len - delta_missing;
      buf->vecs_mut[i].iov_base =
          &static_cast<char *>(buf->vecs[i].iov_base)[offset_in_iov];
      buf->vecs_mut[i].iov_len = delta_missing;
      io_uring_prep_readv(sqe, connection->conn_fd, &buf->vecs_mut[i],
                          buf->vecs.size() - i, 0);
      break;
    }
  }
  io_uring_sqe_set_data(sqe, connection);
  connection->event_state = RECEIVING;
  return 0;
}

inline int
add_write_sqe_for_connection(struct io_uring *const ring,
                             connection_t *const connection) noexcept {
  struct io_uring_sqe *const sqe = io_uring_get_sqe(ring);
  size_t should_be_written = 0;
  const size_t nbytes_written = connection->write_buf.nbytes_written;
  buf_t *const buf = &connection->write_buf.buf;
  for (size_t i = 0; i < buf->vecs.size(); ++i) {
    const size_t iov_len = buf->vecs[i].iov_len;
    should_be_written += iov_len;
    if (likely(should_be_written >= nbytes_written)) {
      const size_t delta_missing = should_be_written - nbytes_written,
                   offset_in_iov = iov_len - delta_missing;
      buf->vecs_mut[i].iov_base =
          &static_cast<char *>(buf->vecs[i].iov_base)[offset_in_iov];
      buf->vecs_mut[i].iov_len = delta_missing;
      io_uring_prep_writev(sqe, connection->conn_fd, &buf->vecs_mut[i],
                           buf->vecs.size() - i, 0);
      break;
    }
  }
  io_uring_sqe_set_data(sqe, connection);
  connection->event_state = SENDING;
  return 0;
}

inline int
add_close_sqe_for_connection(struct io_uring *const ring,
                             connection_t *const connection) noexcept {
  struct io_uring_sqe *const sqe = io_uring_get_sqe(ring);
  io_uring_prep_close(sqe, connection->conn_fd);
  io_uring_sqe_set_data(sqe, connection);
  connection->conn_state = CLOSE_PENDING;
  connection->event_state = CLOSING;
  return 0;
}

typedef struct loop_config {
  loop_mode_t mode;
  union {
    struct {
      int _listening_sock_fd;
      uint32_t addr;
      uint16_t port;
    } server;
    struct {
    } client;
  };
  struct io_uring _ring;
} loop_config_t;

inline int establish_connection_to_addr(loop_config_t *const loop_config,
                                        connection_t *const connection,
                                        const char *const addr,
                                        const uint16_t port) noexcept {
  std::memset(&connection->sock_addr, 0, sizeof(connection->sock_addr));
  connection->sock_addr.sin_family = AF_INET;
  connection->sock_addr.sin_port = htons(port);
  if (unlikely(inet_pton(AF_INET, addr, &connection->sock_addr.sin_addr) <= 0))
    goto err_socket;

  {
    const int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (unlikely(sock_fd == -1))
      goto err_socket;

    add_connect_sqe_for_connection(&loop_config->_ring, sock_fd, connection);
    io_uring_submit(&loop_config->_ring);
  }

  return 0;
err_socket:
  return -1;
}

inline int loop_destruct(loop_config_t *const loop_config) noexcept {
  if (loop_config->server._listening_sock_fd >= 0)
    close(loop_config->server._listening_sock_fd);
  return 0;
}

inline int loop_init(loop_config_t *const loop_config) noexcept {
  loop_config->server._listening_sock_fd = -1;

  if (loop_config->mode == SERVER) {
    if (unlikely(before_connection_accept == nullptr))
      return 1;

    loop_config->server._listening_sock_fd = listening_socket_init(
        loop_config->server.addr, loop_config->server.port);
    if (unlikely(loop_config->server._listening_sock_fd < 0))
      return -1;

    if (unlikely(
            io_uring_queue_init(IO_URING_QUEUE_DEPTH, &loop_config->_ring, 0)))
      goto err_queue_init;

    {
      connection_t *const connection = before_connection_accept();
      if (unlikely(connection == nullptr))
        goto err_before_connection_accept;
      add_accept_sqe_for_connection(&loop_config->_ring,
                                    loop_config->server._listening_sock_fd,
                                    connection);
    }

    io_uring_submit(&loop_config->_ring);
    return 0;
  }

  if (unlikely(
          io_uring_queue_init(IO_URING_QUEUE_DEPTH, &loop_config->_ring, 0)))
    goto err_queue_init;
  return 0;

err_before_connection_accept:
// somehow destruct ring
err_queue_init:
  loop_destruct(loop_config);
  perror(NULL);
  return -1;
}

inline int loop(loop_config_t *const loop_config) noexcept {
#ifdef BENCH_DEBUG_PRINT
  std::cout << "io_uring: entering event loop..." << std::endl;
#endif

  struct io_uring_cqe *cqe;
  const int ret = io_uring_wait_cqe(&loop_config->_ring, &cqe);
#ifdef BENCH_DEBUG_PRINT
  std::cout << "io_uring: event incoming ret: " << ret << std::endl;
#endif
  if (unlikely(ret < 0))
    goto err_wait_cqe;

  {
    connection_t *const connection = (connection_t *)cqe->user_data;
    const int res = cqe->res;

    switch (connection->conn_state) {
    case CONNECT_PENDING: {
      switch (connection->event_state) {
      case NOP:
      case ACCEPTING:
      case RECEIVING:
      case SENDING:
      case CLOSING:
        // should not be in any of these states
        goto seen;
      case CONNECTING: {
        connection->conn_state = likely(!res) ? CONNECTED : REFUSED;
        connection->on_connected_cb(connection, res);
        if (unlikely(connection->conn_state != CONNECTED))
          goto submit_and_seen;
      }
      }
    }
    // fallthrough
    case CONNECTED: {
      switch (connection->event_state) {
      case NOP:
      case ACCEPTING:
      case CLOSING:
        // should not be in any of these states
        goto seen;
      case CONNECTING:
        goto event_interest;
      case RECEIVING:
        goto receiving;
      case SENDING:
        goto sending;
      }
    }
    case ACCEPT_PENDING: {
      switch (connection->event_state) {
      case NOP:
      case CONNECTING:
      case RECEIVING:
      case SENDING:
      case CLOSING:
        // should not be in any of these states
        goto seen;
      case ACCEPTING: {
        connection->conn_state = likely(res > 0) ? ACCEPTED : REFUSED;
        connection->conn_fd = res;
        connection->on_accepted_cb(connection, res);
        {
          connection_t *const connection = before_connection_accept();
          if (unlikely(connection == NULL))
            goto seen;
          add_accept_sqe_for_connection(&loop_config->_ring,
                                        loop_config->server._listening_sock_fd,
                                        connection);
        }
        if (unlikely(connection->conn_state != ACCEPTED))
          goto submit_and_seen;
      }
      }
    }
    // fallthrough
    case ACCEPTED: {
      switch (connection->event_state) {
      case NOP:
      case CONNECTING:
      case CLOSING:
        // should not be in any of these states
        goto seen;
      case ACCEPTING:
        break;
      case RECEIVING: {
      receiving:
        if (likely(res >= 0)) {
#ifdef BENCH_DEBUG_PRINT
          std::cout << "received " << res
                    << " bytes for connection: " << connection->user_data
                    << std::endl;
#endif
          connection->read_buf.nbytes_read += res;
        }
        connection->on_recvd_cb(connection, res);
        break;
      }
      case SENDING: {
      sending:
        if (likely(res > 0)) {
#ifdef BENCH_DEBUG_PRINT
          std::cout << "sent " << res
                    << " bytes for connection: " << connection->user_data
                    << std::endl;
#endif
          connection->write_buf.nbytes_written += res;
          if (unlikely(connection->write_buf.nbytes_written <
                       get_buf_size(connection->write_buf.buf))) {
            add_write_sqe_for_connection(&loop_config->_ring, connection);
            goto submit_and_seen;
          }
        }
        connection->on_sent_cb(connection, res);
      }
      }
    event_interest:
      switch (connection->event_interest) {
      // should not be in that state
      case NONE:
        goto seen;
      case RECEIVE:
        add_read_sqe_for_connection(&loop_config->_ring, connection);
        break;
      case SEND:
        add_write_sqe_for_connection(&loop_config->_ring, connection);
#ifdef BENCH_DEBUG_PRINT
        std::cout << "added write sqe for connection: " << connection->user_data
                  << std::endl;
#endif
        break;
      case CLOSE:
        add_close_sqe_for_connection(&loop_config->_ring, connection);
        break;
      }
      goto submit_and_seen;
    }
    case CLOSE_PENDING: {
      switch (connection->event_state) {
      case NOP:
      case CONNECTING:
      case ACCEPTING:
      case RECEIVING:
      case SENDING:
        // should not be in any of these states
        break;
      case CLOSING: {
        if (likely(!res))
          connection->conn_state = CLOSED;
        connection->on_closed_cb(connection, res);
        break;
      }
      }
      goto seen;
    }
    case REFUSED:
    case CLOSED:
      goto seen;
    }

  submit_and_seen:
#ifdef BENCH_DEBUG_PRINT
    std::cout << "io_uring: submit and seen" << std::endl;
#endif
    io_uring_submit(&loop_config->_ring);
  seen:
    io_uring_cqe_seen(&loop_config->_ring, cqe);
  }

  return 0;
err_wait_cqe:
  return 1;
}

#elif defined(__MACH__)
#error "platform not supported (yet)"
#else
#error "platform not supported"
#endif

// #ifdef __cplusplus
// }
// #endif
} // namespace networking

#endif
