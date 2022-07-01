#ifndef __NETWORKING_H__
#define __NETWORKING_H__

#include "common.hpp"
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

typedef enum connection_state {
  ACCEPT_PENDING,
  ACCEPTED,
  REFUSED,
  CLOSE_PENDING,
  CLOSED,
} connection_state_t;

typedef enum event_interest {
  NONE,
  READ,
  WRITE,
  CLOSE,
} event_interest_t;

typedef enum event_state {
  NOP,
  ACCEPTING,
  READING,
  WRITING,
  CLOSING,
} event_state_t;

typedef struct connection {
  struct sockaddr_in client_addr;
  socklen_t addr_len;
  int conn_fd;
  connection_state_t conn_state;
  event_interest_t event_interest;
  event_state_t event_state;
  read_buf_t read_buf;
  write_buf_t write_buf;
  int (*on_accepted_cb)(struct connection *connection, int res);
  int (*on_recvd_cb)(struct connection *connection, ssize_t nbytes);
  int (*on_sent_cb)(struct connection *connection, ssize_t nbytes);
  int (*on_closed_cb)(struct connection *connection, int res);
  uint64_t user_data;
} connection_t;

typedef connection_t *(*before_connection_accept_cb_t)();
typedef int (*on_connection_accepted_cb_t)(connection_t *connection, int res);
typedef int (*on_connection_recvd_cb_t)(connection_t *connection,
                                        ssize_t nbytes);
typedef int (*on_connection_sent_cb_t)(connection_t *connection,
                                       ssize_t nbytes);
typedef int (*on_connection_closed_cb_t)(connection_t *connection, int res);

static int listening_socket_init(uint32_t addr, uint16_t port) {
  const int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (unlikely(sock_fd == -1))
    goto err_socket;

  {
    const int enable = 1;
    if (unlikely(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable,
                            sizeof(enable)) < 0))
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
  perror(NULL);
  return -1;
}

static before_connection_accept_cb_t before_connection_accept = NULL;
inline int register_before_connection_accept_cb(
    before_connection_accept_cb_t before_connection_accept_cb) {
  before_connection_accept = before_connection_accept_cb;
  return 0;
}

#ifdef __linux__

#define IO_URING_QUEUE_DEPTH (1 << 12)

inline int add_accept_sqe_for_connection(struct io_uring *const ring,
                                         int listening_sock_fd,
                                         connection_t *const connection) {
  struct io_uring_sqe *const sqe = io_uring_get_sqe(ring);
  connection->addr_len = sizeof(connection->client_addr);
  io_uring_prep_accept(
      sqe, listening_sock_fd,
      reinterpret_cast<struct sockaddr *>(&connection->client_addr),
      &connection->addr_len, 0);
  io_uring_sqe_set_data(sqe, connection);
  connection->conn_state = ACCEPT_PENDING;
  connection->event_state = ACCEPTING;
  return 0;
}

inline int add_read_sqe_for_connection(struct io_uring *const ring,
                                       connection_t *const connection) {
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
  connection->event_state = READING;
  return 0;
}

inline int add_write_sqe_for_connection(struct io_uring *const ring,
                                        connection_t *const connection) {
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
  connection->event_state = WRITING;
  return 0;
}

inline int add_close_sqe_for_connection(struct io_uring *const ring,
                                        connection_t *const connection) {
  struct io_uring_sqe *const sqe = io_uring_get_sqe(ring);
  io_uring_prep_close(sqe, connection->conn_fd);
  io_uring_sqe_set_data(sqe, connection);
  connection->conn_state = CLOSE_PENDING;
  connection->event_state = CLOSING;
  return 0;
}

static int listening_sock_fd = -1;
static struct io_uring ring;

inline int server_loop(const uint32_t addr, const uint16_t port) {
  if (unlikely(before_connection_accept == NULL))
    return 1;

  listening_sock_fd = listening_socket_init(addr, port);
  if (unlikely(listening_sock_fd < 0))
    return -1;

  if (unlikely(io_uring_queue_init(IO_URING_QUEUE_DEPTH, &ring, 0)))
    goto err_queue_init;

  {
    connection_t *const connection = before_connection_accept();
    if (unlikely(connection == NULL))
      goto err_before_connection_accept;
    add_accept_sqe_for_connection(&ring, listening_sock_fd, connection);
  }

  io_uring_submit(&ring);

  std::cout << "io_uring: entering event loop..." << std::endl;

  struct io_uring_cqe *cqe;
  for (;;) {
    const int ret = io_uring_wait_cqe(&ring, &cqe);
#ifdef BENCH_DEBUG_PRINT
    std::cout << "io_uring: event incoming ret: " << ret << std::endl;
#endif
    if (unlikely(ret < 0))
      goto err_wait_cqe;

    connection_t *const connection = (connection_t *)cqe->user_data;
    const int res = cqe->res;

    switch (connection->conn_state) {
    case ACCEPT_PENDING: {
      switch (connection->event_state) {
      case NOP:
      case READING:
      case WRITING:
      case CLOSING:
        // should not be in any of these states
        goto seen;
      case ACCEPTING: {
        connection->conn_state = likely(res > 0) ? ACCEPTED : REFUSED;
        connection->conn_fd = res;
        const auto on_accepted_ret =
            connection->on_accepted_cb(connection, res);
        {
          connection_t *const connection = before_connection_accept();
          if (unlikely(connection == NULL))
            goto seen;
          add_accept_sqe_for_connection(&ring, listening_sock_fd, connection);
        }
        if (unlikely(connection->conn_state != ACCEPTED))
          goto submit_and_seen;
        break;
      }
      }
    }
    // fallthrough
    case ACCEPTED: {
      switch (connection->event_state) {
      case NOP:
      case CLOSING:
        // should not be in any of these states
        goto seen;
      case ACCEPTING:
        break;
      case READING: {
        if (likely(res > 0))
          connection->read_buf.nbytes_read += res;
        connection->on_recvd_cb(connection, res);
        break;
      }
      case WRITING: {
        if (likely(res > 0)) {
          connection->write_buf.nbytes_written += res;
          if (unlikely(connection->write_buf.nbytes_written <
                       get_buf_size(connection->write_buf.buf))) {
            add_write_sqe_for_connection(&ring, connection);
            goto submit_and_seen;
          }
        }
        connection->on_sent_cb(connection, res);
        // break;
      }
      }

      switch (connection->event_interest) {
      // should not be in that state
      case NONE:
        goto seen;
      case READ:
        add_read_sqe_for_connection(&ring, connection);
        break;
      case WRITE:
        add_write_sqe_for_connection(&ring, connection);
        break;
      case CLOSE:
        add_close_sqe_for_connection(&ring, connection);
        break;
      }
      goto submit_and_seen;
    }
    case CLOSE_PENDING: {
      switch (connection->event_state) {
      case NOP:
      case ACCEPTING:
      case READING:
      case WRITING:
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
    io_uring_submit(&ring);
  seen:
    io_uring_cqe_seen(&ring, cqe);
  }

  return 0;
err_before_connection_accept:
err_wait_cqe:
// todo destruct ring
err_queue_init:
  close(listening_sock_fd);
  perror(NULL);
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
