#ifndef __HTTP_REQUEST_PARSER_H__
#define __HTTP_REQUEST_PARSER_H__

#include "common.hpp"
#include "compress.hpp"
#include "http_status.hpp"
#include "networking.hpp"
#include <charconv>
#include <cinttypes>
#include <iostream>
#include <map>
#include <string_view>

namespace http {

enum http_request_state {
  PENDING,
  PARSED,
  ERROR,
  DONE,
};

enum http_method {
  NO_METHOD,
  HTTP_GET,
};

enum http_version {
  NO_VERSION,
  VERSION_1_1,
};

#define GET_STR "GET"
#define HTTP_1_1_STR "HTTP/1.1"
#define CR_LF_STR "\r\n"

class http_request_parser {
private:
  http_request_state state;
  http_method method;
  http_version version;
  http_status_code status;
  const networking::read_buf_t *read_buf;
  std::size_t parsed_bytes;
  std::string_view url;
  std::map<std::string_view, std::string_view> header;

  inline std::size_t parse_header_line(const std::string_view request,
                                       const std::size_t line_start,
                                       bool &done) noexcept {
    const auto pos_colon = request.find(':', line_start);
    if (unlikely(std::string_view::npos == pos_colon))
      return std::string_view::npos;

    const auto pos_cr_lf = request.find(CR_LF_STR, pos_colon + 1);
    if (unlikely(std::string_view::npos == pos_colon))
      return std::string_view::npos;

    const auto header_value_start = pos_colon + 2;
    header.emplace(
        request.substr(line_start, pos_colon - line_start),
        request.substr(header_value_start, pos_cr_lf - header_value_start));

    const auto next_line_start = pos_cr_lf + sizeof(CR_LF_STR) - 1;
    const auto potential_end_of_header = next_line_start + 1;
    if (unlikely(likely(request.size() > potential_end_of_header) &&
                 request.at(potential_end_of_header) == '\n')) {
      done = true;
      return potential_end_of_header;
    }
    return next_line_start;
  }

public:
  inline http_request_parser(
      const networking::read_buf_t *const read_buf) noexcept
      : state(PENDING), method(NO_METHOD), version(NO_VERSION),
        status(NO_STATUS), read_buf(read_buf), parsed_bytes(0) {}

  inline http_request_state parse_http() noexcept {
    this->state = PENDING;
    for (const auto &iov : read_buf->buf.vecs) {
      const auto request = std::string_view(
          static_cast<const char *>(iov.iov_base), iov.iov_len);
      const auto pos_first_space = request.find(' ');
      if (unlikely(std::string_view::npos == pos_first_space))
        goto err;
      // we only support get right now
      if (unlikely(std::string_view::npos ==
                   request.find(GET_STR, 0, sizeof(GET_STR) - 1)))
        goto err;
      this->method = HTTP_GET;
      const auto pos_url_start = pos_first_space + 1;
      const auto pos_second_space = request.find(' ', pos_url_start);
      if (unlikely(std::string_view::npos == pos_second_space))
        goto err;
      this->url =
          request.substr(pos_url_start, pos_second_space - pos_url_start);

      const auto pos_first_cr_lf =
          request.find(CR_LF_STR, pos_second_space + 1);
      if (unlikely(std::string_view::npos == pos_first_cr_lf))
        goto err;
      // we only support 1.1 right now
      if (unlikely(std::string_view::npos ==
                   request.find(HTTP_1_1_STR, pos_second_space + 1,
                                sizeof(HTTP_1_1_STR) - 1)))
        goto err;
      this->version = VERSION_1_1;

      const auto pos_header_start = pos_first_cr_lf + sizeof(CR_LF_STR) - 1;
      if (unlikely(pos_header_start >= request.size()))
        goto err;

      std::size_t header_pos = pos_header_start;
      bool done = done;
      while (likely(likely(header_pos =
                               parse_header_line(request, header_pos, done)) !=
                    std::string_view::npos) &&
             likely(!done))
        ;

      if (unlikely(!done))
        goto err;

      parsed_bytes += header_pos;
    }
    this->state = PARSED;
    return this->state;
  err:
    this->state = ERROR;
    return this->state;
  }

  inline void set_state(const http_request_state state) noexcept {
    this->state = state;
  }

  inline http_request_state get_state() const noexcept { return this->state; }

  inline void set_status(const http_status_code status) noexcept {
    this->status = status;
  }
  inline http_status_code get_status() const noexcept { return this->status; }

  inline const std::string_view get_url() const noexcept { return this->url; }

  inline const std::string_view
  get_header_value_for_field(const std::string_view field) noexcept {
    const auto header_value_it = this->header.find(field);
    if (unlikely(header_value_it == std::end(this->header)))
      return std::string_view();
    return header_value_it->second;
  }

  void print_header() noexcept {
    for (const auto &header_field : this->header)
      std::cout << header_field.first << ": " << header_field.second
                << std::endl;
  }

  inline compression::compression_algo get_compression_algo() noexcept {
    const auto accept_encoding = get_header_value_for_field("Accept-Encoding");

    if (accept_encoding.empty())
      return compression::NONE;

    if (contains(accept_encoding, "lz4"))
      return compression::LZ4;

    if (contains(accept_encoding, "deflate"))
      return compression::DEFLATE;

    return compression::NONE;
  }
};

} // namespace http

#endif