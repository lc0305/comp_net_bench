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

class http_parser {
private:
  http_request_state state;
  http_method method;
  http_version version;
  http_status_code status;
  const networking::buf_t *net_buf;
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
    {
      const auto pair = header.emplace(
          request.substr(line_start, pos_colon - line_start),
          request.substr(header_value_start, pos_cr_lf - header_value_start));
#ifdef BENCH_DEBUG_PRINT
      if (pair.second)
        std::cout << "Inserted field: " << pair.first->first
                  << " with value: " << pair.first->second << std::endl;
#endif
    }
    const auto next_line_start = pos_cr_lf + sizeof(CR_LF_STR) - 1;
    const auto potential_end_of_header = next_line_start + 1;
    if (unlikely(
            likely(request.size() > potential_end_of_header) &&
            // check potential_end_of_header and potential_end_of_header - 1 due
            // to spaces
            unlikely(
                unlikely(request.at(potential_end_of_header - 1) == '\n') ||
                unlikely(request.at(potential_end_of_header) == '\n')))) {
      done = true;
      return potential_end_of_header;
    }
    return next_line_start;
  }

public:
  inline http_parser(const networking::buf_t *const net_buf) noexcept
      : state(PENDING), method(NO_METHOD), version(NO_VERSION),
        status(NO_STATUS), net_buf(net_buf), parsed_bytes(0) {}

  inline http_request_state parse_request_header() noexcept {
    this->state = PENDING;
    if (unlikely(net_buf->vecs.size() <= 0))
      return this->state;
    const auto &iov = net_buf->vecs.back();
    const auto request =
        std::string_view(static_cast<const char *>(iov.iov_base), iov.iov_len);
    {
      const auto pos_first_space = request.find(' ');
      if (unlikely(std::string_view::npos == pos_first_space)) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: could not extract first space"
                  << std::endl;
#endif
        goto err;
      }
      // we only support get right now
      if (unlikely(std::string_view::npos ==
                   request.find(GET_STR, 0, sizeof(GET_STR) - 1))) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: could not extract HTTP method"
                  << std::endl;
#endif
        goto err;
      }
      this->method = HTTP_GET;
      const auto pos_url_start = pos_first_space + 1;
      const auto pos_second_space = request.find(' ', pos_url_start);
      if (unlikely(std::string_view::npos == pos_second_space)) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: could not extract second space"
                  << std::endl;
#endif
        goto err;
      }
      this->url =
          request.substr(pos_url_start, pos_second_space - pos_url_start);

      const auto pos_first_cr_lf =
          request.find(CR_LF_STR, pos_second_space + 1);
      if (unlikely(std::string_view::npos == pos_first_cr_lf)) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: could not extract first CR LF"
                  << std::endl;
#endif
        goto err;
      }
      // we only support 1.1 right now
      if (unlikely(std::string_view::npos ==
                   request.find(HTTP_1_1_STR, pos_second_space + 1,
                                sizeof(HTTP_1_1_STR) - 1))) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: could not extract HTTP version"
                  << std::endl;
#endif
        goto err;
      }
      this->version = VERSION_1_1;

      const auto pos_header_start = pos_first_cr_lf + sizeof(CR_LF_STR) - 1;
      if (unlikely(pos_header_start >= request.size())) {
#ifdef BENCH_DEBUG_PRINT
        std::cout
            << "http parsing error: header start greater than request size"
            << std::endl;
#endif
        goto err;
      }

      std::size_t header_pos = pos_header_start;
      bool done = false;
      while (likely(
          likely((header_pos = parse_header_line(request, header_pos, done)) !=
                 std::string_view::npos) &&
          likely(!done)))
        ;

      if (unlikely(!done)) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: http request does not end with LF"
                  << std::endl;
#endif
        goto err;
      }

      parsed_bytes += header_pos;
      this->state = PARSED;
      return this->state;
    }
  err:
#ifdef BENCH_DEBUG_PRINT
    std::cout << "error parsing request:" << std::endl << request << std::endl;
#endif
    this->state = ERROR;
    return this->state;
  }

  inline http_request_state parse_response_header() noexcept {
    this->state = PENDING;
    if (unlikely(net_buf->vecs.size() <= 0))
      return this->state;
    const auto &iov = net_buf->vecs.back();
    const auto response =
        std::string_view(static_cast<const char *>(iov.iov_base), iov.iov_len);
    {
      const auto pos_first_space = response.find(' ');
      if (unlikely(std::string_view::npos == pos_first_space)) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: could not extract first space"
                  << std::endl;
#endif
        goto err;
      }
      // we only support 1.1 right now
      if (unlikely(std::string_view::npos ==
                   response.find(HTTP_1_1_STR, 0, sizeof(HTTP_1_1_STR) - 1))) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: could not extract HTTP version"
                  << std::endl;
#endif
        goto err;
      }
      this->version = VERSION_1_1;
      const auto pos_status_start = pos_first_space + 1;
      const auto pos_second_space = response.find(' ', pos_status_start);
      if (unlikely(std::string_view::npos == pos_second_space)) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: could not extract second space"
                  << std::endl;
#endif
        goto err;
      }

      const auto status_res = to_int<int>(response.substr(
          pos_status_start, pos_second_space - pos_status_start));
      if (unlikely(!status_res.has_value())) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: could not parse status" << std::endl;
#endif
        goto err;
      }
      this->status = static_cast<http_status_code>(status_res.value());

      const auto pos_first_cr_lf =
          response.find(CR_LF_STR, pos_second_space + 1);
      if (unlikely(std::string_view::npos == pos_first_cr_lf)) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: could not extract first CR LF"
                  << std::endl;
#endif
        goto err;
      }

      const auto pos_header_start = pos_first_cr_lf + sizeof(CR_LF_STR) - 1;
      if (unlikely(pos_header_start >= response.size())) {
#ifdef BENCH_DEBUG_PRINT
        std::cout
            << "http parsing error: header start greater than response size"
            << std::endl;
#endif
        goto err;
      }

      std::size_t header_pos = pos_header_start;
      bool done = false;
      while (likely(
          likely((header_pos = parse_header_line(response, header_pos, done)) !=
                 std::string_view::npos) &&
          likely(!done)))
        ;

      if (unlikely(!done)) {
#ifdef BENCH_DEBUG_PRINT
        std::cout << "http parsing error: http request does not end with LF"
                  << std::endl;
#endif
        goto err;
      }

      parsed_bytes += header_pos;
      this->state = PARSED;
      return this->state;
    }
  err:
#ifdef BENCH_DEBUG_PRINT
    std::cout << "error parsing request:" << std::endl << response << std::endl;
#endif
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

  inline ssize_t get_content_length() noexcept {
    const auto content_length = get_header_value_for_field("Content-Length");

    if (unlikely(content_length.empty()))
      return -1;

    const auto length_res = to_int<ssize_t>(content_length);

    if (unlikely(!length_res.has_value())) {
#ifdef BENCH_DEBUG_PRINT
      std::cout << "could not get content length" << std::endl;
#endif
      return -1;
    }

    return length_res.value();
  }

  inline ssize_t get_total_response_size() noexcept {
    const auto content_length = get_content_length();
    if (unlikely(content_length < 0))
      return -1;
    return content_length + parsed_bytes + sizeof(CR_LF);
  }
};

} // namespace http

#endif