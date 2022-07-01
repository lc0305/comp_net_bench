#ifndef __HTTP_RESPONSE_H__
#define __HTTP_RESPONSE_H__

#include "common.hpp"
#include "compress.hpp"
#include "file_cache.hpp"
#include "http_status.hpp"
#include "networking.hpp"
#include <cinttypes>
#include <cstdio>
#include <iostream>
#include <optional>
#include <string>

namespace http {

constexpr const char *compression_algo_to_str(
    const compression::compression_algo comp_algo) noexcept {
  switch (comp_algo) {
  case compression::NONE:
    return "";
  case compression::DEFLATE:
    return "deflate";
  case compression::LZ4:
    return "lz4";
  }
}

constexpr const char *
http_status_code_to_str(const http_status_code status) noexcept {
  switch (status) {
  case OK:
    return "OK";
  case NOT_FOUND:
    return "NOT FOUND";
  case INTERNAL_SERVER_ERROR:
    return "INTERNAL SERVER ERROR";
  default:
    return "NOT IMPLEMENTED";
  }
}

constexpr const char *
file_type_to_mime_str(const file::file_type type) noexcept {
  switch (type) {
  case file::JPG:
    return "image/jpeg";
  case file::TEXT_HTML:
    return "text/html";
  case file::APPLICATION_JAVASCRIPT:
    return "application/javascript";
  case file::APPLICATION_JSON:
    return "application/json";
  default:
    return "";
  }
}

class http_response {
private:
  networking::write_buf_t &write_buf;

  inline std::optional<iovec> get_header_iov() noexcept {
    const auto vecs_size = write_buf.buf.vecs.size();
    if (unlikely(vecs_size < 1))
      return std::optional<iovec>{std::nullopt};
    const std::size_t iov_header_idx =
        likely(vecs_size > 1) ? vecs_size - 2 : 0;
    return std::optional<iovec>{write_buf.buf.vecs[iov_header_idx]};
  }

  inline std::optional<iovec> get_content_iov() noexcept {
    const auto vecs_size = write_buf.buf.vecs.size();
    if (unlikely(vecs_size < 2))
      return std::optional<iovec>{std::nullopt};
    const auto iov_content_idx = vecs_size - 1;
    return std::optional<iovec>{write_buf.buf.vecs[iov_content_idx]};
  }

public:
  inline http_response(networking::write_buf_t &write_buf) noexcept
      : write_buf(write_buf) {}

  // returns header size on success and 0 on error
  std::size_t
  build_header(const http_status_code status,
               const std::size_t content_length = 0,
               const compression::compression_algo comp_alg = compression::NONE,
               const file::file_type f_type = file::NONE) noexcept {
    auto header_iov_opt = get_header_iov();
    if (unlikely(!header_iov_opt.has_value()))
      return 0;

    auto &header_iov = header_iov_opt.value();

    std::size_t cursor = 0;
    int ret;
    if (unlikely(
            unlikely((ret = std::snprintf(
                          &static_cast<char *>(header_iov.iov_base)[cursor],
                          header_iov.iov_len - cursor, "HTTP/1.1 %d %s\r\n",
                          static_cast<int>(status),
                          http_status_code_to_str(status))) < 0) ||
            unlikely((cursor += ret) > header_iov.iov_len)))
      return 0;

    // set date eventually

    if (likely(likely(f_type != file::NONE) &&
               unlikely(unlikely((ret = std::snprintf(
                                      &static_cast<char *>(
                                          header_iov.iov_base)[cursor],
                                      header_iov.iov_len - cursor,
                                      "Content-Type: %s; charset=utf-8\r\n",
                                      file_type_to_mime_str(f_type))) < 0) ||
                        unlikely((cursor += ret) > header_iov.iov_len))))
      return 0;

    if (likely(
            likely(comp_alg != compression::NONE) &&
            unlikely(
                unlikely((ret = std::snprintf(
                              &static_cast<char *>(header_iov.iov_base)[cursor],
                              header_iov.iov_len - cursor,
                              "Content-Encoding: %s\r\n",
                              compression_algo_to_str(comp_alg))) < 0) ||
                unlikely((cursor += ret) > header_iov.iov_len))))
      return 0;

    if (unlikely(
            unlikely((ret = std::snprintf(
                          &static_cast<char *>(header_iov.iov_base)[cursor],
                          header_iov.iov_len - cursor,
                          "Content-Length: %lu\r\n", content_length)) < 0) ||
            unlikely((cursor += ret) > header_iov.iov_len)))
      return 0;

    const char static_header_content[] = "Connection: Keep-Alive\r\n\n";
    const auto final_size = cursor + sizeof(static_header_content) - 1;
    if (unlikely(final_size > header_iov.iov_len))
      return 0;
    std::memcpy(&static_cast<char *>(header_iov.iov_base)[cursor],
                static_header_content, sizeof(static_header_content) - 1);
    return final_size;
  }

  void print_header() noexcept {
    auto header_iov_opt = get_header_iov();
    if (unlikely(!header_iov_opt.has_value()))
      return;

    auto &header_iov = header_iov_opt.value();

    std::cout << std::string_view(
                     static_cast<const char *>(header_iov.iov_base),
                     header_iov.iov_len)
              << std::endl;
  }

  std::size_t build_content(const std::size_t content_length) noexcept {
    auto content_iov_opt = get_content_iov();
    if (unlikely(!content_iov_opt.has_value()))
      return 0;

    auto &content_iov = content_iov_opt.value();

    const auto final_size = content_length + sizeof(CR_LF);
    if (unlikely(content_iov.iov_len < final_size))
      return 0;

    for (std::size_t i = 0; i < sizeof(CR_LF); ++i)
      static_cast<char *>(content_iov.iov_base)[content_length + i] = CR_LF[i];

    return final_size;
  }
};

} // namespace http

#endif