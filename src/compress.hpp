#ifndef __COMPRESS_H__
#define __COMPRESS_H__

#include "common.hpp"
#include <cinttypes>
#include <cstring>
#include <lz4.h>
#include <zlib.h>

namespace compression {

enum compression_algo : std::uint8_t {
  NONE,
  DEFLATE,
  LZ4,
};

inline std::size_t compress_buf_lz4(const char *const src_buf,
                                    const std::size_t src_buf_size,
                                    char *const dst_buf,
                                    const std::size_t dst_buf_size) noexcept {
  return LZ4_compress_default(src_buf, dst_buf, src_buf_size, dst_buf_size);
}

inline std::size_t
compress_buf_deflate(const char *const src_buf, const std::size_t src_buf_size,
                     char *const dst_buf,
                     const std::size_t dst_buf_size) noexcept {
  std::size_t compressed_size = dst_buf_size;
  return likely(compress2(reinterpret_cast<Bytef *>(dst_buf), &compressed_size,
                          reinterpret_cast<const Bytef *>(src_buf),
                          src_buf_size, Z_DEFAULT_COMPRESSION) == Z_OK)
             ? compressed_size
             : 0;
}

inline std::size_t
compress_buf(const char *const src_buf, const std::size_t src_buf_size,
             char *const dst_buf, const std::size_t dst_buf_size,
             const compression_algo compression_algo) noexcept {
  if (unlikely(unlikely(src_buf == nullptr) || unlikely(src_buf_size == 0) ||
               unlikely(dst_buf == nullptr) || unlikely(dst_buf_size == 0)))
    return 0;
  switch (compression_algo) {
  case DEFLATE:
    return compress_buf_deflate(src_buf, src_buf_size, dst_buf, dst_buf_size);
  case LZ4:
    return compress_buf_lz4(src_buf, src_buf_size, dst_buf, dst_buf_size);
  default:
    if (unlikely(src_buf_size > dst_buf_size))
      return 0;
    std::memcpy(static_cast<void *>(dst_buf),
                static_cast<const void *>(src_buf), src_buf_size);
    return src_buf_size;
  }
}

} // namespace compression

#endif