#ifndef __BUF_POOL_H__
#define __BUF_POOL_H__

#include "common.hpp"
#include "networking.hpp"
#include <array>
#include <cinttypes>
#include <climits>
#include <cstring>
#include <iostream>
#include <stack>
#include <sys/mman.h>
#include <sys/uio.h>

namespace buffer {

enum buf_log : std::size_t {
  INVALID = SIZE_MAX,
  LOG2_4096 = 12,
  LOG2_8192 = 13,
  LOG2_16384 = 14,
  LOG2_32768 = 15,
  LOG2_65536 = 16,
  LOG2_131072 = 17,
  LOG2_262144 = 18,
  LOG2_524288 = 19,
  LOG2_1048576 = 20,
  LOG2_2097152 = 21,
  LOG2_4194304 = 22,
  LOG2_8388608 = 23,
  LOG2_16777216 = 24,
  LOG2_33554432 = 25,
  LOG2_67108864 = 26,
  LOG2_134217728 = 27,
  LOG2_268435456 = 28,
  LOG2_536870912 = 29,
  LOG2_1073741824 = 30,
};

static constexpr buf_log get_buf_log_for_size(const std::size_t size) noexcept {
  if (unlikely(unlikely(size == 0) || unlikely(size > (1 << LOG2_1073741824))))
    return INVALID;
  auto ceil_log2 = ceiled_log2(size);
  return ceil_log2 <= LOG2_4096 ? LOG2_4096 : static_cast<buf_log>(ceil_log2);
}

static constexpr std::size_t buf_log_to_size(const buf_log buf_log) noexcept {
  return 1UL << static_cast<std::size_t>(buf_log);
}

class buf_pool {
private:
  std::size_t mmaped_bytes = 0;
  std::array<std::stack<void *>, 19> free_bufs_stacks;

  inline std::stack<void *> &
  get_free_bufs_stack_for_buf_log(const buf_log buf_log) noexcept {
    return free_bufs_stacks[static_cast<std::size_t>(buf_log) - 12];
  }

  inline void *get_buf(const buf_log buf_log) noexcept {
    const auto buf_size = buf_log_to_size(buf_log);
    auto &free_bufs_stack = get_free_bufs_stack_for_buf_log(buf_log);

    void *buf;
    if (unlikely(free_bufs_stack.empty())) {
      buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
      if (buf == MAP_FAILED)
        return nullptr;
      mmaped_bytes += buf_size;
#ifdef BENCH_DEBUG_PRINT
      std::cout << "mmaped buf with size: " << buf_size << std::endl
                << "overall mmaped bytes now: " << mmaped_bytes << std::endl;
#endif
    } else {
      buf = free_bufs_stack.top();
      free_bufs_stack.pop();
      std::memset(buf, 0, buf_size);
#ifdef BENCH_DEBUG_PRINT
      std::cout << "popped mmaped buf from free stack with size: " << buf_size
                << std::endl;
#endif
    }

    return buf;
  }

public:
  int rent_buf(networking::buf_t &buf, const std::size_t buf_size,
               const std::size_t count = 1) noexcept {
    const auto buf_log = get_buf_log_for_size(buf_size);
    if (unlikely(buf_log == INVALID))
      return 1;

    for (std::size_t i = 0; i < count; ++i) {
      void *const mmaped_buf = get_buf(buf_log);
      if (unlikely(mmaped_buf == nullptr)) {
        hand_back_buf(buf);
        return 1;
      }

      buf.vecs.push_back({.iov_base = mmaped_buf, .iov_len = buf_size});
      buf.vecs_mut.push_back({.iov_base = mmaped_buf, .iov_len = buf_size});
    }

    return 0;
  }

  int resize_buf(networking::buf_t &buf, const std::size_t idx,
                 const std::size_t new_buf_size) noexcept {

    const auto new_buf_log = get_buf_log_for_size(new_buf_size);
    if (unlikely(new_buf_log == INVALID))
      return 1;

    auto &vecs = buf.vecs;
    if (unlikely(vecs.size() <= idx))
      return 1;
    const auto io_vec_to_resize = vecs[idx];
    const auto old_buf_log = get_buf_log_for_size(io_vec_to_resize.iov_len);

    auto &vecs_mut = buf.vecs_mut;
#ifdef BENCH_DEBUG_PRINT
    std::cout << "resizing mmaped buf from: " << buf_log_to_size(old_buf_log)
              << " to: " << buf_log_to_size(new_buf_log) << std::endl;
#endif
    if (old_buf_log == new_buf_log) {
      vecs[idx].iov_len = new_buf_size;
      vecs_mut[idx].iov_len = new_buf_size;
      return 0;
    }

    void *const new_mmaped_buf = get_buf(new_buf_log);
    if (unlikely(new_mmaped_buf == nullptr))
      return 1;

    std::memcpy(new_mmaped_buf, io_vec_to_resize.iov_base,
                std::min(new_buf_size, io_vec_to_resize.iov_len));

    vecs[idx] = {.iov_base = new_mmaped_buf, .iov_len = new_buf_size};
    vecs_mut[idx] = {.iov_base = new_mmaped_buf, .iov_len = new_buf_size};

    auto &free_bufs_stack = get_free_bufs_stack_for_buf_log(old_buf_log);
    free_bufs_stack.push(io_vec_to_resize.iov_base);

    return 0;
  }

  void hand_back_buf(networking::buf_t &buf) noexcept {
    if (unlikely(buf.vecs.size() == 0))
      return;
    for (const auto &io_vec : buf.vecs) {
      const auto buf_log = get_buf_log_for_size(io_vec.iov_len);
      auto &free_bufs_stack = get_free_bufs_stack_for_buf_log(buf_log);
      free_bufs_stack.push(io_vec.iov_base);
#ifdef BENCH_DEBUG_PRINT
      std::cout << "handed back mmaped buf to free stack with size: "
                << buf_log_to_size(buf_log) << std::endl;
#endif
    }
    buf.vecs.clear();
    buf.vecs_mut.clear();
  }
};

} // namespace buffer

#endif