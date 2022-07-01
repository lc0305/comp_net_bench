#ifndef __COMMON_H__
#define __COMMON_H__

#include <cinttypes>
#include <climits>
#include <string_view>

#define BENCH_DEBUG_PRINT

#define expect(expr, value) (__builtin_expect((expr), (value)))
#define likely(expr) expect((expr) != 0, 1)
#define unlikely(expr) expect((expr) != 0, 0)

#define CR ('\r')
#define LF ('\n')
static const char CR_LF[] = {CR, LF};

constexpr std::uint32_t ceiled_log2(std::uint32_t value) noexcept {
  return unlikely(value <= 1)
             ? value
             : CHAR_BIT * sizeof(value) - __builtin_clz(value - 1);
}

constexpr bool contains(const std::string_view where,
                        const char *const what) noexcept {
  return std::string_view::npos != where.find(what);
}

template <typename T>
constexpr T small_str_to_int(const char *const str,
                             const std::size_t len) noexcept {
  T current_val = 0;
  for (std::size_t i = 0; i < len; ++i)
    current_val |= (static_cast<T>(str[i]) & 0xFF) << (i * CHAR_BIT);
  return current_val;
}

#define SMALL_STR_TO_INT(t, s) str_to_int<t>((s), sizeof((s)) - 1);

#endif