#ifndef __FILE_CACHE_H__
#define __FILE_CACHE_H__

#include "common.hpp"
#include <cinttypes>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace file {

enum file_type : std::uint8_t {
  NONE,
  NOT_SUPPORTED,
  JPG,
  TEXT_HTML,
  APPLICATION_JAVASCRIPT,
  APPLICATION_JSON,
};

struct file_data {
  const char *const buf;
  const std::size_t size;
  const file_type type;

  constexpr file_data(const char *const buf, const std::size_t size,
                      const file_type type) noexcept
      : buf(buf), size(size), type(type) {}
};

struct internal_file_data {
  std::vector<char> vec;
  file_type type;

  inline internal_file_data(const std::size_t file_size,
                            const file_type type) noexcept
      : vec(file_size), type(type) {}

  inline internal_file_data(internal_file_data &&other) noexcept
      : vec(std::move(other.vec)), type(other.type) {}

  inline internal_file_data &operator=(internal_file_data &&other) noexcept {
    vec = std::move(other.vec);
    type = other.type;
    return *this;
  }
};

constexpr file_type
get_file_type_for_path(const std::string_view file_path) noexcept {
  // this isnt particulary efficient, but is only called at startup anyway
  if (contains(file_path, ".html"))
    return TEXT_HTML;

  if (contains(file_path, ".js"))
    return APPLICATION_JAVASCRIPT;

  if (contains(file_path, ".json"))
    return APPLICATION_JSON;

  if (contains(file_path, ".jpg") || contains(file_path, ".jpeg"))
    return JPG;

  return NOT_SUPPORTED;
}

class file_cache {
private:
  std::vector<std::string> file_paths;
  std::map<std::string_view, internal_file_data> files;
  const std::string_view public_path;

public:
  file_cache(const std::string_view public_path) noexcept
      : public_path(public_path) {
    for (const auto &entry : std::filesystem::directory_iterator(public_path)) {
      // load only the first hierachy
      if (unlikely(!entry.is_regular_file()))
        continue;
      const auto file_size = entry.file_size();
      if (unlikely(file_size == 0))
        continue;
      const auto file_path = entry.path().string();
      const auto type = get_file_type_for_path(file_path);
      if (unlikely(type == NOT_SUPPORTED))
        continue;
      // so we can index the map with string_view
      // and we dont need any allocations after init
      file_paths.push_back(file_path.substr(public_path.size()));
      const auto &file_path_in_vec = file_paths.back();
      internal_file_data file_data(file_size, type);
      const int fd = openat(AT_FDCWD, file_path.c_str(), O_RDONLY);
      if (unlikely(fd < 0)) {
        std::cout << "Could not open: " << file_path << std::endl;
        continue;
      }
      char *const buf = file_data.vec.data();
      const ssize_t buf_size = file_data.vec.size();
      ssize_t nbytes = 0;
      while (likely((nbytes = read(fd, &buf[nbytes], buf_size - nbytes)) > 0) &&
             unlikely(nbytes < buf_size))
        ;
      close(fd);
      if (likely(files.emplace(file_path_in_vec, std::move(file_data)).second))
        std::cout << "Cached " << file_path_in_vec << std::endl;
    }
    std::cout << "Cache is ready!" << std::endl << std::endl;
  }

  inline file_data get_file(const std::string_view path) noexcept {
    const auto file_data_it = files.find(path);
    if (unlikely(file_data_it == std::end(files))) {
#ifdef BENCH_DEBUG_PRINT
      std::cout << "resource: '" << path << "' was not found." << std::endl;
#endif
      return file_data(nullptr, 0, NOT_SUPPORTED);
    }
#ifdef BENCH_DEBUG_PRINT
    std::cout << "retrieved file: " << path << std::endl;
#endif
    const auto &internal_file_data = file_data_it->second;
    return file_data(internal_file_data.vec.data(),
                     internal_file_data.vec.size(), internal_file_data.type);
  }
};

} // namespace file

#endif