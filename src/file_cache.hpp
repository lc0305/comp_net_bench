#ifndef __FILE_CACHE_H__
#define __FILE_CACHE_H__

#include "common.hpp"
#include <cinttypes>
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <numeric>
#include <string>
#include <string_view>
#include <tuple>
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
  std::vector<char> file_path_vec;
  std::map<const std::string_view,
           std::pair<const std::vector<char>, const file_type>>
      files;
  const std::string_view public_path;

public:
  file_cache(const std::string_view public_path) noexcept
      : public_path(public_path) {
    std::vector<std::tuple<std::string, std::string, std::size_t, file_type>>
        file_paths;
    // file_path.substr(public_path.size()
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
      file_paths.emplace_back(std::make_tuple(
          std::move(file_path), file_path.substr(public_path.size()), file_size,
          type));
    }

    file_path_vec.resize(std::accumulate(
        std::begin(file_paths), std::end(file_paths), std::size_t{0},
        [](const std::size_t current_size,
           const std::tuple<std::string, std::string, std::size_t, file_type>
               &tuple) { return current_size + std::get<1>(tuple).length(); }));

    std::size_t file_path_buf_cursor = 0;
    for (const auto &tuple : file_paths) {
      const auto &file_path_without_public = std::get<1>(tuple);
      const auto file_path_without_public_len =
          file_path_without_public.length();

      char *const file_path_buf = file_path_vec.data();
      for (std::size_t i = 0; i < file_path_without_public_len; ++i)
        file_path_buf[file_path_buf_cursor + i] =
            file_path_without_public.data()[i];

      const auto file_path_view = std::string_view(
          &file_path_buf[file_path_buf_cursor], file_path_without_public_len);
      file_path_buf_cursor += file_path_without_public_len;

      const auto &file_path = std::get<0>(tuple);
      const int fd = openat(AT_FDCWD, file_path.c_str(), O_RDONLY);
      if (unlikely(fd < 0)) {
        std::cout << "Could not open: " << file_path << std::endl;
        continue;
      }

      auto internal_file_data = std::make_pair(
          std::vector<char>(std::get<2>(tuple)), std::get<3>(tuple));
      char *const file_buf = internal_file_data.first.data();
      const ssize_t file_buf_size = internal_file_data.first.size();
      ssize_t nbytes = 0;

      while (likely((nbytes = read(fd, &file_buf[nbytes],
                                   file_buf_size - nbytes)) > 0) &&
             unlikely(nbytes < file_buf_size))
        ;

      if (likely(files.emplace(file_path_view, std::move(internal_file_data))
                     .second))
        std::cout << "Cached " << file_path_view << "XD" << std::endl;
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
    return file_data(internal_file_data.first.data(),
                     internal_file_data.first.size(),
                     internal_file_data.second);
  }
};

} // namespace file

#endif