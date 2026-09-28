#include "detail/paths.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace power_control_plane::detail {
namespace {

std::string to_utf8(const std::filesystem::path& path) {
  const std::u8string utf8 = path.u8string();
  return std::string(reinterpret_cast<const char*>(utf8.data()), utf8.size());
}

std::filesystem::path from_utf8(std::string_view text) {
  return std::filesystem::path(
      std::u8string(reinterpret_cast<const char8_t*>(text.data()), text.size()));
}

bool is_reserved_device_stem(const std::string& stem_upper) {
  static const char* kReserved[] = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3",
                                    "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                                    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
                                    "LPT7", "LPT8", "LPT9"};
  for (const char* reserved : kReserved) {
    if (stem_upper == reserved) {
      return true;
    }
  }
  return false;
}

std::string upper_ascii(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char character : text) {
    if (character >= 'a' && character <= 'z') {
      out.push_back(static_cast<char>(character - 'a' + 'A'));
    } else {
      out.push_back(character);
    }
  }
  return out;
}

}  // namespace

bool is_path_separator(char character) noexcept {
  return character == '\\' || character == '/';
}

Status validate_child_name(std::string_view name) {
  if (name.empty()) {
    return Status::failure(ErrorCode::path_rejected,
                           "a store-owned path component must not be empty");
  }
  if (name.size() > 128) {
    return Status::failure(ErrorCode::path_rejected,
                           "a store-owned path component exceeds 128 bytes");
  }
  if (name == "." || name == "..") {
    return Status::failure(ErrorCode::path_rejected,
                           "a store-owned path component must not be a traversal segment");
  }
  for (const char character : name) {
    const auto raw = static_cast<unsigned char>(character);
    if (raw < 0x20 || raw == 0x7F) {
      return Status::failure(ErrorCode::path_rejected,
                             "a store-owned path component contains a control character");
    }
    if (is_path_separator(character)) {
      return Status::failure(ErrorCode::path_rejected,
                             "a store-owned path component contains a path separator");
    }
    if (character == '<' || character == '>' || character == ':' || character == '"' ||
        character == '|' || character == '?' || character == '*') {
      return Status::failure(ErrorCode::path_rejected,
                             "a store-owned path component contains a character the host "
                             "file system treats as special");
    }
  }
  if (name.back() == '.' || name.back() == ' ') {
    return Status::failure(
        ErrorCode::path_rejected,
        "a store-owned path component must not end with a dot or a space");
  }
  const std::size_t dot = name.find('.');
  const std::string_view stem = dot == std::string_view::npos ? name : name.substr(0, dot);
  if (is_reserved_device_stem(upper_ascii(stem))) {
    return Status::failure(ErrorCode::path_rejected,
                           "a store-owned path component names a reserved device");
  }
  return Status::success();
}

Result<std::string> normalize_root_path(std::string_view input, const Limits& limits) {
  if (input.empty()) {
    return Error(ErrorCode::invalid_argument, "store root path must not be empty");
  }
  if (input.size() > limits.max_path_bytes) {
    return Error(ErrorCode::path_rejected, "store root path exceeds the configured bound");
  }
  for (const char character : input) {
    const auto raw = static_cast<unsigned char>(character);
    if (raw == 0) {
      return Error(ErrorCode::path_rejected, "store root path contains a null byte");
    }
    if (raw < 0x20) {
      return Error(ErrorCode::path_rejected,
                   "store root path contains a control character");
    }
  }

  // Traversal segments are refused before normalization, so normalization can never
  // erase the evidence that an escape was attempted. A component is compared
  // lexically, before any resolution, and the check runs on the raw input.
  std::size_t component_start = 0;
  for (std::size_t index = 0; index <= input.size(); ++index) {
    if (index == input.size() || is_path_separator(input[index])) {
      if (input.substr(component_start, index - component_start) == "..") {
        return Error(ErrorCode::path_rejected,
                     "the store root path contains a traversal segment");
      }
      component_start = index + 1;
    }
  }

  std::filesystem::path path = from_utf8(input);
  std::error_code error;
  if (!path.is_absolute()) {
    path = std::filesystem::absolute(path, error);
    if (error) {
      return Error(ErrorCode::path_rejected, "store root path could not be made absolute");
    }
  }
  std::filesystem::path normalized = path.lexically_normal();
  for (const std::filesystem::path& component : normalized) {
    const std::string text = to_utf8(component);
    if (text == "..") {
      return Error(ErrorCode::path_rejected,
                   "store root path contains a traversal segment");
    }
  }
  if (!normalized.is_absolute()) {
    return Error(ErrorCode::path_rejected, "store root path is not absolute");
  }
  std::string text = to_utf8(normalized);
  while (text.size() > 1 && is_path_separator(text.back())) {
    text.pop_back();
  }
  if (text.empty()) {
    return Error(ErrorCode::path_rejected, "store root path resolves to the file system root");
  }
  return text;
}

std::string join_path(std::string_view parent, std::string_view child) {
  std::string out(parent);
  if (!out.empty() && !is_path_separator(out.back())) {
    out.push_back(std::filesystem::path::preferred_separator);
  }
  out.append(child);
  return out;
}

bool path_exists(const std::string& path) {
  std::error_code error;
  return std::filesystem::exists(from_utf8(path), error);
}

bool is_directory(const std::string& path) {
  std::error_code error;
  return std::filesystem::is_directory(from_utf8(path), error);
}

bool is_reparse_point(const std::string& path) {
#if defined(_WIN32)
  const std::filesystem::path native = from_utf8(path);
  const DWORD attributes = GetFileAttributesW(native.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    return false;
  }
  return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
  struct stat info {};
  const std::string native = path;
  if (::lstat(native.c_str(), &info) != 0) {
    return false;
  }
  return S_ISLNK(info.st_mode);
#endif
}

Status reject_substitution(const std::string& path) {
  if (!path_exists(path)) {
    return Status::success();
  }
  if (is_reparse_point(path)) {
    return Status::failure(
        ErrorCode::path_rejected,
        "the store root or one of its store-owned entries is a symlink, junction, or "
        "other reparse point");
  }
  return Status::success();
}

Status reject_directory(const std::string& path) {
  if (is_directory(path)) {
    return Status::failure(ErrorCode::path_rejected,
                           "a file is required but the path names a directory");
  }
  return Status::success();
}

Status ensure_directory(const std::string& path) {
  std::error_code error;
  const std::filesystem::path native = from_utf8(path);
  if (std::filesystem::exists(native, error)) {
    if (!std::filesystem::is_directory(native, error)) {
      return Status::failure(ErrorCode::path_rejected,
                             "the store root exists and is not a directory");
    }
    return Status::success();
  }
  if (!std::filesystem::create_directories(native, error) || error) {
    return Status::failure(ErrorCode::io_failure,
                           "the store root directory could not be created");
  }
  return Status::success();
}

Status remove_file_if_present(const std::string& path) {
  std::error_code error;
  const std::filesystem::path native = from_utf8(path);
  if (!std::filesystem::exists(native, error)) {
    return Status::success();
  }
  if (!std::filesystem::remove(native, error) || error) {
    return Status::failure(ErrorCode::io_failure, "a store residue file could not be removed");
  }
  return Status::success();
}

Result<std::vector<std::string>> list_directory(const std::string& path,
                                                const Limits& limits) {
  std::vector<std::string> names;
  std::error_code error;
  std::filesystem::directory_iterator iterator(from_utf8(path), error);
  if (error) {
    return Error(ErrorCode::io_failure, "a store directory could not be listed");
  }
  const std::size_t bound = limits.max_retained_generations * 8 + 64;
  for (const std::filesystem::directory_entry& entry : iterator) {
    if (names.size() >= bound) {
      return Error(ErrorCode::limit_exceeded,
                   "a store directory holds more entries than the configured bound");
    }
    const std::string name = to_utf8(entry.path().filename());
    if (name == "." || name == "..") {
      continue;
    }
    names.push_back(name);
  }
  std::sort(names.begin(), names.end());
  return names;
}

}  // namespace power_control_plane::detail
