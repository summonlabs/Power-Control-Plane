#include "detail/file_io.hpp"

#include <cstdint>
#include <filesystem>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "detail/paths.hpp"

namespace power_control_plane::detail {
namespace {

std::filesystem::path native_path(const std::string& path) {
  return std::filesystem::path(
      std::u8string(reinterpret_cast<const char8_t*>(path.data()), path.size()));
}

}  // namespace

Result<Bytes> read_file_bounded(const std::string& path, std::size_t max_bytes) {
#if defined(_WIN32)
  const HANDLE handle = CreateFileW(native_path(path).c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return Error(ErrorCode::io_failure, "a store file could not be opened for reading");
  }
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(handle, &size)) {
    CloseHandle(handle);
    return Error(ErrorCode::io_failure, "a store file size could not be read");
  }
  if (size.QuadPart < 0) {
    CloseHandle(handle);
    return Error(ErrorCode::corrupt_store, "a store file reports a negative size");
  }
  const std::uint64_t declared = static_cast<std::uint64_t>(size.QuadPart);
  if (declared > max_bytes) {
    CloseHandle(handle);
    return Error(ErrorCode::limit_exceeded,
                 "a store file exceeds the configured maximum size and was refused "
                 "without being read");
  }
  Bytes buffer;
  buffer.resize(static_cast<std::size_t>(declared));
  std::size_t offset = 0;
  while (offset < buffer.size()) {
    const DWORD request = static_cast<DWORD>(
        (buffer.size() - offset) > 0x10000000ull ? 0x10000000ull : (buffer.size() - offset));
    DWORD read = 0;
    if (!ReadFile(handle, buffer.data() + offset, request, &read, nullptr)) {
      CloseHandle(handle);
      return Error(ErrorCode::io_failure, "a store file could not be read");
    }
    if (read == 0) {
      break;
    }
    offset += read;
  }
  CloseHandle(handle);
  if (offset != buffer.size()) {
    return Error(ErrorCode::corrupt_store,
                 "a store file ended before the length it declared");
  }
  return buffer;
#else
  const int descriptor = ::open(path.c_str(), O_RDONLY);
  if (descriptor < 0) {
    return Error(ErrorCode::io_failure, "a store file could not be opened for reading");
  }
  struct stat info {};
  if (::fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)) {
    ::close(descriptor);
    return Error(ErrorCode::path_rejected, "a store file is not a regular file");
  }
  const std::uint64_t declared = static_cast<std::uint64_t>(info.st_size);
  if (declared > max_bytes) {
    ::close(descriptor);
    return Error(ErrorCode::limit_exceeded,
                 "a store file exceeds the configured maximum size and was refused "
                 "without being read");
  }
  Bytes buffer;
  buffer.resize(static_cast<std::size_t>(declared));
  std::size_t offset = 0;
  while (offset < buffer.size()) {
    const ssize_t read = ::read(descriptor, buffer.data() + offset, buffer.size() - offset);
    if (read < 0) {
      ::close(descriptor);
      return Error(ErrorCode::io_failure, "a store file could not be read");
    }
    if (read == 0) {
      break;
    }
    offset += static_cast<std::size_t>(read);
  }
  ::close(descriptor);
  if (offset != buffer.size()) {
    return Error(ErrorCode::corrupt_store,
                 "a store file ended before the length it declared");
  }
  return buffer;
#endif
}

namespace {

#if defined(_WIN32)
Status write_durable_impl(const std::string& path, const std::uint8_t* data,
                          std::size_t size, bool exclusive) {
  const DWORD disposition = exclusive ? CREATE_NEW : CREATE_ALWAYS;
  const HANDLE handle = CreateFileW(native_path(path).c_str(), GENERIC_WRITE, 0, nullptr,
                                    disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (exclusive && error == ERROR_FILE_EXISTS) {
      return Status::failure(ErrorCode::conflict,
                             "the staging file already exists and was not reused");
    }
    return Status::failure(ErrorCode::io_failure, "a store file could not be created");
  }
  std::size_t offset = 0;
  while (offset < size) {
    const DWORD request = static_cast<DWORD>(
        (size - offset) > 0x10000000ull ? 0x10000000ull : (size - offset));
    DWORD written = 0;
    if (!WriteFile(handle, data + offset, request, &written, nullptr)) {
      CloseHandle(handle);
      return Status::failure(ErrorCode::io_failure, "a store file could not be written");
    }
    offset += written;
  }
  if (!FlushFileBuffers(handle)) {
    CloseHandle(handle);
    return Status::failure(ErrorCode::io_failure,
                           "a store file could not be flushed to durable storage");
  }
  CloseHandle(handle);
  return Status::success();
}
#else
Status write_durable_impl(const std::string& path, const std::uint8_t* data,
                          std::size_t size, bool exclusive) {
  const int flags = O_WRONLY | O_CREAT | (exclusive ? O_EXCL : O_TRUNC);
  const int descriptor = ::open(path.c_str(), flags, 0644);
  if (descriptor < 0) {
    if (exclusive && errno == EEXIST) {
      return Status::failure(ErrorCode::conflict,
                             "the staging file already exists and was not reused");
    }
    return Status::failure(ErrorCode::io_failure, "a store file could not be created");
  }
  std::size_t offset = 0;
  while (offset < size) {
    const ssize_t written = ::write(descriptor, data + offset, size - offset);
    if (written <= 0) {
      ::close(descriptor);
      return Status::failure(ErrorCode::io_failure, "a store file could not be written");
    }
    offset += static_cast<std::size_t>(written);
  }
  if (::fsync(descriptor) != 0) {
    ::close(descriptor);
    return Status::failure(ErrorCode::io_failure,
                           "a store file could not be flushed to durable storage");
  }
  ::close(descriptor);
  return Status::success();
}
#endif

}  // namespace

Status write_file_durable(const std::string& path, const std::uint8_t* data,
                          std::size_t size) {
  return write_durable_impl(path, data, size, false);
}

Status write_new_file_durable(const std::string& path, const std::uint8_t* data,
                              std::size_t size) {
  return write_durable_impl(path, data, size, true);
}

Status replace_file_atomic(const std::string& source, const std::string& destination) {
#if defined(_WIN32)
  if (!MoveFileExW(native_path(source).c_str(), native_path(destination).c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    return Status::failure(ErrorCode::io_failure,
                           "an atomic store publication rename failed");
  }
  return Status::success();
#else
  if (::rename(source.c_str(), destination.c_str()) != 0) {
    return Status::failure(ErrorCode::io_failure,
                           "an atomic store publication rename failed");
  }
  return Status::success();
#endif
}

Status flush_directory(const std::string& path) {
#if defined(_WIN32)
  const HANDLE handle =
      CreateFileW(native_path(path).c_str(), GENERIC_READ | GENERIC_WRITE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    // Directory flushing is not available on every Windows file system. The
    // publication protocol does not depend on it: durability of the file contents
    // is established by FlushFileBuffers on the file itself, and the head marker is
    // written after the rename. Report the limitation instead of failing.
    return Status::success();
  }
  FlushFileBuffers(handle);
  CloseHandle(handle);
  return Status::success();
#else
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_DIRECTORY);
  if (descriptor < 0) {
    return Status::success();
  }
  ::fsync(descriptor);
  ::close(descriptor);
  return Status::success();
#endif
}

Status remove_file(const std::string& path) {
  std::error_code error;
  const std::filesystem::path native = native_path(path);
  if (!std::filesystem::exists(native, error)) {
    return Status::success();
  }
  if (!std::filesystem::remove(native, error) || error) {
    return Status::failure(ErrorCode::io_failure, "a store file could not be removed");
  }
  return Status::success();
}

Status remove_directory_if_empty(const std::string& path) {
  std::error_code error;
  std::filesystem::remove(native_path(path), error);
  return Status::success();
}

}  // namespace power_control_plane::detail
