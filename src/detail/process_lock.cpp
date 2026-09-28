#include "detail/process_lock.hpp"

#include <filesystem>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace power_control_plane::detail {

ProcessLock::~ProcessLock() { release(); }

ProcessLock::ProcessLock(ProcessLock&& other) noexcept : handle_(other.handle_) {
  other.handle_ = kInvalid;
}

ProcessLock& ProcessLock::operator=(ProcessLock&& other) noexcept {
  if (this != &other) {
    release();
    handle_ = other.handle_;
    other.handle_ = kInvalid;
  }
  return *this;
}

void ProcessLock::release() noexcept {
  if (handle_ == kInvalid) {
    return;
  }
#if defined(_WIN32)
  CloseHandle(reinterpret_cast<HANDLE>(handle_));
#else
  ::flock(static_cast<int>(handle_), LOCK_UN);
  ::close(static_cast<int>(handle_));
#endif
  handle_ = kInvalid;
}

Result<ProcessLock> ProcessLock::try_acquire(const std::string& path) {
  const std::filesystem::path native(
      std::u8string(reinterpret_cast<const char8_t*>(path.data()), path.size()));
#if defined(_WIN32)
  // Sharing mode zero: the file can be opened by exactly one process at a time and
  // the kernel releases it when that process terminates, for any reason.
  const HANDLE handle = CreateFileW(native.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                                    nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION) {
      return Error(ErrorCode::lock_unavailable,
                   "another process currently holds writer authority for this store");
    }
    if (error == ERROR_ACCESS_DENIED) {
      return Error(ErrorCode::lock_unavailable,
                   "writer authority for this store could not be acquired");
    }
    return Error(ErrorCode::io_failure, "the writer authority lock file could not be opened");
  }
  ProcessLock lock;
  lock.handle_ = reinterpret_cast<std::intptr_t>(handle);
  return lock;
#else
  const int descriptor = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
  if (descriptor < 0) {
    return Error(ErrorCode::io_failure, "the writer authority lock file could not be opened");
  }
  if (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    ::close(descriptor);
    return Error(ErrorCode::lock_unavailable,
                 "another process currently holds writer authority for this store");
  }
  ProcessLock lock;
  lock.handle_ = static_cast<std::intptr_t>(descriptor);
  return lock;
#endif
}

}  // namespace power_control_plane::detail
