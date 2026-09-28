#pragma once

// Cross-process writer lock.
//
// The primitive is an operating-system advisory lock that the kernel releases when
// the owning process dies, so a crashed writer never leaves the store permanently
// locked and the next process can always take authority. On Windows the lock is a
// file opened with no sharing; on POSIX it is an exclusive advisory lock
// (flock) on an open file descriptor.
//
// Holding the lock is necessary but not sufficient for authority: the store also
// fences writes with a monotonically increasing controller epoch and a per-session
// incarnation, so a writer that somehow survives past its own epoch still cannot
// publish.

#include <cstdint>
#include <string>

#include "power_control_plane/error.hpp"

namespace power_control_plane::detail {

class ProcessLock {
 public:
  ProcessLock() = default;
  ~ProcessLock();

  ProcessLock(ProcessLock&& other) noexcept;
  ProcessLock& operator=(ProcessLock&& other) noexcept;
  ProcessLock(const ProcessLock&) = delete;
  ProcessLock& operator=(const ProcessLock&) = delete;

  // Takes the lock without blocking. Returns ErrorCode::lock_unavailable when
  // another process currently holds it.
  [[nodiscard]] static Result<ProcessLock> try_acquire(const std::string& path);

  [[nodiscard]] bool held() const noexcept { return handle_ != kInvalid; }
  void release() noexcept;

 private:
  static constexpr std::intptr_t kInvalid = -1;
  std::intptr_t handle_ = kInvalid;
};

}  // namespace power_control_plane::detail
