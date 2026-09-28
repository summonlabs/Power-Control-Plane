#pragma once

// Checked arithmetic for authoritative values.
//
// Authoritative counters (generations, epochs, revisions, tick) must never wrap.
// Every increment goes through these helpers, which refuse overflow with an
// explicit error rather than saturating or wrapping.

#include <cstddef>
#include <cstdint>
#include <limits>

#include "power_control_plane/error.hpp"

namespace power_control_plane {

[[nodiscard]] inline Result<std::uint64_t> checked_add(std::uint64_t a,
                                                       std::uint64_t b) {
  if (b > std::numeric_limits<std::uint64_t>::max() - a) {
    return Error(ErrorCode::arithmetic_overflow,
                 "unsigned 64-bit addition overflow");
  }
  return a + b;
}

[[nodiscard]] inline Result<std::uint64_t> checked_sub(std::uint64_t a,
                                                       std::uint64_t b) {
  if (b > a) {
    return Error(ErrorCode::arithmetic_overflow,
                 "unsigned 64-bit subtraction underflow");
  }
  return a - b;
}

[[nodiscard]] inline Result<std::uint64_t> checked_mul(std::uint64_t a,
                                                       std::uint64_t b) {
  if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) {
    return Error(ErrorCode::arithmetic_overflow,
                 "unsigned 64-bit multiplication overflow");
  }
  return a * b;
}

[[nodiscard]] inline Result<std::uint64_t> checked_increment(std::uint64_t a) {
  return checked_add(a, 1);
}

// Checked conversion from size_t (bounded by the platform) to uint64_t.
[[nodiscard]] inline Result<std::uint64_t> checked_u64(std::size_t value) {
  if (value > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max())) {
    return Error(ErrorCode::arithmetic_overflow, "size does not fit in uint64");
  }
  return static_cast<std::uint64_t>(value);
}

// Bounded accumulation used by capacity checks. Refuses to overflow.
[[nodiscard]] inline Result<std::uint64_t> checked_accumulate(std::uint64_t total,
                                                             std::uint64_t addend) {
  return checked_add(total, addend);
}

}  // namespace power_control_plane
