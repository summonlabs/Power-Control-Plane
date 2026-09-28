#pragma once

// Error taxonomy and result plumbing.
//
// Power Control Plane never signals failure through exceptions and never returns
// a bare boolean for an authority-bearing question. Every outcome is either a
// value or an Error carrying a stable machine readable code plus a bounded human
// readable detail string. Callers are expected to branch on ErrorCode, not on the
// message text.

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace power_control_plane {

enum class ErrorCode {
  ok = 0,
  invalid_argument,
  limit_exceeded,
  arithmetic_overflow,
  out_of_range,
  not_found,
  duplicate_identity,
  stale_generation,
  stale_revision,
  stale_epoch,
  stale_incarnation,
  stale_evidence,
  indeterminate,
  unauthorized,
  blocked_by_interlock,
  blocked_by_obligation,
  blocked_by_capacity,
  denied_by_policy,
  invalid_transition,
  conflict,
  not_authoritative,
  writer_authority_held,
  corrupt_store,
  unsupported_format,
  io_failure,
  path_rejected,
  lock_unavailable,
  rollback_detected,
  capacity_exhausted,
  unsupported,
  internal_failure,
};

[[nodiscard]] std::string_view to_string(ErrorCode code) noexcept;

// True for codes that mean "the request is refused and no authoritative state
// changed". Used by the engine to assert the no-side-effect invariant.
[[nodiscard]] bool is_refusal(ErrorCode code) noexcept;

class Error {
 public:
  Error() = default;
  Error(ErrorCode code, std::string message)
      : code_(code), message_(std::move(message)) {}

  [[nodiscard]] ErrorCode code() const noexcept { return code_; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }
  [[nodiscard]] bool ok() const noexcept { return code_ == ErrorCode::ok; }
  [[nodiscard]] std::string describe() const;

 private:
  ErrorCode code_ = ErrorCode::ok;
  std::string message_;
};

// Status is a Result without a payload.
class Status {
 public:
  Status() = default;
  Status(Error error) : error_(std::move(error)) {}

  static Status success() { return Status{}; }
  static Status failure(ErrorCode code, std::string message) {
    return Status(Error(code, std::move(message)));
  }

  [[nodiscard]] bool ok() const noexcept { return !error_.has_value(); }
  explicit operator bool() const noexcept { return ok(); }
  [[nodiscard]] const Error& error() const noexcept {
    static const Error kOk{};
    return error_.has_value() ? *error_ : kOk;
  }
  [[nodiscard]] ErrorCode code() const noexcept { return error().code(); }
  [[nodiscard]] std::string describe() const { return error().describe(); }

 private:
  std::optional<Error> error_;
};

template <class T>
class Result {
 public:
  Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
  Result(Error error) : storage_(std::in_place_index<1>, std::move(error)) {}
  Result(Status status) : storage_(std::in_place_index<1>, status.error()) {}

  [[nodiscard]] bool has_value() const noexcept {
    return storage_.index() == 0;
  }
  explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] T& value() & { return std::get<0>(storage_); }
  [[nodiscard]] const T& value() const& { return std::get<0>(storage_); }
  [[nodiscard]] T&& value() && { return std::get<0>(std::move(storage_)); }

  [[nodiscard]] const Error& error() const noexcept {
    static const Error kOk{};
    return storage_.index() == 1 ? std::get<1>(storage_) : kOk;
  }
  [[nodiscard]] ErrorCode code() const noexcept { return error().code(); }
  [[nodiscard]] std::string describe() const { return error().describe(); }

  T value_or(T fallback) const {
    return has_value() ? std::get<0>(storage_) : std::move(fallback);
  }

 private:
  std::variant<T, Error> storage_;
};

}  // namespace power_control_plane

// Propagates a failed Result/Status out of the enclosing function, which must
// return Result<U> or Status.
#define PCP_TRY(expr)                                            \
  do {                                                           \
    auto&& pcp_try_value = (expr);                               \
    if (!pcp_try_value.has_value()) {                            \
      return ::power_control_plane::Error(pcp_try_value.error()); \
    }                                                            \
  } while (false)

#define PCP_TRY_STATUS(expr)                                     \
  do {                                                           \
    auto&& pcp_try_status = (expr);                              \
    if (!pcp_try_status.ok()) {                                  \
      return pcp_try_status.error();                             \
    }                                                            \
  } while (false)
