#include "power_control_plane/error.hpp"

namespace power_control_plane {

std::string_view to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::ok:
      return "ok";
    case ErrorCode::invalid_argument:
      return "invalid_argument";
    case ErrorCode::limit_exceeded:
      return "limit_exceeded";
    case ErrorCode::arithmetic_overflow:
      return "arithmetic_overflow";
    case ErrorCode::out_of_range:
      return "out_of_range";
    case ErrorCode::not_found:
      return "not_found";
    case ErrorCode::duplicate_identity:
      return "duplicate_identity";
    case ErrorCode::stale_generation:
      return "stale_generation";
    case ErrorCode::stale_revision:
      return "stale_revision";
    case ErrorCode::stale_epoch:
      return "stale_epoch";
    case ErrorCode::stale_incarnation:
      return "stale_incarnation";
    case ErrorCode::stale_evidence:
      return "stale_evidence";
    case ErrorCode::indeterminate:
      return "indeterminate";
    case ErrorCode::unauthorized:
      return "unauthorized";
    case ErrorCode::blocked_by_interlock:
      return "blocked_by_interlock";
    case ErrorCode::blocked_by_obligation:
      return "blocked_by_obligation";
    case ErrorCode::blocked_by_capacity:
      return "blocked_by_capacity";
    case ErrorCode::denied_by_policy:
      return "denied_by_policy";
    case ErrorCode::invalid_transition:
      return "invalid_transition";
    case ErrorCode::conflict:
      return "conflict";
    case ErrorCode::not_authoritative:
      return "not_authoritative";
    case ErrorCode::writer_authority_held:
      return "writer_authority_held";
    case ErrorCode::corrupt_store:
      return "corrupt_store";
    case ErrorCode::unsupported_format:
      return "unsupported_format";
    case ErrorCode::io_failure:
      return "io_failure";
    case ErrorCode::path_rejected:
      return "path_rejected";
    case ErrorCode::lock_unavailable:
      return "lock_unavailable";
    case ErrorCode::rollback_detected:
      return "rollback_detected";
    case ErrorCode::capacity_exhausted:
      return "capacity_exhausted";
    case ErrorCode::unsupported:
      return "unsupported";
    case ErrorCode::internal_failure:
      return "internal_failure";
  }
  return "unknown";
}

bool is_refusal(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::ok:
    case ErrorCode::io_failure:
    case ErrorCode::corrupt_store:
    case ErrorCode::unsupported_format:
    case ErrorCode::path_rejected:
    case ErrorCode::lock_unavailable:
    case ErrorCode::rollback_detected:
    case ErrorCode::internal_failure:
      return false;
    default:
      return true;
  }
}

std::string Error::describe() const {
  std::string out;
  out.reserve(message_.size() + 32);
  out.append(to_string(code_));
  if (!message_.empty()) {
    out.append(": ");
    out.append(message_);
  }
  return out;
}

}  // namespace power_control_plane
