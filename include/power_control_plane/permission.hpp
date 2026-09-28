#pragma once

// Switching and control permissions.
//
// A permission is never a boolean. It is a bounded grant that names:
//
//   * the action kinds and targets it covers,
//   * the control generation it was issued at and the generation at which it
//     expires (the lifetime is bounded in generations, not wall-clock time, so
//     the grant is reproducible and survives restart exactly),
//   * the policy revision it was issued under,
//   * the exact external evidence binding it was issued against,
//   * how many times it may be used.
//
// A permission is valid only against the exact generation, policy revision, and
// evidence binding it names. Any drift makes it invalid, and once revoked,
// superseded, or exhausted it can never be replayed.

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "power_control_plane/action.hpp"
#include "power_control_plane/canonical.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/evidence.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/limits.hpp"

namespace power_control_plane {

enum class PermissionState : std::uint8_t {
  active = 1,
  revoked = 2,
  superseded = 3,
  exhausted = 4,
};

[[nodiscard]] std::string_view to_string(PermissionState state) noexcept;
[[nodiscard]] Result<PermissionState> parse_permission_state(std::string_view text);

struct PermissionGrant {
  PermissionId id;
  std::vector<ActionKind> kinds;
  // Empty target list means "every target within the listed kinds".
  std::vector<ActionTargetId> targets;
  ControlGeneration issued_generation;
  // Half-open electrical-generation lifetime: the grant is usable while
  // issued_generation <= current < expiry_generation.
  ControlGeneration expiry_generation;
  // Publication-revision lifetime. Both bounds must hold; a grant whose
  // electrical generation is still current is still refused once the store has
  // published past expiry_revision.
  StateRevision issued_revision;
  StateRevision expiry_revision;
  PolicyRevision policy_revision;
  EvidenceBinding evidence;
  PermissionState state = PermissionState::active;
  AuthorityReference granted_by;
  std::uint32_t max_uses = 1;
  std::uint32_t uses = 0;
  StateRevision updated_revision;
};

[[nodiscard]] bool permission_covers(const PermissionGrant& grant,
                                     ActionKind kind,
                                     const ActionTargetId& target) noexcept;

[[nodiscard]] bool permission_within_lifetime(const PermissionGrant& grant,
                                              ControlGeneration current_generation,
                                              StateRevision current_revision) noexcept;

// Reason a grant cannot be used, evaluated in a fixed order so the reported
// reason is deterministic. Returns std::nullopt when the grant is usable for the
// given kind/target at the given generation.
enum class PermissionRejection : std::uint8_t {
  revoked = 1,
  superseded = 2,
  exhausted = 3,
  not_yet_issued = 4,
  expired = 5,
  scope_mismatch = 6,
};

[[nodiscard]] std::string_view to_string(PermissionRejection rejection) noexcept;
[[nodiscard]] std::optional<PermissionRejection> permission_rejection(
    const PermissionGrant& grant, ActionKind kind, const ActionTargetId& target,
    ControlGeneration current_generation, StateRevision current_revision) noexcept;

[[nodiscard]] Status encode_permission(CanonicalWriter& writer,
                                       const PermissionGrant& value,
                                       const Limits& limits);
[[nodiscard]] Result<PermissionGrant> decode_permission(CanonicalReader& reader,
                                                        const Limits& limits);

}  // namespace power_control_plane
