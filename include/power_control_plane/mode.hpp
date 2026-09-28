#pragma once

// Facility electrical operating modes and the transition table that governs
// movement between them.
//
// This runtime decides *which* operating mode is in force. It does not perform
// the physical work of entering a mode: feed transfer, generator start, breaker
// operation and load shedding belong to the adjacent DCCP runtimes. A mode
// transition here changes the authoritative operating state and the requirements
// that subsequent actions must satisfy.
//
// Black start is deliberately out of scope. This runtime never models a
// cold-start sequence, a dead-bus energization order, or a cranking path; it only
// consumes the resulting state as external evidence. Black Start Manager owns
// that boundary.

#include <cstdint>
#include <string_view>

#include "power_control_plane/error.hpp"

namespace power_control_plane {

enum class OperatingMode : std::uint8_t {
  normal = 1,
  maintenance = 2,
  degraded = 3,
  failover = 4,
  emergency = 5,
  isolated = 6,
};

[[nodiscard]] std::string_view to_string(OperatingMode mode) noexcept;
[[nodiscard]] Result<OperatingMode> parse_mode(std::string_view text);

// True when moving from "from" to "to" reduces the amount of equipment available
// or the quality of supply. Fail-safe direction transitions are permitted even
// when the facility is already degraded, because refusing to record a
// deterioration would be less safe than recording it.
[[nodiscard]] bool is_fail_safe_direction(OperatingMode from, OperatingMode to) noexcept;

// Requirements a mode transition must satisfy. These are facts about the
// electrical model, not policy: policy can add requirements, it can never remove
// one of these.
enum class ModeTransitionId : std::uint8_t {
  enter_maintenance = 1,
  exit_maintenance = 2,
  degrade = 3,
  recover_from_degraded = 4,
  enter_failover = 5,
  exit_failover = 6,
  declare_emergency = 7,
  exit_emergency = 8,
  isolate = 9,
  restore_from_isolation = 10,
};

struct ModeTransitionRule {
  ModeTransitionId id;
  OperatingMode from;
  OperatingMode to;
  bool requires_fresh_evidence;
  bool requires_permission;
  std::uint8_t required_kind;
  bool requires_obligation_plan;
  bool requires_post_event_revalidation;
  std::string_view description;
};

[[nodiscard]] const ModeTransitionRule* find_mode_transition(OperatingMode from,
                                                            OperatingMode to) noexcept;

}  // namespace power_control_plane
