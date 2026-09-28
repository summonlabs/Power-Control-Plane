#pragma once

// Action intents: what an operator or an upstream runtime is asking the facility
// to do.
//
// An intent is a request. It carries no authority by itself. It names the exact
// generation, policy revision, and evidence binding it was planned against, and
// the engine refuses the intent when any of those no longer match.

#include <cstdint>
#include <string_view>
#include <vector>

#include "power_control_plane/error.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/limits.hpp"

namespace power_control_plane {

enum class ActionKind : std::uint8_t {
  open_breaker = 1,
  close_breaker = 2,
  transfer_source = 3,
  set_load_limit = 4,
  enter_maintenance = 5,
  exit_maintenance = 6,
  declare_emergency = 7,
  clear_emergency = 8,
  isolate_bus = 9,
  restore_bus = 10,
  shed_load_group = 11,
  restore_load_group = 12,
  // Returns the facility to normal supply after a degraded, failover, emergency,
  // or isolated period. Distinct from exit_maintenance: the electrical intent is
  // different even though both end in the normal operating mode.
  restore_normal = 14,
  revalidate_evidence = 13,
};

[[nodiscard]] std::string_view to_string(ActionKind kind) noexcept;
[[nodiscard]] Result<ActionKind> parse_action_kind(std::string_view text);

// True for kinds that would reach an actuation adapter. Evidence revalidation is
// the only non-physical kind.
[[nodiscard]] bool is_physical_action(ActionKind kind) noexcept;

struct ActionIntent {
  ActionId id;
  ActionKind kind = ActionKind::open_breaker;
  ActionTargetId target;
  // The authoritative generation, publication revision, policy revision, and
  // evidence binding this intent was planned against. Every component is
  // compared exactly and the intent is refused when any of them has moved on.
  PlannedAgainst planned;
  // Declared demand for the kinds that move load. Zero means no demand was
  // declared, which is deliberately distinct from a known demand of zero.
  std::uint64_t requested_load_kw = 0;
};

[[nodiscard]] Status validate_intent_structure(const ActionIntent& intent,
                                               const Limits& limits);

[[nodiscard]] Result<ActionId> make_action_id(std::string_view tag);

}  // namespace power_control_plane
