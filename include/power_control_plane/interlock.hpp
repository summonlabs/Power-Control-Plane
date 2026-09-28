#pragma once

// Safety interlocks.
//
// An interlock is a safety fact published by this control plane or by an adjacent
// safety-bearing runtime. Interlocks fail closed:
//
//   * state engaged  -> blocks every in-scope action
//   * state unknown  -> blocks every in-scope action (absence of information is
//                       never treated as clearance)
//   * state cleared  -> does not block
//   * severity advisory does not block, by explicit design, and is surfaced in the
//     explanation trace so an operator still sees it
//
// No policy rule can clear, weaken, or outrank an interlock. The engine evaluates
// interlocks before policy and a policy "allow" rule never overrides a blocking
// interlock.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/action.hpp"
#include "power_control_plane/canonical.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/limits.hpp"

namespace power_control_plane {

enum class InterlockSeverity : std::uint8_t {
  advisory = 1,
  blocking = 2,
  critical = 3,
};

enum class InterlockState : std::uint8_t {
  cleared = 1,
  engaged = 2,
  // The publishing runtime cannot currently report the interlock state. Treated
  // exactly like engaged for blocking purposes.
  unknown = 3,
};

[[nodiscard]] std::string_view to_string(InterlockSeverity severity) noexcept;
[[nodiscard]] std::string_view to_string(InterlockState state) noexcept;
[[nodiscard]] Result<InterlockSeverity> parse_interlock_severity(std::string_view text);
[[nodiscard]] Result<InterlockState> parse_interlock_state(std::string_view text);

struct Interlock {
  InterlockId id;
  // The runtime that published this interlock fact.
  EvidenceSourceId source;
  InterlockSeverity severity = InterlockSeverity::blocking;
  InterlockState state = InterlockState::unknown;
  // The control generation at which the interlock was first declared and the one
  // at which it was last changed. Both are carried so a decision can name the
  // exact interlock generation it was evaluated against.
  ControlGeneration declared_generation;
  ControlGeneration updated_generation;
  // Empty scope lists mean "all kinds" and "all targets" respectively. The scope
  // is deliberately fail-open in extent and fail-closed in state: an interlock
  // with no scope recorded covers everything rather than nothing.
  std::vector<ActionKind> scope_kinds;
  std::vector<ActionTargetId> scope_targets;
  std::string explanation;
};

// True when this interlock blocks the given action kind and target under the
// fail-closed rules above.
[[nodiscard]] bool interlock_blocks(const Interlock& interlock,
                                    ActionKind kind,
                                    const ActionTargetId& target) noexcept;

[[nodiscard]] Status encode_interlock(CanonicalWriter& writer, const Interlock& value,
                                      const Limits& limits);
[[nodiscard]] Result<Interlock> decode_interlock(CanonicalReader& reader,
                                                 const Limits& limits);

}  // namespace power_control_plane
