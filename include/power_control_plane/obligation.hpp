#pragma once

// Protected obligations and capacity commitments.
//
// Both are external, authority-bound references. This runtime does not decide what
// the facility owes and does not compute capacity: it records the references an
// upstream authority published and refuses operations that would leave a
// continuity-required obligation unserved or exceed a committed capacity.
//
// A protected obligation can only stop being served through an explicit
// SuspensionRecord that names the external authority which permitted the
// suspension. There is no path that silently drops an obligation during a mode
// transition.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/action.hpp"
#include "power_control_plane/canonical.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/evidence.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/limits.hpp"

namespace power_control_plane {

enum class ObligationState : std::uint8_t {
  active = 1,
  suspended = 2,
};

[[nodiscard]] std::string_view to_string(ObligationState state) noexcept;
[[nodiscard]] Result<ObligationState> parse_obligation_state(std::string_view text);

struct SuspensionRecord {
  // The external authority that permitted the suspension. A suspension without a
  // named authority reference is rejected by validation.
  AuthorityReference authority;
  ControlGeneration generation;
  LogicalTick tick;
  std::string reason;
};

// One obligation suspended by one authority-bound decision. Keyed by obligation
// identity so the mapping can never be inferred positionally.
struct ObligationSuspension {
  ObligationId obligation;
  SuspensionRecord record;
};

struct ProtectedObligation {
  ObligationId id;
  // The runtime that owns this obligation (for example the facility capacity
  // authority). Consumed, never reimplemented.
  EvidenceSourceId authority_source;
  AuthorityReference authority_reference;
  std::vector<ActionKind> scope_kinds;
  std::vector<ActionTargetId> scope_targets;
  ObligationState state = ObligationState::active;
  // When true the obligation must remain served across every mode transition
  // unless a SuspensionRecord names the authority that released it.
  bool continuity_required = true;
  std::optional<SuspensionRecord> suspension;
  std::string description;
};

struct CapacityCommitment {
  CapacityCommitmentId id;
  EvidenceSourceId source;
  AuthorityReference authority_reference;
  // Committed demand in kilowatts, as published by the capacity authority. This
  // value is an external fact; the control plane never derives it.
  std::uint64_t committed_kw = 0;
  bool active = true;
  std::vector<ActionTargetId> targets;
  EvidenceRef evidence;
};

// True when the obligation is in scope for the given action kind and target.
[[nodiscard]] bool obligation_in_scope(const ProtectedObligation& obligation,
                                       ActionKind kind,
                                       const ActionTargetId& target) noexcept;

// True when the obligation currently requires service: active, in scope, and
// continuity required.
[[nodiscard]] bool obligation_requires_service(const ProtectedObligation& obligation,
                                               ActionKind kind,
                                               const ActionTargetId& target) noexcept;

[[nodiscard]] Status encode_suspension(CanonicalWriter& writer, const SuspensionRecord& value,
                                      const Limits& limits);
[[nodiscard]] Result<SuspensionRecord> decode_suspension(CanonicalReader& reader,
                                                         const Limits& limits);
[[nodiscard]] Status encode_obligation_suspension(CanonicalWriter& writer,
                                                  const ObligationSuspension& value,
                                                  const Limits& limits);
[[nodiscard]] Result<ObligationSuspension> decode_obligation_suspension(
    CanonicalReader& reader, const Limits& limits);

[[nodiscard]] Status encode_obligation(CanonicalWriter& writer,
                                       const ProtectedObligation& value,
                                       const Limits& limits);
[[nodiscard]] Result<ProtectedObligation> decode_obligation(CanonicalReader& reader,
                                                            const Limits& limits);

[[nodiscard]] Status encode_commitment(CanonicalWriter& writer,
                                       const CapacityCommitment& value,
                                       const Limits& limits);
[[nodiscard]] Result<CapacityCommitment> decode_commitment(CanonicalReader& reader,
                                                           const Limits& limits);

}  // namespace power_control_plane
