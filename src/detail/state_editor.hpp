#pragma once

// Library-internal mutable access to FacilityState.
//
// This header is not installed. The only translation units that may include it
// are the ones implementing apply_transition and durable-store loading. Public
// headers expose FacilityState with a read-only surface, so the mutation authority
// path is narrow by construction rather than by convention.

#include <cstddef>
#include <optional>

#include "power_control_plane/limits.hpp"
#include "power_control_plane/state.hpp"

namespace power_control_plane::detail {

class StateEditor {
 public:
  explicit StateEditor(FacilityState& state) noexcept : state_(state) {}

  [[nodiscard]] FacilityId& facility() noexcept { return state_.facility_; }
  [[nodiscard]] StoreIncarnation& incarnation() noexcept { return state_.incarnation_; }
  [[nodiscard]] ControlGeneration& generation() noexcept { return state_.generation_; }
  [[nodiscard]] StateRevision& revision() noexcept { return state_.revision_; }
  [[nodiscard]] PolicyRevision& policy_revision() noexcept { return state_.policy_revision_; }
  [[nodiscard]] LogicalTick& tick() noexcept { return state_.tick_; }
  [[nodiscard]] OperatingMode& mode() noexcept { return state_.mode_; }
  [[nodiscard]] PowerPolicy& policy() noexcept { return state_.policy_; }
  [[nodiscard]] EvidenceBinding& evidence() noexcept { return state_.evidence_; }
  [[nodiscard]] std::vector<Interlock>& interlocks() noexcept { return state_.interlocks_; }
  [[nodiscard]] std::vector<ProtectedObligation>& obligations() noexcept {
    return state_.obligations_;
  }
  [[nodiscard]] std::vector<CapacityCommitment>& commitments() noexcept {
    return state_.commitments_;
  }
  [[nodiscard]] std::vector<PermissionGrant>& permissions() noexcept {
    return state_.permissions_;
  }
  [[nodiscard]] std::vector<AttemptRecord>& attempts() noexcept { return state_.attempts_; }
  [[nodiscard]] std::map<IdempotencyKey, CommittedOperation>& operation_index() noexcept {
    return state_.operation_index_;
  }
  [[nodiscard]] std::vector<ModeHistoryEntry>& mode_history() noexcept {
    return state_.mode_history_;
  }
  [[nodiscard]] std::vector<TransitionLogEntry>& transition_log() noexcept {
    return state_.transition_log_;
  }
  [[nodiscard]] AttemptId& next_attempt_id() noexcept { return state_.next_attempt_id_; }
  [[nodiscard]] PermissionId& next_permission_id() noexcept {
    return state_.next_permission_id_;
  }
  [[nodiscard]] std::uint64_t& pruned_attempts() noexcept { return state_.pruned_attempts_; }
  [[nodiscard]] std::uint64_t& pruned_replay_records() noexcept {
    return state_.pruned_replay_records_;
  }

  // Appends the log entry for the transition being applied and trims the log to
  // the configured bound. Callers must set entry.generation, entry.revision,
  // entry.kind, entry.previous_state_digest, entry.tick, and entry.payload before
  // calling.
  [[nodiscard]] Status append_transition_log(TransitionLogEntry entry, const Limits& limits);

  // Sorted, duplicate-free insert or replace for each bounded collection. Each
  // refuses with limit_exceeded when the collection is full and the identity is
  // new, and with duplicate_identity when the identity is new but reserved.
  [[nodiscard]] Status upsert_interlock(Interlock value, const Limits& limits);
  [[nodiscard]] Status upsert_obligation(ProtectedObligation value, const Limits& limits);
  [[nodiscard]] Status upsert_commitment(CapacityCommitment value, const Limits& limits);
  [[nodiscard]] Status upsert_permission(PermissionGrant value, const Limits& limits);
  [[nodiscard]] Status upsert_attempt(AttemptRecord value, const Limits& limits);
  [[nodiscard]] Status upsert_mode_history(ModeHistoryEntry value, const Limits& limits);

  [[nodiscard]] bool erase_interlock(const InterlockId& id) noexcept;
  [[nodiscard]] bool erase_obligation(const ObligationId& id) noexcept;
  [[nodiscard]] bool erase_commitment(const CapacityCommitmentId& id) noexcept;

  [[nodiscard]] ProtectedObligation* mutable_obligation(const ObligationId& id) noexcept;
  [[nodiscard]] PermissionGrant* mutable_permission(const PermissionId& id) noexcept;
  [[nodiscard]] AttemptRecord* mutable_attempt(AttemptId id) noexcept;

  [[nodiscard]] FacilityState& state() noexcept { return state_; }

 private:
  FacilityState& state_;
};

// Bounded-retention maintenance. Removes the oldest attempts and replay records so
// the persisted state stays inside Limits::max_attempts and
// Limits::max_replay_records. Retention semantics are documented in
// docs/DESIGN.md: an attempt's replay record is retained until the configured
// bound evicts it, after which a retry with the same key is a new attempt.
[[nodiscard]] Status enforce_retention(StateEditor& editor, const Limits& limits,
                                       std::uint64_t& attempts_removed,
                                       std::uint64_t& replay_records_removed);

}  // namespace power_control_plane::detail
