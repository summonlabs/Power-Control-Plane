#pragma once

// The authoritative facility electrical control state.
//
// FacilityState is a value type with a read-only public surface. Readers always
// work through an immutable snapshot; the only function that mutates state is
// apply_transition (see transition.hpp), which reaches the fields through the
// library-internal detail::StateEditor friend. The mutable field accessors are
// not part of the installed public API.
//
// Collections are kept in a canonical order (ascending identity) with no
// duplicates, which makes the canonical encoding independent of insertion order
// and therefore byte-deterministic.

#include <cstddef>
#include <cstdint>
#include <map>
#include <string_view>
#include <vector>

#include "power_control_plane/attempt.hpp"
#include "power_control_plane/canonical.hpp"
#include "power_control_plane/decision.hpp"
#include "power_control_plane/digest.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/evidence.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/interlock.hpp"
#include "power_control_plane/limits.hpp"
#include "power_control_plane/mode.hpp"
#include "power_control_plane/obligation.hpp"
#include "power_control_plane/permission.hpp"
#include "power_control_plane/policy.hpp"
#include "power_control_plane/transition.hpp"

namespace power_control_plane {

namespace detail {
class StateEditor;
}  // namespace detail

// One committed mutation, recorded so that a retry of a lost response returns the
// result that was already published instead of re-applying the operation.
//
// Retention is bounded by Limits::max_replay_records. An entry is evicted oldest
// published revision first, which is deterministic and reproducible. After an
// entry has been evicted a retry with the same idempotency key is treated as a new
// operation and is judged entirely by the ordinary authorization pipeline; the
// retention bound is therefore an operational sizing decision, not a safety
// property, and is documented in docs/DESIGN.md.
struct CommittedOperation {
  IdempotencyKey key;
  TransitionKind kind = TransitionKind::facility_bootstrap;
  ControlGeneration generation;
  StateRevision revision;
  DecisionOutcome outcome = DecisionOutcome::accepted;
  // Zero when the verb does not produce an actuation attempt.
  AttemptId attempt;
  AttemptState attempt_state = AttemptState::authorized;
  LogicalTick tick;
};

[[nodiscard]] Status encode_committed_operation(CanonicalWriter& writer,
                                                const CommittedOperation& value,
                                                const Limits& limits);
[[nodiscard]] Result<CommittedOperation> decode_committed_operation(CanonicalReader& reader,
                                                                    const Limits& limits);

class FacilityState {
 public:
  FacilityState() = default;

  // A state with no authoritative generation. Generation zero is the sentinel
  // meaning "no facility electrical operating state is authoritative". A durable
  // store that has never been bootstrapped has no state at all; the first
  // published generation is one.
  [[nodiscard]] static FacilityState vacant(FacilityId facility,
                                            StoreIncarnation incarnation);

  [[nodiscard]] const FacilityId& facility() const noexcept { return facility_; }
  [[nodiscard]] const StoreIncarnation& incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] ControlGeneration generation() const noexcept { return generation_; }
  [[nodiscard]] StateRevision revision() const noexcept { return revision_; }
  [[nodiscard]] PolicyRevision policy_revision() const noexcept { return policy_revision_; }
  [[nodiscard]] LogicalTick tick() const noexcept { return tick_; }
  [[nodiscard]] OperatingMode mode() const noexcept { return mode_; }
  [[nodiscard]] const PowerPolicy& policy() const noexcept { return policy_; }
  [[nodiscard]] const EvidenceBinding& evidence() const noexcept { return evidence_; }
  [[nodiscard]] const std::vector<Interlock>& interlocks() const noexcept { return interlocks_; }
  [[nodiscard]] const std::vector<ProtectedObligation>& obligations() const noexcept {
    return obligations_;
  }
  [[nodiscard]] const std::vector<CapacityCommitment>& commitments() const noexcept {
    return commitments_;
  }
  [[nodiscard]] const std::vector<PermissionGrant>& permissions() const noexcept {
    return permissions_;
  }
  [[nodiscard]] const std::vector<AttemptRecord>& attempts() const noexcept {
    return attempts_;
  }
  [[nodiscard]] const std::map<IdempotencyKey, CommittedOperation>& operation_index()
      const noexcept {
    return operation_index_;
  }
  [[nodiscard]] const CommittedOperation* find_operation(const IdempotencyKey& key)
      const noexcept;
  [[nodiscard]] std::size_t operation_count() const noexcept {
    return operation_index_.size();
  }
  [[nodiscard]] const std::vector<ModeHistoryEntry>& mode_history() const noexcept {
    return mode_history_;
  }
  [[nodiscard]] const std::vector<TransitionLogEntry>& transition_log() const noexcept {
    return transition_log_;
  }
  // Monotonic identity allocators. Persisted so that an identity is never
  // reused after its record is evicted by bounded retention.
  [[nodiscard]] AttemptId next_attempt_id() const noexcept { return next_attempt_id_; }
  [[nodiscard]] PermissionId next_permission_id() const noexcept { return next_permission_id_; }

  [[nodiscard]] std::uint64_t pruned_attempts() const noexcept { return pruned_attempts_; }
  [[nodiscard]] std::uint64_t pruned_replay_records() const noexcept {
    return pruned_replay_records_;
  }

  [[nodiscard]] bool has_authoritative_generation() const noexcept {
    return !generation_.is_zero();
  }

  [[nodiscard]] const Interlock* find_interlock(const InterlockId& id) const noexcept;
  [[nodiscard]] const ProtectedObligation* find_obligation(const ObligationId& id) const noexcept;
  [[nodiscard]] const CapacityCommitment* find_commitment(
      const CapacityCommitmentId& id) const noexcept;
  [[nodiscard]] const PermissionGrant* find_permission(const PermissionId& id) const noexcept;
  [[nodiscard]] const AttemptRecord* find_attempt(AttemptId id) const noexcept;
  [[nodiscard]] const AttemptRecord* find_attempt_by_key(const IdempotencyKey& key) const noexcept;

  // Generation at which the facility most recently entered the given mode, or
  // zero when it never has. Derived from the mode history; no extra persisted
  // field.
  [[nodiscard]] ControlGeneration last_entry_generation(OperatingMode mode) const noexcept;
  // Publication revision at which the facility most recently entered the given mode,
  // or zero when it never has.
  [[nodiscard]] StateRevision last_entry_revision(OperatingMode mode) const noexcept;

  [[nodiscard]] Status encode(CanonicalWriter& writer, const Limits& limits) const;
  [[nodiscard]] static Result<FacilityState> decode(CanonicalReader& reader,
                                                    const Limits& limits);
  [[nodiscard]] static Result<FacilityState> decode(const Bytes& bytes,
                                                    const Limits& limits);

  [[nodiscard]] Bytes encode(const Limits& limits) const;
  [[nodiscard]] Digest canonical_digest() const;

 private:
  friend class detail::StateEditor;

  FacilityId facility_;
  StoreIncarnation incarnation_;
  ControlGeneration generation_;
  StateRevision revision_;
  PolicyRevision policy_revision_;
  LogicalTick tick_;
  OperatingMode mode_ = OperatingMode::normal;
  PowerPolicy policy_;
  EvidenceBinding evidence_;
  std::vector<Interlock> interlocks_;
  std::vector<ProtectedObligation> obligations_;
  std::vector<CapacityCommitment> commitments_;
  std::vector<PermissionGrant> permissions_;
  std::vector<AttemptRecord> attempts_;
  std::map<IdempotencyKey, CommittedOperation> operation_index_;
  std::vector<ModeHistoryEntry> mode_history_;
  std::vector<TransitionLogEntry> transition_log_;
  AttemptId next_attempt_id_{1};
  PermissionId next_permission_id_{1};
  std::uint64_t pruned_attempts_ = 0;
  std::uint64_t pruned_replay_records_ = 0;
};

// Canonical encoding version of the state payload. Bumping it is a format break.
inline constexpr std::uint32_t kStateEncodingVersion = 1;

// Domain tag for the canonical state digest. Digests computed for other purposes
// over identical bytes cannot collide with a state digest.
inline constexpr std::string_view kStateDigestDomain = "pcp/state-digest/v1";

}  // namespace power_control_plane
