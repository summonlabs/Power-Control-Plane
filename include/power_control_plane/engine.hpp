#pragma once

// Power Control Plane: the facility-wide authority layer for electrical operating
// state.
//
// ControlPlane answers one question: which facility electrical operating state and
// control authority are valid now, which actions are permitted under the current
// topology, capacity, interlock, and policy evidence, and which attempted actions
// must be refused as stale, unsafe, unauthorized, or inconsistent.
//
// It does not own electrical topology, per-feed eligibility, PDU/UPS/generator
// device lifecycle, load-shedding execution, energy accounting, capacity
// computation, or black start. Those facts arrive as typed EvidenceRef values
// produced by the adjacent DCCP runtimes.
//
// Deterministic validation precedence
// -----------------------------------
// Refusals are primary-coded: the same invalid request always reports the same
// first failure, evaluated in this fixed order:
//
//   1. structural validation of the request (bounds, identifiers, arithmetic)
//   2. idempotent replay of an already accepted attempt
//   3. controller authority (epoch, incarnation) for mutations
//   4. planned-against generation, revision, and policy revision
//   5. evidence freshness and exact binding match
//   6. safety interlocks
//   7. protected obligations
//   8. capacity commitments
//   9. permission grants
//  10. ordered power policy
//
// Steps 2 and 3 are deliberately ordered this way: a retry of an accepted attempt
// must return the committed result before a now-stale generation check could
// reject it. Interlocks precede policy because a policy rule can never outrank a
// safety interlock.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/adapter.hpp"
#include "power_control_plane/evidence.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/interlock.hpp"
#include "power_control_plane/limits.hpp"
#include "power_control_plane/obligation.hpp"
#include "power_control_plane/permission.hpp"
#include "power_control_plane/policy.hpp"
#include "power_control_plane/report.hpp"
#include "power_control_plane/snapshot.hpp"
#include "power_control_plane/store.hpp"
#include "power_control_plane/transition.hpp"

namespace power_control_plane {

struct EngineOptions {
  Limits limits{};
  std::size_t retained_publications = 8;
  CommitObserver* commit_observer = nullptr;
};

struct MutationRequest {
  PlannedAgainst planned;
  IdempotencyKey key;
};

struct ModeTransitionRequest {
  PlannedAgainst planned;
  OperatingMode target = OperatingMode::normal;
  // The external authority that requested the transition.
  AuthorityReference authority;
  // Explicit authority-bound suspensions for protected obligations that will not
  // be served in the target mode. An obligation that needs a suspension and does
  // not have one refuses the transition; it is never dropped silently.
  std::vector<ObligationSuspension> suspensions;
  IdempotencyKey key;
};

// Runtime evidence freshness.
//
// Freshness is a property of this process incarnation, never of the persisted
// bytes. A reopened store always starts with no fresh evidence, and freshness is
// re-established only by an explicit revalidation.
struct EvidenceFreshness {
  bool fresh = false;
  Digest digest;
  ControlGeneration revalidated_generation;
  StateRevision revalidated_revision;
};

struct ControlPlaneStatus {
  bool authoritative_generation_present = false;
  FacilityId facility;
  StoreIncarnation incarnation;
  ControlGeneration generation;
  StateRevision revision;
  PolicyRevision policy_revision;
  LogicalTick tick;
  OperatingMode mode = OperatingMode::normal;
  Digest evidence_digest;
  Digest state_digest;
  std::size_t interlock_count = 0;
  std::size_t blocking_interlock_count = 0;
  std::size_t obligation_count = 0;
  std::size_t unserved_obligation_count = 0;
  std::size_t commitment_count = 0;
  std::size_t active_permission_count = 0;
  std::size_t attempt_count = 0;
  std::size_t open_attempt_count = 0;
  RevalidationReport revalidation;
  WriterStatus writer;
  StoreHead head;
  StoreOpenReport open_report;
};

// The separated outcome of driving one action through an adapter.
struct ActuationOutcome {
  AttemptId attempt;
  AttemptState final_state = AttemptState::authorized;
  bool command_issued = false;
  bool acknowledged = false;
  bool effect_observed = false;
  bool verified = false;
  std::string detail;
};

class ControlPlane {
 public:
  ControlPlane() = default;
  ~ControlPlane();
  ControlPlane(ControlPlane&&) noexcept;
  ControlPlane& operator=(ControlPlane&&) noexcept;
  ControlPlane(const ControlPlane&) = delete;
  ControlPlane& operator=(const ControlPlane&) = delete;

  static Result<ControlPlane> open(const std::string& root, StoreOpenMode mode,
                                   EngineOptions options);

  [[nodiscard]] bool is_open() const noexcept;
  [[nodiscard]] const std::string& root() const noexcept;
  [[nodiscard]] StoreOpenMode mode() const noexcept;
  [[nodiscard]] const Limits& limits() const noexcept;
  [[nodiscard]] const DurableStore& store() const noexcept;

  // ------------------------------------------------------------------
  // Reads. These take no writer authority and mutate nothing.
  // ------------------------------------------------------------------

  [[nodiscard]] Result<FacilitySnapshot> snapshot() const;

  // Full status, including aggregate counts and runtime evidence freshness.
  [[nodiscard]] Result<ControlPlaneStatus> status() const;

  // Runtime evidence freshness. Persisted bindings are never fresh after a
  // reopen until revalidate() is called.
  [[nodiscard]] RevalidationReport revalidation_status() const;

  // Pure policy evaluation: the ordered rule trace and derived outcome, with no
  // interlock, obligation, capacity, or permission stage applied.
  [[nodiscard]] Result<PolicyEvaluation> evaluate_policy(const ActionIntent& intent) const;

  // Full proposed-action evaluation through the whole precedence chain. Never
  // mutates: an accepted evaluation here does not consume a permission, does not
  // create an attempt, and does not advance any generation.
  [[nodiscard]] Result<AuthorizationDecision> evaluate_action(const ActionIntent& intent) const;

  [[nodiscard]] Result<StoreIntegrityReport> verify_store() const;
  [[nodiscard]] Result<ReplayReport> verify_replay() const;

  // ------------------------------------------------------------------
  // Writer authority
  // ------------------------------------------------------------------

  [[nodiscard]] Result<WriterLease> acquire_writer();
  [[nodiscard]] Status release_writer(const WriterLease& lease);

  // ------------------------------------------------------------------
  // Mutation verbs. Every one returns a typed decision; refusals are values, not
  // errors. Errors are reserved for I/O and store failures.
  // ------------------------------------------------------------------

  [[nodiscard]] Result<AuthorizationDecision> bootstrap(const WriterLease& lease,
                                                        const FacilityId& facility,
                                                        OperatingMode initial_mode,
                                                        const EvidenceBinding& evidence,
                                                        const IdempotencyKey& key);

  [[nodiscard]] Result<AuthorizationDecision> bind_evidence(const WriterLease& lease,
                                                            const EvidenceBinding& evidence,
                                                            const MutationRequest& request);

  // Binds evidence and records it as revalidated in this process incarnation.
  [[nodiscard]] Result<AuthorizationDecision> revalidate(const WriterLease& lease,
                                                         const EvidenceBinding& evidence,
                                                         const MutationRequest& request);

  [[nodiscard]] Result<AuthorizationDecision> rebind_policy(const WriterLease& lease,
                                                            const PowerPolicy& policy,
                                                            const MutationRequest& request);

  [[nodiscard]] Result<AuthorizationDecision> record_interlock(const WriterLease& lease,
                                                               const Interlock& interlock,
                                                               const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> remove_interlock(const WriterLease& lease,
                                                               const InterlockId& id,
                                                               const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> record_obligation(
      const WriterLease& lease, const ProtectedObligation& obligation,
      const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> remove_obligation(const WriterLease& lease,
                                                                const ObligationId& id,
                                                                const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> record_commitment(
      const WriterLease& lease, const CapacityCommitment& commitment,
      const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> remove_commitment(
      const WriterLease& lease, const CapacityCommitmentId& id,
      const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> grant_permission(const WriterLease& lease,
                                                               const PermissionGrant& grant,
                                                               const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> retire_permission(const WriterLease& lease,
                                                                const PermissionId& id,
                                                                PermissionState state,
                                                                const MutationRequest& request);

  [[nodiscard]] Result<AuthorizationDecision> request_mode_transition(
      const WriterLease& lease, const ModeTransitionRequest& request);

  // Authorizes an action intent and, when accepted, commits an attempt. A refusal
  // commits nothing.
  [[nodiscard]] Result<AuthorizationDecision> authorize_action(const WriterLease& lease,
                                                               const ActionIntent& intent,
                                                               const MutationRequest& request);

  // ------------------------------------------------------------------
  // Attempt lifecycle. Each step is a separate authoritative publication and each
  // step keeps its own distinct meaning.
  // ------------------------------------------------------------------

  // Records that the command object was handed to an actuation adapter. This is
  // distinct from the authorization that permitted it and from the acknowledgement
  // that may follow it.
  [[nodiscard]] Result<AuthorizationDecision> record_issued(const WriterLease& lease,
                                                           AttemptId attempt,
                                                           Digest command_digest,
                                                           std::string detail,
                                                           const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> record_acknowledgement(
      const WriterLease& lease, AttemptId attempt, const Acknowledgement& acknowledgement,
      const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> record_observed_effect(
      const WriterLease& lease, AttemptId attempt, const ObservedEffect& effect,
      const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> record_effect_failure(
      const WriterLease& lease, AttemptId attempt, const ObservedEffect& effect,
      const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> record_verification(
      const WriterLease& lease, AttemptId attempt, const VerificationReport& verification,
      const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> cancel_attempt(const WriterLease& lease,
                                                             AttemptId attempt,
                                                             const MutationRequest& request);
  [[nodiscard]] Result<AuthorizationDecision> supersede_attempt(const WriterLease& lease,
                                                                AttemptId attempt,
                                                                const MutationRequest& request);

  // Drives one physical action from authorization to verified effect through the
  // supplied adapter. Every intermediate fact is published separately. The
  // returned decision is the authorization; actuation_outcome records how far the
  // command actually got. A refusal never reaches the adapter.
  [[nodiscard]] Result<AuthorizationDecision> actuate(const WriterLease& lease,
                                                      const ActionIntent& intent,
                                                      const MutationRequest& request,
                                                      ActuationAdapter& adapter,
                                                      ActuationOutcome& actuation_outcome);

  void close();

 private:
  // Mutable runtime state. It is deliberately defined here rather than behind an
  // incomplete type so that every translation unit that destroys a ControlPlane can
  // see the complete type. None of it is persisted.
  struct Runtime {
    // Guards the runtime evidence freshness value.
    mutable std::mutex mutex;
    EvidenceFreshness value;
    // Serializes the read-validate-commit sequence of every mutation, so that the
    // authority a request was validated against is still the authority it commits
    // against. Without it, two concurrent mutations could both validate against the
    // same revision and the loser would have to be refused inside the store instead
    // of by the documented precedence chain.
    mutable std::mutex commit_mutex;
  };

  [[nodiscard]] EvidenceFreshness read_freshness() const;
  void set_freshness(const EvidenceFreshness& freshness);

  [[nodiscard]] Result<FacilitySnapshot> current_snapshot() const;
  [[nodiscard]] Status ensure_writer(const WriterLease& lease) const;

  // The single commit path shared by every mutation verb. Handles replay of an
  // already committed operation, planned-against validation, optional evidence
  // freshness, and the refuse-without-effect invariant.
  [[nodiscard]] Result<AuthorizationDecision> commit_record(const WriterLease& lease,
                                                            const PlannedAgainst& planned,
                                                            const IdempotencyKey& key,
                                                            bool check_planned,
                                                            bool require_fresh_evidence,
                                                            TransitionRecord record,
                                                            AttemptId resulting_attempt);

  // The body of commit_record. Callers must already hold Runtime::commit_mutex.
  [[nodiscard]] Result<AuthorizationDecision> commit_record_locked(
      const WriterLease& lease, const PlannedAgainst& planned, const IdempotencyKey& key,
      bool check_planned, bool require_fresh_evidence, TransitionRecord record,
      AttemptId resulting_attempt);

  DurableStore store_;
  std::unique_ptr<Runtime> runtime_;
};

// The version of the control-plane model implemented by this library.
[[nodiscard]] std::string_view control_plane_version() noexcept;

}  // namespace power_control_plane
