#pragma once

// Typed authorization outcomes with machine readable explanations.
//
// A decision is never a boolean. Every decision names the authoritative control
// generation and policy revision it was evaluated against, the evidence binding
// digest that was current, and an ordered explanation trace naming the exact
// obligations, interlocks, evidence sources, permissions, and policy rules that
// produced the outcome.
//
// The explanation trace always contains at least one step, including for accepted
// decisions, so "why was this allowed" is answerable from the recorded decision
// alone.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/digest.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/limits.hpp"

namespace power_control_plane {

enum class DecisionOutcome : std::uint8_t {
  // The action was authorized and committed as a new authoritative generation.
  accepted = 1,
  // The attempt was already accepted under this idempotency key; the recorded
  // result is returned unchanged and no state changed.
  replayed = 2,
  denied = 3,
  unauthorized = 4,
  blocked_by_interlock = 5,
  blocked_by_obligation = 6,
  blocked_by_capacity = 7,
  stale_evidence = 8,
  // The request was planned against a generation, revision, or policy revision
  // that is no longer authoritative.
  stale_generation = 9,
  // The presenting controller epoch/incarnation is not the current writer
  // authority.
  stale_authority = 10,
  indeterminate = 11,
  unsupported = 12,
  invalid_request = 13,
  conflict = 14,
};

[[nodiscard]] std::string_view to_string(DecisionOutcome outcome) noexcept;

// True when the decision permitted a new authoritative transition.
[[nodiscard]] bool decision_committed(DecisionOutcome outcome) noexcept;

enum class ExplanationCode : std::uint8_t {
  accepted = 1,
  idempotent_replay = 2,
  evidence_missing = 3,
  evidence_not_revalidated = 4,
  evidence_generation_mismatch = 5,
  evidence_revision_mismatch = 6,
  evidence_epoch_mismatch = 7,
  evidence_incarnation_mismatch = 8,
  evidence_digest_mismatch = 9,
  evidence_contradictory = 10,
  interlock_engaged = 11,
  interlock_unknown = 12,
  interlock_advisory = 13,
  obligation_unserved = 14,
  obligation_suspended_without_authority = 15,
  capacity_commitment_exceeded = 16,
  capacity_commitment_unknown = 17,
  capacity_commitment_retired = 18,
  permission_missing = 19,
  permission_revoked = 20,
  permission_superseded = 21,
  permission_exhausted = 22,
  permission_not_yet_issued = 23,
  permission_expired = 24,
  permission_scope_mismatch = 25,
  permission_evidence_mismatch = 26,
  permission_policy_mismatch = 27,
  policy_denied = 28,
  policy_requires_permission = 29,
  policy_requires_revalidation = 30,
  policy_no_match = 31,
  policy_allowed = 32,
  generation_mismatch = 33,
  policy_revision_mismatch = 34,
  revision_mismatch = 45,
  epoch_mismatch = 35,
  incarnation_mismatch = 36,
  unsupported_action = 37,
  limit_exceeded = 38,
  arithmetic_overflow = 39,
  mode_transition_refused = 40,
  attempt_conflict = 41,
  attempt_not_found = 42,
  invalid_request = 43,
  request_failed_closed = 44,
};

[[nodiscard]] std::string_view to_string(ExplanationCode code) noexcept;

enum class SubjectKind : std::uint8_t {
  none = 0,
  rule = 1,
  interlock = 2,
  obligation = 3,
  commitment = 4,
  permission = 5,
  evidence_source = 6,
  attempt = 7,
  action = 8,
  mode = 9,
};

struct ExplanationSubject {
  SubjectKind kind = SubjectKind::none;
  std::string id;
};

struct ExplanationStep {
  ExplanationCode code = ExplanationCode::invalid_request;
  ExplanationSubject subject;
  std::string detail;
};

struct AuthorizationDecision {
  DecisionOutcome outcome = DecisionOutcome::invalid_request;
  ControlGeneration authoritative_generation;
  StateRevision authoritative_revision;
  PolicyRevision policy_revision;
  Digest evidence_digest;
  std::vector<ExplanationStep> steps;
  // Present when the outcome is accepted or replayed: the attempt that carries
  // the authorization forward toward actuation.
  std::optional<AttemptId> attempt;
  IdempotencyKey idempotency_key;
  // Echoes the generation the request was planned against, so a refusal can be
  // diffed against the current authority without extra queries.
  ControlGeneration planned_generation;
};

[[nodiscard]] bool decision_is_refusal(const AuthorizationDecision& decision) noexcept;

// The ErrorCode a caller should surface for a refusal outcome. Accepted and
// replayed map to ErrorCode::ok.
[[nodiscard]] ErrorCode decision_error_code(const AuthorizationDecision& decision) noexcept;

// Renders the trace as one deterministic line per step. Used by the CLI and by
// tests that assert on the primary explanation.
[[nodiscard]] std::string describe_decision(const AuthorizationDecision& decision,
                                            const Limits& limits);

}  // namespace power_control_plane
