#include <string>

#include "power_control_plane/adapter.hpp"
#include "power_control_plane/attempt.hpp"
#include "power_control_plane/decision.hpp"
#include "power_control_plane/evidence.hpp"
#include "power_control_plane/mode.hpp"
#include "power_control_plane/obligation.hpp"
#include "power_control_plane/permission.hpp"
#include "power_control_plane/policy.hpp"
#include "power_control_plane/report.hpp"
#include "power_control_plane/store.hpp"
#include "power_control_plane/transition.hpp"

// Text forms for every enumerator that crosses a boundary: CLI arguments, JSON
// documents, and persisted payloads. Text is the stable spelling; the numeric
// ordinals are only used inside canonical binary payloads, and the text table is
// the single place a spelling is defined.

namespace power_control_plane {
namespace {

template <class Enum>
struct EnumEntry {
  std::string_view text;
  Enum value;
};

template <class Enum, std::size_t Size>
std::string_view enum_to_text(const EnumEntry<Enum> (&table)[Size], Enum value) noexcept {
  for (const EnumEntry<Enum>& entry : table) {
    if (entry.value == value) {
      return entry.text;
    }
  }
  return "unknown";
}

template <class Enum, std::size_t Size>
Result<Enum> enum_from_text(const EnumEntry<Enum> (&table)[Size], std::string_view text,
                            std::string_view what) {
  for (const EnumEntry<Enum>& entry : table) {
    if (entry.text == text) {
      return entry.value;
    }
  }
  std::string message = "unrecognized ";
  message.append(what);
  message.append(": ");
  message.append(text.substr(0, 64));
  return Error(ErrorCode::invalid_argument, std::move(message));
}

constexpr EnumEntry<OperatingMode> kModes[] = {
    {"normal", OperatingMode::normal},
    {"maintenance", OperatingMode::maintenance},
    {"degraded", OperatingMode::degraded},
    {"failover", OperatingMode::failover},
    {"emergency", OperatingMode::emergency},
    {"isolated", OperatingMode::isolated},
};

constexpr EnumEntry<ActionKind> kActionKinds[] = {
    {"open_breaker", ActionKind::open_breaker},
    {"close_breaker", ActionKind::close_breaker},
    {"transfer_source", ActionKind::transfer_source},
    {"set_load_limit", ActionKind::set_load_limit},
    {"enter_maintenance", ActionKind::enter_maintenance},
    {"exit_maintenance", ActionKind::exit_maintenance},
    {"declare_emergency", ActionKind::declare_emergency},
    {"clear_emergency", ActionKind::clear_emergency},
    {"isolate_bus", ActionKind::isolate_bus},
    {"restore_bus", ActionKind::restore_bus},
    {"shed_load_group", ActionKind::shed_load_group},
    {"restore_load_group", ActionKind::restore_load_group},
    {"restore_normal", ActionKind::restore_normal},
    {"revalidate_evidence", ActionKind::revalidate_evidence},
};

constexpr EnumEntry<EvidenceKind> kEvidenceKinds[] = {
    {"power_topology", EvidenceKind::power_topology},
    {"feed_authority", EvidenceKind::feed_authority},
    {"power_capacity", EvidenceKind::power_capacity},
    {"pdu_device", EvidenceKind::pdu_device},
    {"ups_device", EvidenceKind::ups_device},
    {"generator_device", EvidenceKind::generator_device},
    {"load_shedding", EvidenceKind::load_shedding},
    {"energy_ledger", EvidenceKind::energy_ledger},
    {"facility_capacity", EvidenceKind::facility_capacity},
    {"black_start_status", EvidenceKind::black_start_status},
    {"safety_system", EvidenceKind::safety_system},
};

constexpr EnumEntry<InterlockSeverity> kInterlockSeverities[] = {
    {"advisory", InterlockSeverity::advisory},
    {"blocking", InterlockSeverity::blocking},
    {"critical", InterlockSeverity::critical},
};

constexpr EnumEntry<InterlockState> kInterlockStates[] = {
    {"cleared", InterlockState::cleared},
    {"engaged", InterlockState::engaged},
    {"unknown", InterlockState::unknown},
};

constexpr EnumEntry<ObligationState> kObligationStates[] = {
    {"active", ObligationState::active},
    {"suspended", ObligationState::suspended},
};

constexpr EnumEntry<PolicyEffect> kPolicyEffects[] = {
    {"allow", PolicyEffect::allow},
    {"deny", PolicyEffect::deny},
    {"require_permission", PolicyEffect::require_permission},
    {"require_revalidation", PolicyEffect::require_revalidation},
};

constexpr EnumEntry<PolicyConditionKind> kConditionKinds[] = {
    {"always", PolicyConditionKind::always},
    {"mode_is", PolicyConditionKind::mode_is},
    {"action_kind_is", PolicyConditionKind::action_kind_is},
    {"target_is", PolicyConditionKind::target_is},
    {"interlock_state_is", PolicyConditionKind::interlock_state_is},
    {"obligation_state_is", PolicyConditionKind::obligation_state_is},
    {"evidence_source_present", PolicyConditionKind::evidence_source_present},
    {"requested_load_at_least", PolicyConditionKind::requested_load_at_least},
};

constexpr EnumEntry<PolicyOutcome> kPolicyOutcomes[] = {
    {"allow", PolicyOutcome::allow},
    {"deny", PolicyOutcome::deny},
    {"require_permission", PolicyOutcome::require_permission},
    {"require_revalidation", PolicyOutcome::require_revalidation},
    {"no_match", PolicyOutcome::no_match},
};

constexpr EnumEntry<PermissionState> kPermissionStates[] = {
    {"active", PermissionState::active},
    {"revoked", PermissionState::revoked},
    {"superseded", PermissionState::superseded},
    {"exhausted", PermissionState::exhausted},
};

constexpr EnumEntry<PermissionRejection> kPermissionRejections[] = {
    {"revoked", PermissionRejection::revoked},
    {"superseded", PermissionRejection::superseded},
    {"exhausted", PermissionRejection::exhausted},
    {"not_yet_issued", PermissionRejection::not_yet_issued},
    {"expired", PermissionRejection::expired},
    {"scope_mismatch", PermissionRejection::scope_mismatch},
};

constexpr EnumEntry<DecisionOutcome> kDecisionOutcomes[] = {
    {"accepted", DecisionOutcome::accepted},
    {"replayed", DecisionOutcome::replayed},
    {"denied", DecisionOutcome::denied},
    {"unauthorized", DecisionOutcome::unauthorized},
    {"blocked_by_interlock", DecisionOutcome::blocked_by_interlock},
    {"blocked_by_obligation", DecisionOutcome::blocked_by_obligation},
    {"blocked_by_capacity", DecisionOutcome::blocked_by_capacity},
    {"stale_evidence", DecisionOutcome::stale_evidence},
    {"stale_generation", DecisionOutcome::stale_generation},
    {"stale_authority", DecisionOutcome::stale_authority},
    {"indeterminate", DecisionOutcome::indeterminate},
    {"unsupported", DecisionOutcome::unsupported},
    {"invalid_request", DecisionOutcome::invalid_request},
    {"conflict", DecisionOutcome::conflict},
};

constexpr EnumEntry<ExplanationCode> kExplanationCodes[] = {
    {"accepted", ExplanationCode::accepted},
    {"idempotent_replay", ExplanationCode::idempotent_replay},
    {"evidence_missing", ExplanationCode::evidence_missing},
    {"evidence_not_revalidated", ExplanationCode::evidence_not_revalidated},
    {"evidence_generation_mismatch", ExplanationCode::evidence_generation_mismatch},
    {"evidence_revision_mismatch", ExplanationCode::evidence_revision_mismatch},
    {"evidence_epoch_mismatch", ExplanationCode::evidence_epoch_mismatch},
    {"evidence_incarnation_mismatch", ExplanationCode::evidence_incarnation_mismatch},
    {"evidence_digest_mismatch", ExplanationCode::evidence_digest_mismatch},
    {"evidence_contradictory", ExplanationCode::evidence_contradictory},
    {"interlock_engaged", ExplanationCode::interlock_engaged},
    {"interlock_unknown", ExplanationCode::interlock_unknown},
    {"interlock_advisory", ExplanationCode::interlock_advisory},
    {"obligation_unserved", ExplanationCode::obligation_unserved},
    {"obligation_suspended_without_authority", ExplanationCode::obligation_suspended_without_authority},
    {"capacity_commitment_exceeded", ExplanationCode::capacity_commitment_exceeded},
    {"capacity_commitment_unknown", ExplanationCode::capacity_commitment_unknown},
    {"capacity_commitment_retired", ExplanationCode::capacity_commitment_retired},
    {"permission_missing", ExplanationCode::permission_missing},
    {"permission_revoked", ExplanationCode::permission_revoked},
    {"permission_superseded", ExplanationCode::permission_superseded},
    {"permission_exhausted", ExplanationCode::permission_exhausted},
    {"permission_not_yet_issued", ExplanationCode::permission_not_yet_issued},
    {"permission_expired", ExplanationCode::permission_expired},
    {"permission_scope_mismatch", ExplanationCode::permission_scope_mismatch},
    {"permission_evidence_mismatch", ExplanationCode::permission_evidence_mismatch},
    {"permission_policy_mismatch", ExplanationCode::permission_policy_mismatch},
    {"policy_denied", ExplanationCode::policy_denied},
    {"policy_requires_permission", ExplanationCode::policy_requires_permission},
    {"policy_requires_revalidation", ExplanationCode::policy_requires_revalidation},
    {"policy_no_match", ExplanationCode::policy_no_match},
    {"policy_allowed", ExplanationCode::policy_allowed},
    {"generation_mismatch", ExplanationCode::generation_mismatch},
    {"policy_revision_mismatch", ExplanationCode::policy_revision_mismatch},
    {"revision_mismatch", ExplanationCode::revision_mismatch},
    {"epoch_mismatch", ExplanationCode::epoch_mismatch},
    {"incarnation_mismatch", ExplanationCode::incarnation_mismatch},
    {"unsupported_action", ExplanationCode::unsupported_action},
    {"limit_exceeded", ExplanationCode::limit_exceeded},
    {"arithmetic_overflow", ExplanationCode::arithmetic_overflow},
    {"mode_transition_refused", ExplanationCode::mode_transition_refused},
    {"attempt_conflict", ExplanationCode::attempt_conflict},
    {"attempt_not_found", ExplanationCode::attempt_not_found},
    {"invalid_request", ExplanationCode::invalid_request},
    {"request_failed_closed", ExplanationCode::request_failed_closed},
};

constexpr EnumEntry<AttemptState> kAttemptStates[] = {
    {"authorized", AttemptState::authorized},
    {"issued", AttemptState::issued},
    {"acknowledged", AttemptState::acknowledged},
    {"effect_observed", AttemptState::effect_observed},
    {"verified", AttemptState::verified},
    {"refused", AttemptState::refused},
    {"cancelled", AttemptState::cancelled},
    {"superseded", AttemptState::superseded},
    {"effect_failed", AttemptState::effect_failed},
    {"verification_failed", AttemptState::verification_failed},
};

constexpr EnumEntry<AttemptEventKind> kAttemptEventKinds[] = {
    {"authorized", AttemptEventKind::authorized},
    {"issued", AttemptEventKind::issued},
    {"acknowledged", AttemptEventKind::acknowledged},
    {"effect_observed", AttemptEventKind::effect_observed},
    {"effect_failed", AttemptEventKind::effect_failed},
    {"verification_passed", AttemptEventKind::verification_passed},
    {"verification_failed", AttemptEventKind::verification_failed},
    {"cancelled", AttemptEventKind::cancelled},
    {"superseded", AttemptEventKind::superseded},
    {"refused", AttemptEventKind::refused},
};

constexpr EnumEntry<TransitionKind> kTransitionKinds[] = {
    {"facility_bootstrap", TransitionKind::facility_bootstrap},
    {"mode_transition", TransitionKind::mode_transition},
    {"evidence_rebound", TransitionKind::evidence_rebound},
    {"interlock_recorded", TransitionKind::interlock_recorded},
    {"interlock_removed", TransitionKind::interlock_removed},
    {"obligation_recorded", TransitionKind::obligation_recorded},
    {"obligation_removed", TransitionKind::obligation_removed},
    {"commitment_recorded", TransitionKind::commitment_recorded},
    {"commitment_removed", TransitionKind::commitment_removed},
    {"permission_granted", TransitionKind::permission_granted},
    {"permission_retired", TransitionKind::permission_retired},
    {"policy_rebound", TransitionKind::policy_rebound},
    {"attempt_authorized", TransitionKind::attempt_authorized},
    {"attempt_issued", TransitionKind::attempt_issued},
    {"attempt_acknowledged", TransitionKind::attempt_acknowledged},
    {"attempt_effect_observed", TransitionKind::attempt_effect_observed},
    {"attempt_effect_failed", TransitionKind::attempt_effect_failed},
    {"attempt_verified", TransitionKind::attempt_verified},
    {"attempt_verification_failed", TransitionKind::attempt_verification_failed},
    {"attempt_cancelled", TransitionKind::attempt_cancelled},
    {"attempt_superseded", TransitionKind::attempt_superseded},
};

constexpr EnumEntry<CommitStage> kCommitStages[] = {
    {"staging_written", CommitStage::staging_written},
    {"staging_flushed", CommitStage::staging_flushed},
    {"staging_read_back_verified", CommitStage::staging_read_back_verified},
    {"generation_published", CommitStage::generation_published},
    {"head_committed", CommitStage::head_committed},
    {"authority_marked", CommitStage::authority_marked},
    {"residue_retired", CommitStage::residue_retired},
};

constexpr EnumEntry<StoreOpenMode> kStoreOpenModes[] = {
    {"read_only", StoreOpenMode::read_only},
    {"read_write", StoreOpenMode::read_write},
};

constexpr EnumEntry<SimulationBehaviour> kSimulationBehaviours[] = {
    {"full_success", SimulationBehaviour::full_success},
    {"acknowledge_only", SimulationBehaviour::acknowledge_only},
    {"refuse_command", SimulationBehaviour::refuse_command},
    {"effect_contradicts_intent", SimulationBehaviour::effect_contradicts_intent},
    {"effect_unverified", SimulationBehaviour::effect_unverified},
    {"observation_failure", SimulationBehaviour::observation_failure},
};

}  // namespace

std::string_view to_string(OperatingMode mode) noexcept {
  return enum_to_text(kModes, mode);
}
Result<OperatingMode> parse_mode(std::string_view text) {
  return enum_from_text(kModes, text, "operating mode");
}
std::string_view to_string(ActionKind kind) noexcept {
  return enum_to_text(kActionKinds, kind);
}
Result<ActionKind> parse_action_kind(std::string_view text) {
  return enum_from_text(kActionKinds, text, "action kind");
}
std::string_view to_string(EvidenceKind kind) noexcept {
  return enum_to_text(kEvidenceKinds, kind);
}
Result<EvidenceKind> parse_evidence_kind(std::string_view text) {
  return enum_from_text(kEvidenceKinds, text, "evidence kind");
}
std::string_view to_string(InterlockSeverity severity) noexcept {
  return enum_to_text(kInterlockSeverities, severity);
}
std::string_view to_string(InterlockState state) noexcept {
  return enum_to_text(kInterlockStates, state);
}
Result<InterlockSeverity> parse_interlock_severity(std::string_view text) {
  return enum_from_text(kInterlockSeverities, text, "interlock severity");
}
Result<InterlockState> parse_interlock_state(std::string_view text) {
  return enum_from_text(kInterlockStates, text, "interlock state");
}
std::string_view to_string(ObligationState state) noexcept {
  return enum_to_text(kObligationStates, state);
}
Result<ObligationState> parse_obligation_state(std::string_view text) {
  return enum_from_text(kObligationStates, text, "obligation state");
}
std::string_view to_string(PolicyEffect effect) noexcept {
  return enum_to_text(kPolicyEffects, effect);
}
Result<PolicyEffect> parse_policy_effect(std::string_view text) {
  return enum_from_text(kPolicyEffects, text, "policy effect");
}
std::string_view to_string(PolicyConditionKind kind) noexcept {
  return enum_to_text(kConditionKinds, kind);
}
Result<PolicyConditionKind> parse_condition_kind(std::string_view text) {
  return enum_from_text(kConditionKinds, text, "policy condition kind");
}
std::string_view to_string(PolicyOutcome outcome) noexcept {
  return enum_to_text(kPolicyOutcomes, outcome);
}
std::string_view to_string(PermissionState state) noexcept {
  return enum_to_text(kPermissionStates, state);
}
Result<PermissionState> parse_permission_state(std::string_view text) {
  return enum_from_text(kPermissionStates, text, "permission state");
}
std::string_view to_string(PermissionRejection rejection) noexcept {
  return enum_to_text(kPermissionRejections, rejection);
}
std::string_view to_string(DecisionOutcome outcome) noexcept {
  return enum_to_text(kDecisionOutcomes, outcome);
}
std::string_view to_string(ExplanationCode code) noexcept {
  return enum_to_text(kExplanationCodes, code);
}
std::string_view to_string(AttemptState state) noexcept {
  return enum_to_text(kAttemptStates, state);
}
Result<AttemptState> parse_attempt_state(std::string_view text) {
  return enum_from_text(kAttemptStates, text, "attempt state");
}
std::string_view to_string(AttemptEventKind kind) noexcept {
  return enum_to_text(kAttemptEventKinds, kind);
}
std::string_view to_string(TransitionKind kind) noexcept {
  return enum_to_text(kTransitionKinds, kind);
}
Result<TransitionKind> parse_transition_kind(std::string_view text) {
  return enum_from_text(kTransitionKinds, text, "transition kind");
}
std::string_view to_string(CommitStage stage) noexcept {
  return enum_to_text(kCommitStages, stage);
}
std::string_view to_string(StoreOpenMode mode) noexcept {
  return enum_to_text(kStoreOpenModes, mode);
}
Result<StoreOpenMode> parse_store_open_mode(std::string_view text) {
  return enum_from_text(kStoreOpenModes, text, "store open mode");
}
std::string_view to_string(SimulationBehaviour behaviour) noexcept {
  return enum_to_text(kSimulationBehaviours, behaviour);
}
Result<SimulationBehaviour> parse_simulation_behaviour(std::string_view text) {
  return enum_from_text(kSimulationBehaviours, text, "simulation behaviour");
}

bool commit_stage_is_authoritative(CommitStage stage) noexcept {
  return stage == CommitStage::head_committed || stage == CommitStage::authority_marked ||
         stage == CommitStage::residue_retired;
}

bool attempt_is_terminal(AttemptState state) noexcept {
  return state == AttemptState::verified || state == AttemptState::refused ||
         state == AttemptState::cancelled || state == AttemptState::superseded ||
         state == AttemptState::effect_failed ||
         state == AttemptState::verification_failed;
}

bool decision_committed(DecisionOutcome outcome) noexcept {
  return outcome == DecisionOutcome::accepted || outcome == DecisionOutcome::replayed;
}

bool decision_is_refusal(const AuthorizationDecision& decision) noexcept {
  return !decision_committed(decision.outcome);
}

ErrorCode decision_error_code(const AuthorizationDecision& decision) noexcept {
  switch (decision.outcome) {
    case DecisionOutcome::accepted:
    case DecisionOutcome::replayed:
      return ErrorCode::ok;
    case DecisionOutcome::denied:
      return ErrorCode::denied_by_policy;
    case DecisionOutcome::unauthorized:
      return ErrorCode::unauthorized;
    case DecisionOutcome::blocked_by_interlock:
      return ErrorCode::blocked_by_interlock;
    case DecisionOutcome::blocked_by_obligation:
      return ErrorCode::blocked_by_obligation;
    case DecisionOutcome::blocked_by_capacity:
      return ErrorCode::blocked_by_capacity;
    case DecisionOutcome::stale_evidence:
      return ErrorCode::stale_evidence;
    case DecisionOutcome::stale_generation:
      return ErrorCode::stale_generation;
    case DecisionOutcome::stale_authority:
      return ErrorCode::stale_epoch;
    case DecisionOutcome::indeterminate:
      return ErrorCode::indeterminate;
    case DecisionOutcome::unsupported:
      return ErrorCode::unsupported;
    case DecisionOutcome::invalid_request:
      return ErrorCode::invalid_argument;
    case DecisionOutcome::conflict:
      return ErrorCode::conflict;
  }
  return ErrorCode::internal_failure;
}

}  // namespace power_control_plane
