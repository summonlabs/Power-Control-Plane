#include "power_control_plane/engine.hpp"

#include <algorithm>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "power_control_plane/version.hpp"

// The control plane engine.
//
// Deterministic validation precedence, evaluated in this exact order so that the
// same invalid request always produces the same primary outcome:
//
//   1. structural validation of the request
//   2. idempotent replay of an already committed operation
//   3. controller authority (epoch and incarnation) for mutations
//   4. planned-against generation, revision, and policy revision
//   5. evidence binding and runtime freshness
//   6. safety interlocks
//   7. protected obligations
//   8. capacity commitments
//   9. permission grants
//  10. ordered power policy
//
// Steps 2 and 3 are ordered so that a retry of an accepted operation returns the
// committed result before a now-stale generation check could reject it. Step 6
// precedes step 10 so that no policy rule can outrank a safety interlock.

namespace power_control_plane {
namespace {

// The target identity used by facility-wide permissions and by mode transitions,
// which are not directed at one piece of equipment.
constexpr std::string_view kFacilityTargetId = "facility";

bool mode_preserves_continuity(OperatingMode mode) noexcept {
  return mode != OperatingMode::emergency && mode != OperatingMode::isolated;
}

struct StepSink {
  const Limits* limits = nullptr;
  std::vector<ExplanationStep>* steps = nullptr;

  void add(ExplanationCode code, SubjectKind kind, std::string_view id,
           std::string detail) const {
    if (steps == nullptr || limits == nullptr) {
      return;
    }
    if (steps->size() >= limits->max_explanation_steps) {
      return;
    }
    ExplanationStep step;
    step.code = code;
    step.subject.kind = kind;
    step.subject.id.assign(id.substr(0, limits->max_identifier_length));
    if (detail.size() > limits->max_explanation_detail_bytes) {
      detail.resize(limits->max_explanation_detail_bytes);
    }
    step.detail = std::move(detail);
    steps->push_back(std::move(step));
  }
};

DecisionOutcome outcome_for_error(ErrorCode code) {
  switch (code) {
    case ErrorCode::blocked_by_interlock:
      return DecisionOutcome::blocked_by_interlock;
    case ErrorCode::blocked_by_obligation:
      return DecisionOutcome::blocked_by_obligation;
    case ErrorCode::blocked_by_capacity:
      return DecisionOutcome::blocked_by_capacity;
    case ErrorCode::stale_evidence:
      return DecisionOutcome::stale_evidence;
    case ErrorCode::stale_generation:
    case ErrorCode::stale_revision:
      return DecisionOutcome::stale_generation;
    case ErrorCode::stale_epoch:
    case ErrorCode::stale_incarnation:
    case ErrorCode::not_authoritative:
      return DecisionOutcome::stale_authority;
    case ErrorCode::unauthorized:
      return DecisionOutcome::unauthorized;
    case ErrorCode::denied_by_policy:
      return DecisionOutcome::denied;
    case ErrorCode::indeterminate:
    case ErrorCode::capacity_exhausted:
      return DecisionOutcome::indeterminate;
    case ErrorCode::unsupported:
      return DecisionOutcome::unsupported;
    case ErrorCode::duplicate_identity:
    case ErrorCode::conflict:
    case ErrorCode::invalid_transition:
    case ErrorCode::not_found:
      return DecisionOutcome::conflict;
    default:
      return DecisionOutcome::invalid_request;
  }
}

ExplanationCode explanation_for_error(ErrorCode code) {
  switch (code) {
    case ErrorCode::limit_exceeded:
      return ExplanationCode::limit_exceeded;
    case ErrorCode::arithmetic_overflow:
      return ExplanationCode::arithmetic_overflow;
    case ErrorCode::stale_generation:
    case ErrorCode::stale_revision:
      return ExplanationCode::generation_mismatch;
    case ErrorCode::stale_evidence:
      return ExplanationCode::evidence_not_revalidated;
    case ErrorCode::stale_epoch:
      return ExplanationCode::epoch_mismatch;
    case ErrorCode::stale_incarnation:
      return ExplanationCode::incarnation_mismatch;
    case ErrorCode::not_found:
      return ExplanationCode::attempt_not_found;
    case ErrorCode::invalid_transition:
    case ErrorCode::conflict:
    case ErrorCode::duplicate_identity:
      return ExplanationCode::mode_transition_refused;
    case ErrorCode::blocked_by_interlock:
      return ExplanationCode::interlock_engaged;
    case ErrorCode::blocked_by_obligation:
      return ExplanationCode::obligation_unserved;
    case ErrorCode::blocked_by_capacity:
      return ExplanationCode::capacity_commitment_exceeded;
    case ErrorCode::unauthorized:
      return ExplanationCode::permission_missing;
    case ErrorCode::denied_by_policy:
      return ExplanationCode::policy_denied;
    default:
      return ExplanationCode::invalid_request;
  }
}

bool is_destructive_action(ActionKind kind) noexcept {
  switch (kind) {
    case ActionKind::open_breaker:
    case ActionKind::transfer_source:
    case ActionKind::set_load_limit:
    case ActionKind::isolate_bus:
    case ActionKind::shed_load_group:
      return true;
    default:
      return false;
  }
}

bool action_declares_demand(ActionKind kind) noexcept {
  switch (kind) {
    case ActionKind::close_breaker:
    case ActionKind::transfer_source:
    case ActionKind::set_load_limit:
    case ActionKind::restore_bus:
    case ActionKind::restore_load_group:
      return true;
    default:
      return false;
  }
}

ExplanationCode permission_rejection_code(PermissionRejection rejection) {
  switch (rejection) {
    case PermissionRejection::revoked:
      return ExplanationCode::permission_revoked;
    case PermissionRejection::superseded:
      return ExplanationCode::permission_superseded;
    case PermissionRejection::exhausted:
      return ExplanationCode::permission_exhausted;
    case PermissionRejection::not_yet_issued:
      return ExplanationCode::permission_not_yet_issued;
    case PermissionRejection::expired:
      return ExplanationCode::permission_expired;
    case PermissionRejection::scope_mismatch:
      return ExplanationCode::permission_scope_mismatch;
  }
  return ExplanationCode::permission_missing;
}

struct StageOutcome {
  bool blocked = false;
  DecisionOutcome outcome = DecisionOutcome::indeterminate;
};

StageOutcome stage_planned_against(const FacilityState& state, const PlannedAgainst& planned,
                                   const StepSink& sink) {
  StageOutcome result;
  if (planned.generation != state.generation()) {
    sink.add(ExplanationCode::generation_mismatch, SubjectKind::mode, "",
             "the request was planned against a different authoritative control generation");
    result.blocked = true;
    result.outcome = DecisionOutcome::stale_generation;
    return result;
  }
  if (planned.revision != state.revision()) {
    sink.add(ExplanationCode::revision_mismatch, SubjectKind::mode, "",
             "the request was planned against a different authoritative publication revision");
    result.blocked = true;
    result.outcome = DecisionOutcome::stale_generation;
    return result;
  }
  if (planned.policy_revision != state.policy_revision()) {
    sink.add(ExplanationCode::policy_revision_mismatch, SubjectKind::rule, "",
             "the request was planned against a different power policy revision");
    result.blocked = true;
    result.outcome = DecisionOutcome::stale_generation;
    return result;
  }
  return result;
}

StageOutcome stage_evidence(const FacilityState& state, const Digest& planned_digest,
                            const EvidenceFreshness& freshness, bool require_fresh,
                            const StepSink& sink) {
  StageOutcome result;
  const Digest current = state.evidence().digest();
  if (state.evidence().empty()) {
    sink.add(ExplanationCode::evidence_missing, SubjectKind::evidence_source, "",
             "no external evidence is bound to this facility control generation");
    result.blocked = true;
    result.outcome = DecisionOutcome::indeterminate;
    return result;
  }
  if (!(planned_digest == current)) {
    sink.add(ExplanationCode::evidence_digest_mismatch, SubjectKind::evidence_source, "",
             "the request names an evidence binding that is not the currently bound one");
    result.blocked = true;
    result.outcome = DecisionOutcome::stale_evidence;
    return result;
  }
  if (require_fresh && (!freshness.fresh || !(freshness.digest == current))) {
    sink.add(ExplanationCode::evidence_not_revalidated, SubjectKind::evidence_source, "",
             "the bound evidence has not been revalidated in this process incarnation");
    result.blocked = true;
    result.outcome = DecisionOutcome::stale_evidence;
    return result;
  }
  return result;
}

StageOutcome stage_interlocks(const FacilityState& state, ActionKind kind,
                              const ActionTargetId& target, const StepSink& sink) {
  StageOutcome result;
  for (const Interlock& interlock : state.interlocks()) {
    if (interlock.severity == InterlockSeverity::advisory) {
      if (interlock.state != InterlockState::cleared &&
          std::find(interlock.scope_kinds.begin(), interlock.scope_kinds.end(), kind) !=
              interlock.scope_kinds.end()) {
        sink.add(ExplanationCode::interlock_advisory, SubjectKind::interlock,
                 interlock.id.view(), interlock.explanation);
      }
      continue;
    }
    if (!interlock_blocks(interlock, kind, target)) {
      continue;
    }
    sink.add(interlock.state == InterlockState::unknown ? ExplanationCode::interlock_unknown
                                                        : ExplanationCode::interlock_engaged,
             SubjectKind::interlock, interlock.id.view(), interlock.explanation);
    result.blocked = true;
    result.outcome = DecisionOutcome::blocked_by_interlock;
    return result;
  }
  return result;
}

StageOutcome stage_obligations(const FacilityState& state, ActionKind kind,
                               const ActionTargetId& target, const StepSink& sink) {
  StageOutcome result;
  for (const ProtectedObligation& obligation : state.obligations()) {
    if (!obligation_in_scope(obligation, kind, target)) {
      continue;
    }
    if (obligation.state == ObligationState::suspended) {
      if (!obligation.suspension.has_value() || obligation.suspension->authority.empty()) {
        sink.add(ExplanationCode::obligation_suspended_without_authority,
                 SubjectKind::obligation, obligation.id.view(),
                 "the obligation is recorded as suspended without a named external authority");
        result.blocked = true;
        result.outcome = DecisionOutcome::indeterminate;
        return result;
      }
      continue;
    }
    if (!obligation.continuity_required || !is_destructive_action(kind)) {
      continue;
    }
    sink.add(ExplanationCode::obligation_unserved, SubjectKind::obligation,
             obligation.id.view(), obligation.description);
    result.blocked = true;
    result.outcome = DecisionOutcome::blocked_by_obligation;
    return result;
  }
  return result;
}

StageOutcome stage_capacity(const FacilityState& state, const ActionIntent& intent,
                            const StepSink& sink) {
  StageOutcome result;
  if (intent.requested_load_kw == 0 || !action_declares_demand(intent.kind)) {
    return result;
  }
  std::uint64_t committed = 0;
  bool covered = false;
  bool retired = false;
  for (const CapacityCommitment& commitment : state.commitments()) {
    const bool in_scope = commitment.targets.empty() ||
                          std::find(commitment.targets.begin(), commitment.targets.end(),
                                    intent.target) != commitment.targets.end();
    if (!in_scope) {
      continue;
    }
    if (!commitment.active) {
      retired = true;
      continue;
    }
    covered = true;
    auto total = checked_accumulate(committed, commitment.committed_kw);
    if (!total.has_value()) {
      sink.add(ExplanationCode::arithmetic_overflow, SubjectKind::commitment,
               commitment.id.view(),
               "the committed capacity covering this target overflows 64-bit arithmetic");
      result.blocked = true;
      result.outcome = DecisionOutcome::invalid_request;
      return result;
    }
    committed = total.value();
  }
  if (!covered) {
    sink.add(ExplanationCode::capacity_commitment_unknown, SubjectKind::commitment, "",
             retired ? "every capacity commitment covering this target has been retired; the "
                       "absence of a commitment is not evidence of zero demand"
                     : "no capacity commitment covers this target; the absence of a commitment "
                       "is not evidence of zero demand");
    result.blocked = true;
    result.outcome = DecisionOutcome::indeterminate;
    return result;
  }
  if (intent.requested_load_kw > committed) {
    sink.add(ExplanationCode::capacity_commitment_exceeded, SubjectKind::commitment,
             intent.target.view(),
             "the declared demand exceeds the committed capacity available for this target");
    result.blocked = true;
    result.outcome = DecisionOutcome::blocked_by_capacity;
    return result;
  }
  return result;
}

struct PermissionStage {
  StageOutcome result;
  const PermissionGrant* grant = nullptr;
};

PermissionStage stage_permission(const FacilityState& state, ActionKind kind,
                                 const ActionTargetId& target, const StepSink& sink) {
  PermissionStage stage;
  const PermissionGrant* first_in_scope = nullptr;
  PermissionRejection first_rejection = PermissionRejection::scope_mismatch;
  bool reported_binding_mismatch = false;
  for (const PermissionGrant& grant : state.permissions()) {
    if (!permission_covers(grant, kind, target)) {
      continue;
    }
    const auto rejection =
        permission_rejection(grant, kind, target, state.generation(), state.revision());
    if (!rejection.has_value()) {
      if (!(grant.evidence.digest() == state.evidence().digest())) {
        if (!reported_binding_mismatch) {
          reported_binding_mismatch = true;
          sink.add(ExplanationCode::permission_evidence_mismatch, SubjectKind::permission,
                   std::to_string(grant.id.value()),
                   "the grant was issued against a different evidence binding than the one "
                   "currently bound");
        }
        continue;
      }
      if (grant.policy_revision != state.policy_revision()) {
        if (!reported_binding_mismatch) {
          reported_binding_mismatch = true;
          sink.add(ExplanationCode::permission_policy_mismatch, SubjectKind::permission,
                   std::to_string(grant.id.value()),
                   "the grant was issued under a different power policy revision");
        }
        continue;
      }
      stage.grant = &grant;
      return stage;
    }
    if (first_in_scope == nullptr) {
      first_in_scope = &grant;
      first_rejection = rejection.value();
    }
  }
  if (first_in_scope == nullptr && !reported_binding_mismatch) {
    sink.add(ExplanationCode::permission_missing, SubjectKind::permission, "",
             "no permission covers this action kind and target");
  } else if (first_in_scope != nullptr) {
    sink.add(permission_rejection_code(first_rejection), SubjectKind::permission,
             std::to_string(first_in_scope->id.value()),
             "the only permission covering this action is not usable");
  }
  stage.result.blocked = true;
  stage.result.outcome = DecisionOutcome::unauthorized;
  return stage;
}

bool condition_matches(const FacilityState& state, const ActionIntent& intent,
                       const PolicyCondition& condition) {
  switch (condition.kind) {
    case PolicyConditionKind::always:
      return true;
    case PolicyConditionKind::mode_is:
      return state.mode() == condition.mode;
    case PolicyConditionKind::action_kind_is:
      return intent.kind == condition.action_kind;
    case PolicyConditionKind::target_is:
      return intent.target == condition.target;
    case PolicyConditionKind::interlock_state_is:
      for (const Interlock& interlock : state.interlocks()) {
        if (interlock.state == condition.interlock_state) {
          return true;
        }
      }
      return false;
    case PolicyConditionKind::obligation_state_is:
      for (const ProtectedObligation& obligation : state.obligations()) {
        if (obligation.state == condition.obligation_state) {
          return true;
        }
      }
      return false;
    case PolicyConditionKind::evidence_source_present:
      return state.evidence().contains(condition.evidence_source);
    case PolicyConditionKind::requested_load_at_least:
      return intent.requested_load_kw >= condition.threshold_kw;
  }
  return false;
}

PolicyEvaluation evaluate_policy_rules(const FacilityState& state, const ActionIntent& intent) {
  PolicyEvaluation evaluation;
  evaluation.revision = state.policy().revision();
  bool denied = false;
  bool has_requirement = false;
  bool has_allow = false;
  PolicyOutcome requirement = PolicyOutcome::no_match;
  for (const PolicyRule& rule : state.policy().rules()) {
    PolicyRuleTrace trace;
    trace.rule = rule.id;
    trace.order = rule.order;
    trace.effect = rule.effect;
    trace.matched = condition_matches(state, intent, rule.condition);
    trace.explanation = rule.explanation;
    if (trace.matched) {
      switch (rule.effect) {
        case PolicyEffect::deny:
          denied = true;
          break;
        case PolicyEffect::allow:
          has_allow = true;
          break;
        case PolicyEffect::require_permission:
          has_requirement = true;
          requirement = PolicyOutcome::require_permission;
          break;
        case PolicyEffect::require_revalidation:
          has_requirement = true;
          requirement = PolicyOutcome::require_revalidation;
          break;
      }
    }
    evaluation.trace.push_back(std::move(trace));
  }
  if (denied) {
    evaluation.outcome = PolicyOutcome::deny;
  } else if (has_requirement) {
    evaluation.outcome = requirement;
  } else if (has_allow) {
    evaluation.outcome = PolicyOutcome::allow;
  } else {
    evaluation.outcome = PolicyOutcome::no_match;
  }
  return evaluation;
}

StageOutcome stage_policy(const FacilityState& state, const ActionIntent& intent,
                          const StepSink& sink) {
  StageOutcome result;
  const PolicyEvaluation evaluation = evaluate_policy_rules(state, intent);
  for (const PolicyRuleTrace& trace : evaluation.trace) {
    if (!trace.matched) {
      continue;
    }
    switch (trace.effect) {
      case PolicyEffect::deny:
        sink.add(ExplanationCode::policy_denied, SubjectKind::rule, trace.rule.view(),
                 trace.explanation);
        result.blocked = true;
        result.outcome = DecisionOutcome::denied;
        return result;
      case PolicyEffect::require_permission:
        sink.add(ExplanationCode::policy_requires_permission, SubjectKind::rule,
                 trace.rule.view(), trace.explanation);
        break;
      case PolicyEffect::require_revalidation:
        sink.add(ExplanationCode::policy_requires_revalidation, SubjectKind::rule,
                 trace.rule.view(), trace.explanation);
        break;
      case PolicyEffect::allow:
        sink.add(ExplanationCode::policy_allowed, SubjectKind::rule, trace.rule.view(),
                 trace.explanation);
        break;
    }
  }
  if (evaluation.outcome == PolicyOutcome::allow) {
    return result;
  }
  if (evaluation.outcome == PolicyOutcome::no_match) {
    sink.add(ExplanationCode::policy_no_match, SubjectKind::rule, "",
             "no policy rule authorizes this action; the default is refusal");
  }
  result.blocked = true;
  result.outcome = DecisionOutcome::denied;
  return result;
}

DecisionOutcome evaluate_action_pipeline(const FacilityState& state, const ActionIntent& intent,
                                         const EvidenceFreshness& freshness, const Limits& limits,
                                         std::vector<ExplanationStep>& steps,
                                         PermissionId* consumed_permission) {
  const StepSink sink{&limits, &steps};
  StageOutcome stage = stage_planned_against(state, intent.planned, sink);
  if (stage.blocked) {
    return stage.outcome;
  }
  stage = stage_evidence(state, intent.planned.evidence_digest, freshness, true, sink);
  if (stage.blocked) {
    return stage.outcome;
  }
  stage = stage_interlocks(state, intent.kind, intent.target, sink);
  if (stage.blocked) {
    return stage.outcome;
  }
  stage = stage_obligations(state, intent.kind, intent.target, sink);
  if (stage.blocked) {
    return stage.outcome;
  }
  stage = stage_capacity(state, intent, sink);
  if (stage.blocked) {
    return stage.outcome;
  }
  const PermissionStage permission = stage_permission(state, intent.kind, intent.target, sink);
  if (permission.result.blocked) {
    return permission.result.outcome;
  }
  if (consumed_permission != nullptr) {
    *consumed_permission = permission.grant->id;
  }
  stage = stage_policy(state, intent, sink);
  if (stage.blocked) {
    return stage.outcome;
  }
  sink.add(ExplanationCode::accepted, SubjectKind::action, intent.id.view(),
           "the action is authorized against the current generation, evidence binding, "
           "interlocks, obligations, capacity commitments, permission, and policy");
  return DecisionOutcome::accepted;
}

ActionKind mode_action_kind(const ModeTransitionRule& rule) noexcept {
  if (rule.requires_permission && rule.required_kind != 0) {
    return static_cast<ActionKind>(rule.required_kind);
  }
  switch (rule.to) {
    case OperatingMode::maintenance:
      return ActionKind::enter_maintenance;
    case OperatingMode::degraded:
      return ActionKind::set_load_limit;
    case OperatingMode::failover:
      return ActionKind::transfer_source;
    case OperatingMode::emergency:
      return ActionKind::declare_emergency;
    case OperatingMode::isolated:
      return ActionKind::isolate_bus;
    case OperatingMode::normal:
      return ActionKind::restore_normal;
  }
  return ActionKind::restore_normal;
}

DecisionOutcome evaluate_mode_transition_pipeline(const FacilityState& state,
                                                  const ModeTransitionRequest& request,
                                                  const EvidenceFreshness& freshness,
                                                  const Limits& limits,
                                                  std::vector<ExplanationStep>& steps) {
  const StepSink sink{&limits, &steps};
  StageOutcome stage = stage_planned_against(state, request.planned, sink);
  if (stage.blocked) {
    return stage.outcome;
  }
  if (state.mode() == request.target) {
    sink.add(ExplanationCode::mode_transition_refused, SubjectKind::mode,
             to_string(request.target),
             "the facility is already in that operating mode");
    return DecisionOutcome::conflict;
  }
  const ModeTransitionRule* rule = find_mode_transition(state.mode(), request.target);
  if (rule == nullptr) {
    sink.add(ExplanationCode::mode_transition_refused, SubjectKind::mode,
             to_string(request.target),
             "the requested operating mode transition is not permitted by the mode "
             "transition table");
    return DecisionOutcome::conflict;
  }
  const bool planned_transition =
      rule->requires_fresh_evidence || rule->requires_permission ||
      rule->requires_obligation_plan || rule->requires_post_event_revalidation;
  if (!planned_transition) {
    sink.add(ExplanationCode::accepted, SubjectKind::mode, to_string(request.target),
             "a deterioration record is never blocked by missing evidence or a missing "
             "permission; it only tightens the requirements that later actions must meet");
    return DecisionOutcome::accepted;
  }
  stage = stage_evidence(state, request.planned.evidence_digest, freshness,
                         rule->requires_fresh_evidence, sink);
  if (stage.blocked) {
    return stage.outcome;
  }
  if (rule->requires_post_event_revalidation) {
    // Generations do not advance for metadata-only publications, so the ordering is
    // expressed in publication revisions: the revalidation must have happened in a
    // later publication than the one that recorded the emergency or isolation.
    StateRevision last_event = state.last_entry_revision(OperatingMode::emergency);
    const StateRevision isolated = state.last_entry_revision(OperatingMode::isolated);
    if (isolated > last_event) {
      last_event = isolated;
    }
    if (!freshness.fresh || !(freshness.revalidated_revision > last_event)) {
      sink.add(ExplanationCode::evidence_not_revalidated, SubjectKind::mode, "",
               "leaving emergency or isolation requires an evidence revalidation performed "
               "after the facility entered it");
      return DecisionOutcome::stale_evidence;
    }
  }
  const auto facility_target = ActionTargetId::parse(kFacilityTargetId);
  if (!facility_target.has_value()) {
    return DecisionOutcome::unsupported;
  }
  const ActionKind kind = mode_action_kind(*rule);
  stage = stage_interlocks(state, kind, facility_target.value(), sink);
  if (stage.blocked) {
    return stage.outcome;
  }
  if (!mode_preserves_continuity(request.target)) {
    for (const ProtectedObligation& obligation : state.obligations()) {
      if (!obligation.continuity_required || obligation.state != ObligationState::active) {
        continue;
      }
      bool covered = false;
      for (const ObligationSuspension& suspension : request.suspensions) {
        if (suspension.obligation == obligation.id && !suspension.record.authority.empty()) {
          covered = true;
          break;
        }
      }
      if (!covered) {
        sink.add(ExplanationCode::obligation_unserved, SubjectKind::obligation,
                 obligation.id.view(),
                 "the target operating mode does not preserve continuity and this "
                 "continuity-required obligation has no authority-bound suspension");
        return DecisionOutcome::blocked_by_obligation;
      }
    }
  }
  for (const ObligationSuspension& suspension : request.suspensions) {
    const ProtectedObligation* obligation = state.find_obligation(suspension.obligation);
    if (obligation == nullptr) {
      sink.add(ExplanationCode::obligation_unserved, SubjectKind::obligation,
               suspension.obligation.view(),
               "the suspension names an obligation this facility does not have");
      return DecisionOutcome::blocked_by_obligation;
    }
    if (obligation->state != ObligationState::active) {
      sink.add(ExplanationCode::obligation_unserved, SubjectKind::obligation,
               suspension.obligation.view(),
               "the suspension names an obligation that is not active");
      return DecisionOutcome::blocked_by_obligation;
    }
    if (suspension.record.authority.empty()) {
      sink.add(ExplanationCode::obligation_suspended_without_authority,
               SubjectKind::obligation, suspension.obligation.view(),
               "a suspension must name the external authority that permitted it");
      return DecisionOutcome::blocked_by_obligation;
    }
  }
  if (rule->requires_permission) {
    const PermissionStage permission =
        stage_permission(state, kind, facility_target.value(), sink);
    if (permission.result.blocked) {
      return permission.result.outcome;
    }
  }
  ActionIntent intent;
  const auto intent_id = ActionId::parse(std::string("mode-") + std::string(to_string(request.target)));
  if (!intent_id.has_value()) {
    return DecisionOutcome::unsupported;
  }
  intent.id = intent_id.value();
  intent.kind = kind;
  intent.target = facility_target.value();
  intent.planned = request.planned;
  stage = stage_policy(state, intent, sink);
  if (stage.blocked) {
    return stage.outcome;
  }
  sink.add(ExplanationCode::accepted, SubjectKind::mode, to_string(request.target),
           "the operating mode transition is authorized against the current generation, "
           "evidence binding, interlocks, obligations, permission, and policy");
  return DecisionOutcome::accepted;
}

}  // namespace

ControlPlane::~ControlPlane() = default;
ControlPlane::ControlPlane(ControlPlane&&) noexcept = default;
ControlPlane& ControlPlane::operator=(ControlPlane&&) noexcept = default;

Result<ControlPlane> ControlPlane::open(const std::string& root, StoreOpenMode mode,
                                        EngineOptions options) {
  StoreOptions store_options;
  store_options.limits = options.limits;
  store_options.retained_publications = options.retained_publications;
  store_options.commit_observer = options.commit_observer;
  auto store = DurableStore::open(root, mode, store_options);
  if (!store.has_value()) {
    return store.error();
  }
  ControlPlane plane;
  plane.store_ = std::move(store).value();
  plane.runtime_ = std::make_unique<Runtime>();
  // Recovery never makes persisted evidence fresh. EvidenceFreshness is runtime state and
  // starts false in every process incarnation.
  plane.set_freshness(EvidenceFreshness{});
  return plane;
}

bool ControlPlane::is_open() const noexcept { return runtime_ != nullptr; }
const std::string& ControlPlane::root() const noexcept { return store_.root(); }
StoreOpenMode ControlPlane::mode() const noexcept { return store_.mode(); }
const Limits& ControlPlane::limits() const noexcept { return store_.limits(); }
const DurableStore& ControlPlane::store() const noexcept { return store_; }

void ControlPlane::close() {
  if (runtime_ != nullptr) {
    set_freshness(EvidenceFreshness{});
  }
  store_.close();
}

EvidenceFreshness ControlPlane::read_freshness() const {
  if (runtime_ == nullptr) {
    return EvidenceFreshness{};
  }
  std::lock_guard<std::mutex> guard(runtime_->mutex);
  return runtime_->value;
}

void ControlPlane::set_freshness(const EvidenceFreshness& freshness) {
  if (runtime_ == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> guard(runtime_->mutex);
  runtime_->value = freshness;
}

Result<FacilitySnapshot> ControlPlane::current_snapshot() const {
  auto pointer = store_.state_pointer();
  if (!pointer) {
    return Error(ErrorCode::not_found,
                 "this store holds no authoritative facility control generation");
  }
  return FacilitySnapshot(std::move(pointer));
}

Result<FacilitySnapshot> ControlPlane::snapshot() const { return current_snapshot(); }

RevalidationReport ControlPlane::revalidation_status() const {
  RevalidationReport report;
  auto pointer = store_.state_pointer();
  const EvidenceFreshness freshness = runtime_ == nullptr ? EvidenceFreshness{} : read_freshness();
  if (pointer) {
    report.bound_digest = pointer->evidence().digest();
    report.bound_sources = pointer->evidence().size();
  }
  report.fresh_digest = freshness.digest;
  report.evidence_fresh = freshness.fresh && pointer != nullptr &&
                          freshness.digest == pointer->evidence().digest();
  report.revalidated_in_this_incarnation = freshness.fresh;
  report.revalidated_generation = freshness.revalidated_generation;
  report.revalidated_revision = freshness.revalidated_revision;
  if (!pointer) {
    report.detail = "the store holds no authoritative generation";
  } else if (report.evidence_fresh) {
    report.detail = "the bound evidence was revalidated in this process incarnation";
  } else if (freshness.fresh) {
    report.detail = "the revalidated evidence no longer matches the bound evidence";
  } else {
    report.detail =
        "the bound evidence has not been revalidated in this process incarnation; "
        "persisted evidence references are bindings, not freshness claims";
  }
  return report;
}

Result<ControlPlaneStatus> ControlPlane::status() const {
  ControlPlaneStatus status;
  auto pointer = store_.state_pointer();
  status.head = store_.head();
  status.open_report = store_.open_report();
  status.writer = store_.writer_status();
  status.revalidation = revalidation_status();
  if (!pointer) {
    return status;
  }
  const FacilityState& state = *pointer;
  status.authoritative_generation_present = state.has_authoritative_generation();
  status.facility = state.facility();
  status.incarnation = state.incarnation();
  status.generation = state.generation();
  status.revision = state.revision();
  status.policy_revision = state.policy_revision();
  status.tick = state.tick();
  status.mode = state.mode();
  status.evidence_digest = state.evidence().digest();
  status.state_digest = state.canonical_digest();
  status.interlock_count = state.interlocks().size();
  for (const Interlock& interlock : state.interlocks()) {
    if (interlock.state != InterlockState::cleared &&
        interlock.severity != InterlockSeverity::advisory) {
      ++status.blocking_interlock_count;
    }
  }
  status.obligation_count = state.obligations().size();
  for (const ProtectedObligation& obligation : state.obligations()) {
    if (obligation.continuity_required && obligation.state == ObligationState::active) {
      ++status.unserved_obligation_count;
    }
  }
  status.commitment_count = state.commitments().size();
  for (const PermissionGrant& grant : state.permissions()) {
    if (grant.state == PermissionState::active) {
      ++status.active_permission_count;
    }
  }
  status.attempt_count = state.attempts().size();
  for (const AttemptRecord& attempt : state.attempts()) {
    if (!attempt_is_terminal(attempt.state)) {
      ++status.open_attempt_count;
    }
  }
  return status;
}

Result<PolicyEvaluation> ControlPlane::evaluate_policy(const ActionIntent& intent) const {
  auto pointer = store_.state_pointer();
  if (!pointer) {
    return Error(ErrorCode::not_found,
                 "this store holds no authoritative facility control generation");
  }
  return evaluate_policy_rules(*pointer, intent);
}

Result<AuthorizationDecision> ControlPlane::evaluate_action(const ActionIntent& intent) const {
  const Limits& scope = limits();
  AuthorizationDecision decision;
  auto pointer = store_.state_pointer();
  if (!pointer) {
    decision.outcome = DecisionOutcome::invalid_request;
    StepSink{&scope, &decision.steps}.add(ExplanationCode::invalid_request,
                                          SubjectKind::action, intent.id.view(),
                                          "no authoritative facility control generation exists");
    return decision;
  }
  const FacilityState& state = *pointer;
  decision.authoritative_generation = state.generation();
  decision.authoritative_revision = state.revision();
  decision.policy_revision = state.policy_revision();
  decision.evidence_digest = state.evidence().digest();
  decision.planned_generation = intent.planned.generation;

  const Status structure = validate_intent_structure(intent, scope);
  if (!structure.ok()) {
    decision.outcome = DecisionOutcome::invalid_request;
    StepSink{&scope, &decision.steps}.add(ExplanationCode::invalid_request,
                                          SubjectKind::action, intent.id.view(),
                                          structure.error().message());
    return decision;
  }
  const EvidenceFreshness freshness = runtime_ == nullptr ? EvidenceFreshness{} : read_freshness();
  decision.outcome = evaluate_action_pipeline(state, intent, freshness, scope, decision.steps,
                                              nullptr);
  return decision;
}

Result<StoreIntegrityReport> ControlPlane::verify_store() const {
  return store_.verify_integrity();
}

Result<ReplayReport> ControlPlane::verify_replay() const {
  return store_.verify_deterministic_replay();
}

Result<WriterLease> ControlPlane::acquire_writer() { return store_.acquire_writer(); }

Status ControlPlane::release_writer(const WriterLease& lease) {
  return store_.release_writer(lease);
}

Status ControlPlane::ensure_writer(const WriterLease& lease) const {
  if (mode() != StoreOpenMode::read_write) {
    return Status::failure(ErrorCode::not_authoritative,
                           "the control plane was opened read-only and cannot mutate");
  }
  return store_.validate_writer(lease);
}

Result<AuthorizationDecision> ControlPlane::commit_record(
    const WriterLease& lease, const PlannedAgainst& planned, const IdempotencyKey& key,
    bool check_planned, bool require_fresh_evidence, TransitionRecord record,
    AttemptId resulting_attempt) {
  std::lock_guard<std::mutex> guard(runtime_->commit_mutex);
  return commit_record_locked(lease, planned, key, check_planned, require_fresh_evidence,
                              std::move(record), resulting_attempt);
}

Result<AuthorizationDecision> ControlPlane::commit_record_locked(
    const WriterLease& lease, const PlannedAgainst& planned, const IdempotencyKey& key,
    bool check_planned, bool require_fresh_evidence, TransitionRecord record,
    AttemptId resulting_attempt) {
  const Limits& scope = limits();
  AuthorizationDecision decision;
  const Status authority = ensure_writer(lease);
  if (!authority.ok()) {
    // A superseded controller epoch is a typed outcome with an explanation, not an
    // I/O error: the caller asked a well-formed question and the answer is that this
    // process is no longer the writer authority.
    decision.outcome = outcome_for_error(authority.error().code());
    StepSink{&scope, &decision.steps}.add(explanation_for_error(authority.error().code()),
                                          SubjectKind::mode, "",
                                          authority.error().message());
    return decision;
  }

  // A store that has never been bootstrapped has no authoritative state to read,
  // so the bootstrap transition starts from a vacant state carrying the store's own
  // facility identity and incarnation. Every other verb requires an authoritative
  // generation to exist.
  FacilityState vacant;
  const auto pointer = store_.state_pointer();
  if (!pointer) {
    if (record.kind != TransitionKind::facility_bootstrap) {
      decision.outcome = DecisionOutcome::invalid_request;
      StepSink{&scope, &decision.steps}.add(ExplanationCode::invalid_request,
                                            SubjectKind::mode, "",
                                            "no authoritative generation exists");
      return decision;
    }
    CanonicalReader bootstrap_reader(record.payload);
    auto bootstrap = decode_bootstrap_payload(bootstrap_reader, scope);
    if (!bootstrap.has_value()) {
      decision.outcome = DecisionOutcome::invalid_request;
      StepSink{&scope, &decision.steps}.add(ExplanationCode::invalid_request,
                                            SubjectKind::mode, "",
                                            bootstrap.error().message());
      return decision;
    }
    vacant = FacilityState::vacant(bootstrap.value().facility, bootstrap.value().incarnation);
  }
  const FacilityState& state = pointer ? *pointer : vacant;
  decision.authoritative_generation = state.generation();
  decision.authoritative_revision = state.revision();
  decision.policy_revision = state.policy_revision();
  decision.evidence_digest = state.evidence().digest();
  decision.planned_generation = planned.generation;
  decision.idempotency_key = key;
  const StepSink sink{&scope, &decision.steps};

  // Step 2 of the precedence chain: an already committed operation is returned
  // before any staleness check can reject it.
  if (!key.is_zero()) {
    const CommittedOperation* prior = state.find_operation(key);
    if (prior != nullptr) {
      decision.outcome = DecisionOutcome::replayed;
      if (!prior->attempt.is_zero()) {
        decision.attempt = prior->attempt;
      }
      sink.add(ExplanationCode::idempotent_replay, SubjectKind::attempt,
               std::to_string(prior->attempt.value()),
               "this idempotency key was already committed at revision " +
                   std::to_string(prior->revision.value()) +
                   "; the recorded result is returned unchanged");
      return decision;
    }
  }

  if (check_planned) {
    const StageOutcome planned_stage = stage_planned_against(state, planned, sink);
    if (planned_stage.blocked) {
      decision.outcome = planned_stage.outcome;
      return decision;
    }
    if (require_fresh_evidence) {
      const EvidenceFreshness freshness = runtime_ == nullptr ? EvidenceFreshness{} : read_freshness();
      const StageOutcome evidence_stage =
          stage_evidence(state, planned.evidence_digest, freshness, true, sink);
      if (evidence_stage.blocked) {
        decision.outcome = evidence_stage.outcome;
        return decision;
      }
    }
  }

  record.key = key;
  FacilityState candidate = state;
  const Status applied = apply_transition(candidate, record, scope);
  if (!applied.ok()) {
    decision.outcome = outcome_for_error(applied.error().code());
    sink.add(explanation_for_error(applied.error().code()), SubjectKind::mode, "",
             applied.error().message());
    return decision;
  }

  auto committed = store_.commit(lease, candidate, record);
  if (!committed.has_value()) {
    if (is_refusal(committed.error().code())) {
      // A refusal raised by the store is still a refusal with an explanation, not an
      // I/O failure: for example two mutations that raced to the same revision.
      decision.outcome = outcome_for_error(committed.error().code());
      sink.add(explanation_for_error(committed.error().code()), SubjectKind::mode, "",
               committed.error().message());
      return decision;
    }
    return committed.error();
  }

  decision.outcome = DecisionOutcome::accepted;
  decision.authoritative_generation = candidate.generation();
  decision.authoritative_revision = candidate.revision();
  decision.policy_revision = candidate.policy_revision();
  decision.evidence_digest = candidate.evidence().digest();
  if (!resulting_attempt.is_zero()) {
    decision.attempt = resulting_attempt;
  }
  sink.add(ExplanationCode::accepted, SubjectKind::mode, "",
           "transition " + std::string(to_string(record.kind)) + " published at revision " +
               std::to_string(candidate.revision().value()) + " generation " +
               std::to_string(candidate.generation().value()));
  return decision;
}

Result<AuthorizationDecision> ControlPlane::bootstrap(const WriterLease& lease,
                                                      const FacilityId& facility,
                                                      OperatingMode initial_mode,
                                                      const EvidenceBinding& evidence,
                                                      const IdempotencyKey& key) {
  const Limits& scope = limits();
  AuthorizationDecision decision;
  const Status authority = ensure_writer(lease);
  if (!authority.ok()) {
    decision.outcome = outcome_for_error(authority.error().code());
    StepSink{&scope, &decision.steps}.add(explanation_for_error(authority.error().code()),
                                          SubjectKind::mode, "",
                                          authority.error().message());
    return decision;
  }
  static_cast<void>(key);

  if (store_.head().present) {
    decision.outcome = DecisionOutcome::conflict;
    StepSink{&scope, &decision.steps}.add(
        ExplanationCode::mode_transition_refused, SubjectKind::mode, "",
        "this store already holds an authoritative generation");
    return decision;
  }

  BootstrapPayload payload;
  payload.facility = facility;
  payload.incarnation = store_.incarnation();
  payload.mode = initial_mode;
  payload.evidence = evidence;

  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_bootstrap_payload(writer, payload, scope));
  TransitionRecord record;
  record.kind = TransitionKind::facility_bootstrap;
  record.payload = writer.take();
  return commit_record(lease, PlannedAgainst{}, key, false, false, std::move(record),
                       AttemptId{});
}

Result<AuthorizationDecision> ControlPlane::bind_evidence(const WriterLease& lease,
                                                          const EvidenceBinding& evidence,
                                                          const MutationRequest& request) {
  CanonicalWriter writer;
  PCP_TRY_STATUS(evidence.encode(writer, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::evidence_rebound;
  record.payload = writer.take();
  auto decision =
      commit_record(lease, request.planned, request.key, true, false, std::move(record),
                    AttemptId{});
  if (decision.has_value() && decision_committed(decision.value().outcome)) {
    // Binding evidence does not declare it revalidated for control purposes, and
    // it invalidates whatever freshness the previous binding had. revalidate() is
    // the verb that re-establishes freshness.
    set_freshness(EvidenceFreshness{});
  }
  return decision;
}

Result<AuthorizationDecision> ControlPlane::revalidate(const WriterLease& lease,
                                                       const EvidenceBinding& evidence,
                                                       const MutationRequest& request) {
  CanonicalWriter writer;
  PCP_TRY_STATUS(evidence.encode(writer, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::evidence_rebound;
  record.payload = writer.take();
  auto decision =
      commit_record(lease, request.planned, request.key, true, false, std::move(record),
                    AttemptId{});
  if (!decision.has_value()) {
    return decision.error();
  }
  if (decision_committed(decision.value().outcome)) {
    auto pointer = store_.state_pointer();
    if (pointer) {
      EvidenceFreshness fresh;
      fresh.fresh = true;
      fresh.digest = pointer->evidence().digest();
      fresh.revalidated_generation = pointer->generation();
      fresh.revalidated_revision = pointer->revision();
      set_freshness(fresh);
    }
  }
  return decision;
}

Result<AuthorizationDecision> ControlPlane::rebind_policy(const WriterLease& lease,
                                                          const PowerPolicy& policy,
                                                          const MutationRequest& request) {
  CanonicalWriter writer;
  PCP_TRY_STATUS(policy.encode(writer, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::policy_rebound;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       AttemptId{});
}

Result<AuthorizationDecision> ControlPlane::record_interlock(const WriterLease& lease,
                                                             const Interlock& interlock,
                                                             const MutationRequest& request) {
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_interlock(writer, interlock, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::interlock_recorded;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       AttemptId{});
}

Result<AuthorizationDecision> ControlPlane::remove_interlock(const WriterLease& lease,
                                                             const InterlockId& id,
                                                             const MutationRequest& request) {
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_identity_payload(writer, id.view(), InterlockId::kMaxLength));
  TransitionRecord record;
  record.kind = TransitionKind::interlock_removed;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       AttemptId{});
}

Result<AuthorizationDecision> ControlPlane::record_obligation(
    const WriterLease& lease, const ProtectedObligation& obligation,
    const MutationRequest& request) {
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_obligation(writer, obligation, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::obligation_recorded;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       AttemptId{});
}

Result<AuthorizationDecision> ControlPlane::remove_obligation(const WriterLease& lease,
                                                              const ObligationId& id,
                                                              const MutationRequest& request) {
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_identity_payload(writer, id.view(), ObligationId::kMaxLength));
  TransitionRecord record;
  record.kind = TransitionKind::obligation_removed;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       AttemptId{});
}

Result<AuthorizationDecision> ControlPlane::record_commitment(
    const WriterLease& lease, const CapacityCommitment& commitment,
    const MutationRequest& request) {
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_commitment(writer, commitment, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::commitment_recorded;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       AttemptId{});
}

Result<AuthorizationDecision> ControlPlane::remove_commitment(
    const WriterLease& lease, const CapacityCommitmentId& id,
    const MutationRequest& request) {
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_identity_payload(writer, id.view(), CapacityCommitmentId::kMaxLength));
  TransitionRecord record;
  record.kind = TransitionKind::commitment_removed;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       AttemptId{});
}

Result<AuthorizationDecision> ControlPlane::grant_permission(const WriterLease& lease,
                                                             const PermissionGrant& grant,
                                                             const MutationRequest& request) {
  const Limits& scope = limits();
  auto pointer = store_.state_pointer();
  if (!pointer) {
    AuthorizationDecision decision;
    decision.outcome = DecisionOutcome::invalid_request;
    StepSink{&scope, &decision.steps}.add(ExplanationCode::invalid_request, SubjectKind::mode,
                                          "", "no authoritative generation exists");
    return decision;
  }
  PermissionGrant prepared = grant;
  prepared.id = pointer->next_permission_id();
  if (prepared.issued_generation.is_zero()) {
    prepared.issued_generation = pointer->generation();
  }
  if (prepared.issued_revision.is_zero()) {
    prepared.issued_revision = pointer->revision();
  }
  if (prepared.expiry_generation.is_zero()) {
    auto next = checked_increment(prepared.issued_generation.value());
    if (!next.has_value()) {
      return next.error();
    }
    prepared.expiry_generation = ControlGeneration(next.value());
  }
  if (prepared.expiry_revision.is_zero()) {
    auto next = checked_increment(prepared.issued_revision.value());
    if (!next.has_value()) {
      return next.error();
    }
    prepared.expiry_revision = StateRevision(next.value());
  }
  if (prepared.max_uses == 0) {
    prepared.max_uses = 1;
  }
  prepared.updated_revision = pointer->revision();
  if (prepared.evidence.empty()) {
    prepared.evidence = pointer->evidence();
  }
  if (prepared.policy_revision.is_zero()) {
    prepared.policy_revision = pointer->policy_revision();
  }
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_permission(writer, prepared, scope));
  TransitionRecord record;
  record.kind = TransitionKind::permission_granted;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       AttemptId{});
}

Result<AuthorizationDecision> ControlPlane::retire_permission(const WriterLease& lease,
                                                              const PermissionId& id,
                                                              PermissionState state,
                                                              const MutationRequest& request) {
  if (state == PermissionState::active) {
    AuthorizationDecision decision;
    decision.outcome = DecisionOutcome::invalid_request;
    StepSink{&limits(), &decision.steps}.add(
        ExplanationCode::invalid_request, SubjectKind::permission,
        std::to_string(id.value()),
        "retiring a permission cannot set it back to active");
    return decision;
  }
  PermissionRetirePayload payload;
  payload.id = id;
  payload.state = state;
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_permission_retire_payload(writer, payload, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::permission_retired;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       AttemptId{});
}

Result<AuthorizationDecision> ControlPlane::request_mode_transition(
    const WriterLease& lease, const ModeTransitionRequest& request) {
  const Limits& scope = limits();
  AuthorizationDecision decision;
  std::lock_guard<std::mutex> guard(runtime_->commit_mutex);
  auto pointer = store_.state_pointer();
  if (!pointer) {
    decision.outcome = DecisionOutcome::invalid_request;
    StepSink{&scope, &decision.steps}.add(ExplanationCode::invalid_request, SubjectKind::mode,
                                          "", "no authoritative generation exists");
    return decision;
  }
  const FacilityState& state = *pointer;
  decision.authoritative_generation = state.generation();
  decision.authoritative_revision = state.revision();
  decision.policy_revision = state.policy_revision();
  decision.evidence_digest = state.evidence().digest();
  decision.planned_generation = request.planned.generation;
  decision.idempotency_key = request.key;
  const Status authority = ensure_writer(lease);
  if (!authority.ok()) {
    decision.outcome = outcome_for_error(authority.error().code());
    StepSink{&scope, &decision.steps}.add(explanation_for_error(authority.error().code()),
                                          SubjectKind::mode, "",
                                          authority.error().message());
    return decision;
  }

  if (!request.key.is_zero()) {
    const CommittedOperation* prior = state.find_operation(request.key);
    if (prior != nullptr) {
      decision.outcome = DecisionOutcome::replayed;
      StepSink{&scope, &decision.steps}.add(
          ExplanationCode::idempotent_replay, SubjectKind::mode,
          std::to_string(prior->revision.value()),
          "this idempotency key was already committed; the recorded result is returned "
          "unchanged");
      return decision;
    }
  }

  const EvidenceFreshness freshness = runtime_ == nullptr ? EvidenceFreshness{} : read_freshness();
  const DecisionOutcome outcome = evaluate_mode_transition_pipeline(
      state, request, freshness, scope, decision.steps);
  decision.outcome = outcome;
  if (outcome != DecisionOutcome::accepted) {
    return decision;
  }

  ModeTransitionPayload payload;
  payload.from = state.mode();
  payload.to = request.target;
  payload.authority = request.authority;
  payload.suspensions = request.suspensions;
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_mode_transition_payload(writer, payload, scope));
  TransitionRecord record;
  record.kind = TransitionKind::mode_transition;
  record.payload = writer.take();
  auto committed = commit_record_locked(lease, request.planned, request.key, true, false,
                                        std::move(record), AttemptId{});
  if (!committed.has_value()) {
    return committed.error();
  }
  return committed.value();
}

Result<AuthorizationDecision> ControlPlane::authorize_action(const WriterLease& lease,
                                                             const ActionIntent& intent,
                                                             const MutationRequest& request) {
  const Limits& scope = limits();
  AuthorizationDecision decision;
  std::lock_guard<std::mutex> guard(runtime_->commit_mutex);
  auto pointer = store_.state_pointer();
  if (!pointer) {
    decision.outcome = DecisionOutcome::invalid_request;
    StepSink{&scope, &decision.steps}.add(ExplanationCode::invalid_request, SubjectKind::action,
                                          intent.id.view(),
                                          "no authoritative generation exists");
    return decision;
  }
  {
    const Status authority = ensure_writer(lease);
    if (!authority.ok()) {
      const FacilityState& current = *pointer;
      decision.authoritative_generation = current.generation();
      decision.authoritative_revision = current.revision();
      decision.policy_revision = current.policy_revision();
      decision.evidence_digest = current.evidence().digest();
      decision.planned_generation = intent.planned.generation;
      decision.idempotency_key = request.key;
      decision.outcome = outcome_for_error(authority.error().code());
      StepSink{&scope, &decision.steps}.add(explanation_for_error(authority.error().code()),
                                            SubjectKind::mode, "",
                                            authority.error().message());
      return decision;
    }
  }
  const FacilityState& state = *pointer;
  decision.authoritative_generation = state.generation();
  decision.authoritative_revision = state.revision();
  decision.policy_revision = state.policy_revision();
  decision.evidence_digest = state.evidence().digest();
  decision.planned_generation = intent.planned.generation;
  decision.idempotency_key = request.key;

  const Status structure = validate_intent_structure(intent, scope);
  if (!structure.ok()) {
    decision.outcome = DecisionOutcome::invalid_request;
    StepSink{&scope, &decision.steps}.add(ExplanationCode::invalid_request,
                                          SubjectKind::action, intent.id.view(),
                                          structure.error().message());
    return decision;
  }

  if (!request.key.is_zero()) {
    const CommittedOperation* prior = state.find_operation(request.key);
    if (prior != nullptr) {
      decision.outcome = DecisionOutcome::replayed;
      if (!prior->attempt.is_zero()) {
        decision.attempt = prior->attempt;
      }
      StepSink{&scope, &decision.steps}.add(
          ExplanationCode::idempotent_replay, SubjectKind::attempt,
          std::to_string(prior->attempt.value()),
          "this idempotency key was already committed at revision " +
              std::to_string(prior->revision.value()) +
              "; the recorded result is returned unchanged");
      return decision;
    }
  }

  const EvidenceFreshness freshness = runtime_ == nullptr ? EvidenceFreshness{} : read_freshness();
  PermissionId consumed;
  const DecisionOutcome outcome = evaluate_action_pipeline(
      state, intent, freshness, scope, decision.steps, &consumed);
  decision.outcome = outcome;
  if (outcome != DecisionOutcome::accepted) {
    return decision;
  }

  AttemptRecord attempt;
  attempt.id = state.next_attempt_id();
  attempt.key = request.key;
  attempt.intent = intent;
  CanonicalWriter writer;
  if (request.key.is_zero()) {
    // An action without an idempotency key cannot be replayed after a lost
    // response, so it is refused rather than silently made non-idempotent.
    decision.outcome = DecisionOutcome::invalid_request;
    StepSink{&scope, &decision.steps}.add(
        ExplanationCode::invalid_request, SubjectKind::action, intent.id.view(),
        "authorizing an action requires a non-zero idempotency key so that a retry of a "
        "lost response can be answered from the committed result");
    return decision;
  }
  AttemptAuthorizedPayload payload;
  payload.attempt = std::move(attempt);
  payload.permission = consumed;
  PCP_TRY_STATUS(encode_attempt_authorized_payload(writer, payload, scope));
  TransitionRecord record;
  record.kind = TransitionKind::attempt_authorized;
  record.payload = writer.take();
  auto committed = commit_record_locked(lease, intent.planned, request.key, true, false,
                                        std::move(record), payload.attempt.id);
  if (!committed.has_value()) {
    return committed.error();
  }
  return committed.value();
}

Result<AuthorizationDecision> ControlPlane::record_issued(const WriterLease& lease,
                                                          AttemptId attempt,
                                                          Digest command_digest_value,
                                                          std::string detail,
                                                          const MutationRequest& request) {
  AttemptTransitionPayload payload;
  payload.attempt = attempt;
  payload.event = AttemptEventKind::issued;
  payload.payload_digest = command_digest_value;
  payload.detail = std::move(detail);
  payload.resulting_state = AttemptState::issued;
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_attempt_transition_payload(writer, payload, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::attempt_issued;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       attempt);
}

Result<AuthorizationDecision> ControlPlane::record_acknowledgement(
    const WriterLease& lease, AttemptId attempt, const Acknowledgement& acknowledgement,
    const MutationRequest& request) {
  AttemptTransitionPayload payload;
  payload.attempt = attempt;
  payload.event = AttemptEventKind::acknowledged;
  payload.payload_digest = acknowledgement.command_digest;
  payload.detail = acknowledgement.detail;
  payload.resulting_state = AttemptState::acknowledged;
  payload.acknowledgement = acknowledgement;
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_attempt_transition_payload(writer, payload, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::attempt_acknowledged;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       attempt);
}

Result<AuthorizationDecision> ControlPlane::record_observed_effect(
    const WriterLease& lease, AttemptId attempt, const ObservedEffect& effect,
    const MutationRequest& request) {
  AttemptTransitionPayload payload;
  payload.attempt = attempt;
  payload.event = AttemptEventKind::effect_observed;
  payload.payload_digest = effect.observation_digest;
  payload.detail = effect.detail;
  payload.resulting_state = AttemptState::effect_observed;
  payload.effect = effect;
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_attempt_transition_payload(writer, payload, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::attempt_effect_observed;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       attempt);
}

Result<AuthorizationDecision> ControlPlane::record_effect_failure(
    const WriterLease& lease, AttemptId attempt, const ObservedEffect& effect,
    const MutationRequest& request) {
  AttemptTransitionPayload payload;
  payload.attempt = attempt;
  payload.event = AttemptEventKind::effect_failed;
  payload.payload_digest = effect.observation_digest;
  payload.detail = effect.detail;
  payload.resulting_state = AttemptState::effect_failed;
  payload.effect = effect;
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_attempt_transition_payload(writer, payload, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::attempt_effect_failed;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       attempt);
}

Result<AuthorizationDecision> ControlPlane::record_verification(
    const WriterLease& lease, AttemptId attempt, const VerificationReport& verification,
    const MutationRequest& request) {
  AttemptTransitionPayload payload;
  payload.attempt = attempt;
  payload.event = verification.matches_intent ? AttemptEventKind::verification_passed
                                              : AttemptEventKind::verification_failed;
  payload.payload_digest = verification.evidence_digest;
  payload.detail = verification.detail;
  payload.resulting_state = verification.matches_intent ? AttemptState::verified
                                                        : AttemptState::verification_failed;
  payload.verification = verification;
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_attempt_transition_payload(writer, payload, limits()));
  TransitionRecord record;
  record.kind = verification.matches_intent ? TransitionKind::attempt_verified
                                            : TransitionKind::attempt_verification_failed;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       attempt);
}

Result<AuthorizationDecision> ControlPlane::cancel_attempt(const WriterLease& lease,
                                                           AttemptId attempt,
                                                           const MutationRequest& request) {
  AttemptTransitionPayload payload;
  payload.attempt = attempt;
  payload.event = AttemptEventKind::cancelled;
  payload.resulting_state = AttemptState::cancelled;
  payload.detail = "cancelled by an operator";
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_attempt_transition_payload(writer, payload, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::attempt_cancelled;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       attempt);
}

Result<AuthorizationDecision> ControlPlane::supersede_attempt(const WriterLease& lease,
                                                              AttemptId attempt,
                                                              const MutationRequest& request) {
  AttemptTransitionPayload payload;
  payload.attempt = attempt;
  payload.event = AttemptEventKind::superseded;
  payload.resulting_state = AttemptState::superseded;
  payload.detail = "superseded by a newer authorized attempt";
  CanonicalWriter writer;
  PCP_TRY_STATUS(encode_attempt_transition_payload(writer, payload, limits()));
  TransitionRecord record;
  record.kind = TransitionKind::attempt_superseded;
  record.payload = writer.take();
  return commit_record(lease, request.planned, request.key, true, false, std::move(record),
                       attempt);
}

Result<AuthorizationDecision> ControlPlane::actuate(const WriterLease& lease,
                                                    const ActionIntent& intent,
                                                    const MutationRequest& request,
                                                    ActuationAdapter& adapter,
                                                    ActuationOutcome& actuation_outcome) {
  const Limits& scope = limits();
  actuation_outcome = ActuationOutcome{};
  auto authorization = authorize_action(lease, intent, request);
  if (!authorization.has_value()) {
    return authorization.error();
  }
  AuthorizationDecision decision = std::move(authorization).value();
  if (!decision_committed(decision.outcome)) {
    actuation_outcome.detail =
        "the action was refused, so no command was handed to any actuation adapter";
    return decision;
  }
  if (!decision.attempt.has_value()) {
    actuation_outcome.detail = "the authorization produced no attempt";
    return decision;
  }
  const AttemptId attempt = decision.attempt.value();
  actuation_outcome.attempt = attempt;
  if (decision.outcome == DecisionOutcome::replayed) {
    const AttemptRecord* record = nullptr;
    auto pointer = store_.state_pointer();
    if (pointer) {
      record = pointer->find_attempt(attempt);
    }
    actuation_outcome.final_state =
        record == nullptr ? AttemptState::authorized : record->state;
    actuation_outcome.detail =
        "this operation was already committed and replayed; the adapter was not invoked again";
    return decision;
  }
  if (!is_physical_action(intent.kind)) {
    actuation_outcome.final_state = AttemptState::authorized;
    actuation_outcome.detail =
        "evidence revalidation is a control-plane operation and never reaches an actuation "
        "adapter";
    return decision;
  }

  auto fresh_request = [&](std::string_view tag) -> Result<MutationRequest> {
    auto pointer = store_.state_pointer();
    if (!pointer) {
      return Error(ErrorCode::not_found, "no authoritative generation exists");
    }
    MutationRequest next;
    next.planned.generation = pointer->generation();
    next.planned.revision = pointer->revision();
    next.planned.policy_revision = pointer->policy_revision();
    next.planned.evidence_digest = pointer->evidence().digest();
    auto key = IdempotencyKey::derive(std::string(request.key.to_hex()) + std::string(tag));
    if (!key.has_value()) {
      return key.error();
    }
    next.key = key.value();
    return next;
  };

  IssuedCommand command;
  command.attempt = attempt;
  command.action = intent.id;
  command.kind = intent.kind;
  command.target = intent.target;
  command.generation = decision.authoritative_generation;
  command.revision = decision.authoritative_revision;
  command.command_digest = command_digest(command);
  static_cast<void>(scope);

  auto acknowledgement = adapter.issue(command);
  if (!acknowledgement.has_value()) {
    auto step_request = fresh_request("/effect-failed");
    if (!step_request.has_value()) {
      return step_request.error();
    }
    ObservedEffect failure;
    failure.adapter = adapter.id();
    failure.observation_digest =
        sha256_domain("pcp/adapter-refusal/v1", acknowledgement.error().message());
    failure.detail = acknowledgement.error().message();
    auto recorded = record_effect_failure(lease, attempt, failure, step_request.value());
    if (!recorded.has_value()) {
      return recorded.error();
    }
    actuation_outcome.final_state = AttemptState::effect_failed;
    actuation_outcome.detail =
        "the adapter did not hand the command to the equipment boundary: " +
        acknowledgement.error().message();
    decision.outcome = DecisionOutcome::accepted;
    return decision;
  }

  {
    auto step_request = fresh_request("/issued");
    if (!step_request.has_value()) {
      return step_request.error();
    }
    auto recorded = record_issued(lease, attempt, command.command_digest,
                                  "the command object was handed to the adapter",
                                  step_request.value());
    if (!recorded.has_value()) {
      return recorded.error();
    }
    actuation_outcome.command_issued = true;
  }
  {
    auto step_request = fresh_request("/acknowledged");
    if (!step_request.has_value()) {
      return step_request.error();
    }
    auto recorded =
        record_acknowledgement(lease, attempt, acknowledgement.value(), step_request.value());
    if (!recorded.has_value()) {
      return recorded.error();
    }
    actuation_outcome.acknowledged = true;
  }

  auto effect = adapter.observe(command);
  if (!effect.has_value()) {
    actuation_outcome.final_state = AttemptState::acknowledged;
    actuation_outcome.detail =
        "the command was acknowledged but no effect was observed: " +
        effect.error().message();
    return decision;
  }
  {
    auto step_request = fresh_request("/effect-observed");
    if (!step_request.has_value()) {
      return step_request.error();
    }
    auto recorded = record_observed_effect(lease, attempt, effect.value(), step_request.value());
    if (!recorded.has_value()) {
      return recorded.error();
    }
    actuation_outcome.effect_observed = true;
  }

  auto verification = adapter.verify(command, effect.value());
  {
    VerificationReport report;
    if (!verification.has_value()) {
      report.verifier = adapter.id();
      report.matches_intent = false;
      report.evidence_digest = effect.value().observation_digest;
      report.detail = verification.error().message();
    } else {
      report = verification.value();
    }
    auto step_request = fresh_request("/verified");
    if (!step_request.has_value()) {
      return step_request.error();
    }
    auto recorded = record_verification(lease, attempt, report, step_request.value());
    if (!recorded.has_value()) {
      return recorded.error();
    }
    actuation_outcome.verified = report.matches_intent;
    actuation_outcome.final_state =
        report.matches_intent ? AttemptState::verified : AttemptState::verification_failed;
    actuation_outcome.detail =
        report.matches_intent
            ? "an independent adapter verified the commanded state"
            : "the effect was observed but not verified as matching the intent: " +
                  report.detail;
  }
  return decision;
}

}  // namespace power_control_plane
