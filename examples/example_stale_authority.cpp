// Example: refusal paths.
//
// Demonstrates: a proposed operation refused by a safety interlock that no policy
// rule can override, a refused stale control generation, a refused stale writer
// epoch, an exhausted permission, and an idempotent retry of an accepted attempt
// that returns the committed result even though the generation has moved on.

#include <filesystem>
#include <iostream>
#include <string>

#include "example_support.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_examples;

int run(const std::string& root) {
  EngineOptions options;
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, options);
  if (!plane.has_value()) {
    return fail(plane.error().describe());
  }
  const Limits& limits = plane.value().limits();
  auto lease = plane.value().acquire_writer();
  if (!lease.has_value()) {
    return fail(lease.error().describe());
  }

  auto topology = make_evidence("power-topology", EvidenceKind::power_topology, 20, 1);
  if (!topology.has_value()) {
    return fail("evidence construction failed");
  }
  const auto facility = FacilityId::parse("dc1");
  auto boot_key = IdempotencyKey::derive("stale/bootstrap");
  auto booted = plane.value().bootstrap(lease.value(), facility.value(), OperatingMode::normal,
                                        topology.value(), boot_key.value());
  if (!booted.has_value()) {
    return fail(booted.error().describe());
  }

  auto policy = make_baseline_policy(PolicyRevision(1), limits);
  auto state = plane.value().snapshot();
  auto policy_request = make_request(state.value().state(), "stale/policy");
  if (!policy.has_value() || !policy_request.has_value()) {
    return fail("policy construction failed");
  }
  auto policy_decision =
      plane.value().rebind_policy(lease.value(), policy.value(), policy_request.value());
  if (!policy_decision.has_value()) {
    return fail(policy_decision.error().describe());
  }

  state = plane.value().snapshot();
  auto revalidate_request = make_request(state.value().state(), "stale/revalidate");
  auto revalidated = plane.value().revalidate(lease.value(), topology.value(),
                                              revalidate_request.value());
  if (!revalidated.has_value()) {
    return fail(revalidated.error().describe());
  }

  heading("permission");
  state = plane.value().snapshot();
  PermissionGrant grant;
  grant.kinds.push_back(ActionKind::open_breaker);
  grant.granted_by = AuthorityReference::parse("shift-supervisor").value();
  grant.max_uses = 1;
  grant.issued_generation = state.value().generation();
  grant.issued_revision = state.value().revision();
  grant.expiry_generation = ControlGeneration(state.value().generation().value() + 4);
  grant.expiry_revision = StateRevision(state.value().revision().value() + 64);
  grant.policy_revision = state.value().policy_revision();
  grant.evidence = state.value().evidence();
  auto grant_request = make_request(state.value().state(), "stale/permission");
  auto grant_decision =
      plane.value().grant_permission(lease.value(), grant, grant_request.value());
  if (!grant_decision.has_value()) {
    return fail(grant_decision.error().describe());
  }
  show_decision(limits, grant_decision.value());

  heading("authorized action, then a lost response");
  state = plane.value().snapshot();
  const ControlGeneration planned_generation = state.value().generation();
  const StateRevision planned_revision = state.value().revision();
  const ActionIntent intent = make_intent(state.value().state(), "open-breaker-b7",
                                          ActionKind::open_breaker, "bus-b");
  auto action_request = make_request(state.value().state(), "stale/open-breaker-b7");
  auto action_decision =
      plane.value().authorize_action(lease.value(), intent, action_request.value());
  if (!action_decision.has_value()) {
    return fail(action_decision.error().describe());
  }
  show_decision(limits, action_decision.value());
  if (!decision_committed(action_decision.value().outcome)) {
    return fail("the first authorization was expected to be accepted");
  }
  const AttemptId accepted_attempt = action_decision.value().attempt.value();

  heading("retry of the same idempotency key after the generation moved on");
  line("the retry is deliberately planned against the older authority the first "
       "attempt was planned against: generation " +
       std::to_string(planned_generation.value()) + " revision " +
       std::to_string(planned_revision.value()));
  ActionIntent stale_retry = intent;
  auto retry_decision =
      plane.value().authorize_action(lease.value(), stale_retry, action_request.value());
  if (!retry_decision.has_value()) {
    return fail(retry_decision.error().describe());
  }
  show_decision(limits, retry_decision.value());
  if (retry_decision.value().outcome != DecisionOutcome::replayed) {
    return fail("a retry of an accepted attempt must replay the committed result");
  }
  if (!retry_decision.value().attempt.has_value() ||
      !(retry_decision.value().attempt.value() == accepted_attempt)) {
    return fail("the replay did not return the committed attempt identity");
  }

  heading("the same action under a genuinely new key is now unauthorized");
  auto exhausted_request = make_request(state.value().state(), "stale/open-breaker-b7-again");
  stale_retry = intent;
  stale_retry.planned.generation = plane.value().snapshot().value().generation();
  stale_retry.planned.revision = plane.value().snapshot().value().revision();
  auto exhausted_decision =
      plane.value().authorize_action(lease.value(), stale_retry, exhausted_request.value());
  if (!exhausted_decision.has_value()) {
    return fail(exhausted_decision.error().describe());
  }
  show_decision(limits, exhausted_decision.value());
  if (exhausted_decision.value().outcome != DecisionOutcome::unauthorized) {
    return fail("a spent permission must not authorize a new operation");
  }

  heading("interlock refusal that no policy rule can override");
  state = plane.value().snapshot();
  Interlock interlock;
  interlock.id = InterlockId::parse("arc-flash-bus-b").value();
  interlock.source = EvidenceSourceId::parse("safety-system").value();
  interlock.severity = InterlockSeverity::critical;
  interlock.state = InterlockState::engaged;
  interlock.scope_kinds.push_back(ActionKind::close_breaker);
  interlock.scope_targets.push_back(ActionTargetId::parse("bus-b").value());
  interlock.explanation = "arc flash hazard window is open on bus-b";
  interlock.declared_generation = state.value().generation();
  auto interlock_request = make_request(state.value().state(), "stale/interlock");
  auto interlock_decision =
      plane.value().record_interlock(lease.value(), interlock, interlock_request.value());
  if (!interlock_decision.has_value()) {
    return fail(interlock_decision.error().describe());
  }
  show_decision(limits, interlock_decision.value());

  // A permissive policy is installed deliberately: authorizing the action is
  // allowed by policy, and the interlock still refuses it because interlocks are
  // evaluated before policy and cannot be outranked by a rule.
  std::vector<PolicyRule> permissive;
  PolicyRule allow_all;
  allow_all.id = RuleId::parse("allow-everything").value();
  allow_all.order = 0;
  allow_all.condition.kind = PolicyConditionKind::always;
  allow_all.effect = PolicyEffect::allow;
  allow_all.explanation = "deliberately permissive rule used to show interlock precedence";
  permissive.push_back(allow_all);
  auto permissive_policy = PowerPolicy::create(PolicyRevision(2), std::move(permissive), limits);
  state = plane.value().snapshot();
  auto permissive_request = make_request(state.value().state(), "stale/permissive-policy");
  auto permissive_decision = plane.value().rebind_policy(lease.value(), permissive_policy.value(),
                                                         permissive_request.value());
  if (!permissive_decision.has_value()) {
    return fail(permissive_decision.error().describe());
  }
  show_decision(limits, permissive_decision.value());

  state = plane.value().snapshot();
  auto blocked_request = make_request(state.value().state(), "stale/blocked-close");
  const ActionIntent blocked = make_intent(state.value().state(), "close-breaker-b2",
                                           ActionKind::close_breaker, "bus-b");
  auto blocked_decision =
      plane.value().authorize_action(lease.value(), blocked, blocked_request.value());
  if (!blocked_decision.has_value()) {
    return fail(blocked_decision.error().describe());
  }
  show_decision(limits, blocked_decision.value());
  if (blocked_decision.value().outcome != DecisionOutcome::blocked_by_interlock) {
    return fail("the interlock must refuse the action even under a permissive policy");
  }

  heading("stale writer epoch");
  auto second = plane.value().acquire_writer();
  if (!second.has_value()) {
    return fail(second.error().describe());
  }
  line("a second acquire returned the existing lease at epoch " +
       std::to_string(second.value().epoch().value()));
  const Status released = plane.value().release_writer(lease.value());
  if (!released.ok()) {
    return fail(released.error().describe());
  }
  auto third = plane.value().acquire_writer();
  if (!third.has_value()) {
    return fail(third.error().describe());
  }
  line("after release, a successor took authority at epoch " +
       std::to_string(third.value().epoch().value()));
  state = plane.value().snapshot();
  auto stale_authority_request = make_request(state.value().state(), "stale/old-lease");
  auto stale_authority_decision = plane.value().record_interlock(
      lease.value(), interlock, stale_authority_request.value());
  if (!stale_authority_decision.has_value()) {
    return fail(stale_authority_decision.error().describe());
  }
  show_decision(limits, stale_authority_decision.value());
  if (stale_authority_decision.value().outcome != DecisionOutcome::stale_authority) {
    return fail("a superseded writer authority must not be able to publish");
  }

  heading("stale control generation");
  state = plane.value().snapshot();
  ActionIntent stale_plan = make_intent(state.value().state(), "open-breaker-c3",
                                        ActionKind::open_breaker, "bus-c");
  stale_plan.planned.revision =
      StateRevision(state.value().revision().value() > 0
                        ? state.value().revision().value() - 1
                        : 0);
  auto stale_plan_request = make_request(state.value().state(), "stale/stale-generation");
  auto stale_plan_decision =
      plane.value().authorize_action(third.value(), stale_plan, stale_plan_request.value());
  if (!stale_plan_decision.has_value()) {
    return fail(stale_plan_decision.error().describe());
  }
  show_decision(limits, stale_plan_decision.value());
  if (stale_plan_decision.value().outcome != DecisionOutcome::stale_generation) {
    return fail("a request planned against an older revision must be refused as stale");
  }

  heading("verify");
  auto integrity = plane.value().verify_store();
  auto replay = plane.value().verify_replay();
  if (!integrity.has_value() || !replay.has_value()) {
    return fail("verification could not run");
  }
  line("store integrity ok: " + std::string(integrity.value().ok ? "yes" : "no"));
  line("deterministic replay ok: " + std::string(replay.value().ok ? "yes" : "no") +
       " steps=" + std::to_string(replay.value().steps_checked));
  static_cast<void>(plane.value().release_writer(third.value()));
  plane.value().close();
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  const std::string root = argc > 1 ? argv[1] : "example-stale-authority-store";
  std::error_code error;
  std::filesystem::remove_all(root, error);
  const int code = run(root);
  std::filesystem::remove_all(root, error);
  return code;
}
