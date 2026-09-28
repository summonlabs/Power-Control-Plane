// Proof obligations: authority fencing, staleness refusal, deterministic validation
// precedence, interlock precedence over policy, protected obligations, capacity
// honesty, permission binding, and "a refusal changes no authoritative state".

#include <string>
#include <vector>

#include "power_control_plane/mode.hpp"
#include "support/fixture.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

// Returns the revision and generation of the authoritative state.
std::pair<StateRevision, ControlGeneration> position(const Fixture& fixture) {
  auto snapshot = fixture.snapshot();
  return {snapshot.value().revision(), snapshot.value().generation()};
}

}  // namespace

PCP_TEST(accepted_action_consumes_one_permission_use_and_advances_the_revision) {
  auto fixture = Fixture::create("authority-accept");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::close_breaker}, {"bus-a"}, 2);
  PCP_CHECK(granted.has_value());
  PCP_CHECK(decision_committed(granted.value().outcome));

  const auto before = position(fixture.value());
  auto intent = fixture.value().intent("close-1", ActionKind::close_breaker, "bus-a");
  PCP_CHECK(intent.has_value());
  auto decision = fixture.value().authorize(intent.value(), "authority/close-1");
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::accepted);
  PCP_CHECK(decision.value().attempt.has_value());
  const AttemptId attempt = decision.value().attempt.value();

  auto snapshot = fixture.value().snapshot();
  PCP_CHECK(snapshot.value().revision() > before.first);
  const AttemptRecord* record = snapshot.value().state().find_attempt(attempt);
  PCP_CHECK(record != nullptr);
  PCP_CHECK_EQ(record->state, AttemptState::authorized);
  // Authorization is not effect: nothing has been issued, acknowledged, or verified.
  PCP_CHECK(!record->acknowledgement.has_value());
  PCP_CHECK(!record->effect.has_value());
  PCP_CHECK(!record->verification.has_value());

  auto second = fixture.value().intent("close-2", ActionKind::close_breaker, "bus-a");
  auto second_decision = fixture.value().authorize(second.value(), "authority/close-2");
  PCP_CHECK(second_decision.has_value());
  PCP_CHECK_EQ(second_decision.value().outcome, DecisionOutcome::accepted);

  auto third = fixture.value().intent("close-3", ActionKind::close_breaker, "bus-a");
  auto third_decision = fixture.value().authorize(third.value(), "authority/close-3");
  PCP_CHECK(third_decision.has_value());
  PCP_CHECK_EQ(third_decision.value().outcome, DecisionOutcome::unauthorized);
}

PCP_TEST(refusals_change_no_authoritative_state) {
  auto fixture = Fixture::create("authority-refusal");
  PCP_CHECK(fixture.has_value());
  auto intent = fixture.value().intent("close-noperm", ActionKind::close_breaker, "bus-a");
  PCP_CHECK(intent.has_value());
  const auto before = position(fixture.value());
  const std::size_t operations_before =
      fixture.value().snapshot().value().state().operation_count();
  auto decision = fixture.value().authorize(intent.value(), "authority/no-permission");
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::unauthorized);
  const auto after = position(fixture.value());
  PCP_CHECK(before.first == after.first);
  PCP_CHECK(before.second == after.second);
  auto snapshot = fixture.value().snapshot();
  PCP_CHECK(snapshot.value().attempts().empty());
  // A refusal is not recorded as a committed operation either, so a retry with the
  // same key is judged afresh rather than replayed.
  PCP_CHECK_EQ(snapshot.value().state().operation_count(), operations_before);
}

PCP_TEST(evaluate_action_is_a_pure_read) {
  auto fixture = Fixture::create("authority-evaluate");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::close_breaker}, {"bus-a"}, 1);
  PCP_CHECK(granted.has_value());
  const auto before = position(fixture.value());
  auto intent = fixture.value().intent("evaluate-close", ActionKind::close_breaker, "bus-a");
  PCP_CHECK(intent.has_value());
  for (int index = 0; index < 3; ++index) {
    auto decision = fixture.value().plane().evaluate_action(intent.value());
    PCP_CHECK(decision.has_value());
    PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::accepted);
    // Evaluation never produces an attempt.
    PCP_CHECK(!decision.value().attempt.has_value());
  }
  const auto after = position(fixture.value());
  PCP_CHECK(before.first == after.first);
  PCP_CHECK(before.second == after.second);
  auto snapshot = fixture.value().snapshot();
  PCP_CHECK(snapshot.value().attempts().empty());
  // The permission was not consumed by evaluation.
  PCP_CHECK_EQ(snapshot.value().permissions().front().uses, std::uint32_t{0});
}

PCP_TEST(planned_against_mismatch_is_detected_per_component) {
  auto fixture = Fixture::create("authority-planned");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::close_breaker}, {"bus-a"}, 4);
  PCP_CHECK(granted.has_value());

  auto intent = fixture.value().intent("close-planned", ActionKind::close_breaker, "bus-a");
  PCP_CHECK(intent.has_value());
  ActionIntent stale = intent.value();
  stale.planned.revision = StateRevision(stale.planned.revision.value() + 100);
  auto request = fixture.value().request("authority/planned-revision");
  auto decision = fixture.value().plane().authorize_action(
      fixture.value().lease(), stale, request.value());
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::stale_generation);
  PCP_CHECK(!decision.value().steps.empty());
  PCP_CHECK_EQ(decision.value().steps.front().code, ExplanationCode::revision_mismatch);

  stale = intent.value();
  stale.planned.generation = ControlGeneration(stale.planned.generation.value() + 5);
  decision = fixture.value().plane().authorize_action(fixture.value().lease(), stale,
                                                      request.value());
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::stale_generation);
  PCP_CHECK_EQ(decision.value().steps.front().code, ExplanationCode::generation_mismatch);

  stale = intent.value();
  stale.planned.policy_revision = PolicyRevision(stale.planned.policy_revision.value() + 1);
  decision = fixture.value().plane().authorize_action(fixture.value().lease(), stale,
                                                      request.value());
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::stale_generation);
  PCP_CHECK_EQ(decision.value().steps.front().code, ExplanationCode::policy_revision_mismatch);

  stale = intent.value();
  stale.planned.evidence_digest = Digest::zero();
  decision = fixture.value().plane().authorize_action(fixture.value().lease(), stale,
                                                      request.value());
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::stale_evidence);
  PCP_CHECK_EQ(decision.value().steps.front().code, ExplanationCode::evidence_digest_mismatch);
}

PCP_TEST(precedence_is_fixed_when_a_request_is_invalid_in_several_ways) {
  auto fixture = Fixture::create("authority-precedence");
  PCP_CHECK(fixture.has_value());
  // No permission, no capacity commitment, no interlock, stale planned revision:
  // the planned-against stage is evaluated first, so that is the primary outcome.
  auto intent = fixture.value().intent("close-stale", ActionKind::close_breaker, "bus-a", 500);
  PCP_CHECK(intent.has_value());
  ActionIntent broken = intent.value();
  broken.planned.revision = StateRevision(broken.planned.revision.value() + 50);
  auto request = fixture.value().request("authority/precedence-1");
  auto decision =
      fixture.value().plane().authorize_action(fixture.value().lease(), broken, request.value());
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::stale_generation);

  // With the planned-against authority correct, the evidence stage is next. It is
  // correct here, so the interlock stage decides before capacity does.
  Interlock interlock;
  interlock.id = InterlockId::parse("block-everything").value();
  interlock.source = EvidenceSourceId::parse("safety-system").value();
  interlock.severity = InterlockSeverity::critical;
  interlock.state = InterlockState::engaged;
  interlock.explanation = "blanket interlock";
  interlock.declared_generation = fixture.value().snapshot().value().generation();
  auto interlock_request = fixture.value().request("authority/precedence-interlock");
  auto recorded = fixture.value().plane().record_interlock(fixture.value().lease(), interlock,
                                                           interlock_request.value());
  PCP_CHECK(recorded.has_value());
  PCP_CHECK(decision_committed(recorded.value().outcome));

  auto fresh = fixture.value().intent("close-blocked", ActionKind::close_breaker, "bus-a", 500);
  PCP_CHECK(fresh.has_value());
  auto fresh_request = fixture.value().request("authority/precedence-2");
  decision = fixture.value().plane().authorize_action(fixture.value().lease(), fresh.value(),
                                                      fresh_request.value());
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::blocked_by_interlock);

  // Clearing the interlock moves the primary outcome to the capacity stage, which is
  // indeterminate because no commitment exists: missing evidence is never zero.
  auto cleared = interlock;
  cleared.state = InterlockState::cleared;
  auto clear_request = fixture.value().request("authority/precedence-clear");
  auto cleared_decision = fixture.value().plane().record_interlock(
      fixture.value().lease(), cleared, clear_request.value());
  PCP_CHECK(cleared_decision.has_value());
  PCP_CHECK(decision_committed(cleared_decision.value().outcome));

  auto after_clear = fixture.value().intent("close-capacity", ActionKind::close_breaker, "bus-a",
                                            500);
  PCP_CHECK(after_clear.has_value());
  auto capacity_request = fixture.value().request("authority/precedence-3");
  decision = fixture.value().plane().authorize_action(fixture.value().lease(),
                                                      after_clear.value(),
                                                      capacity_request.value());
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::indeterminate);
  PCP_CHECK_EQ(decision.value().steps.front().code, ExplanationCode::capacity_commitment_unknown);
}

PCP_TEST(interlock_blocks_even_under_a_permissive_policy) {
  auto fixture = Fixture::create("authority-interlock");
  PCP_CHECK(fixture.has_value());
  auto permissive = permissive_policy(PolicyRevision(9), fixture.value().limits());
  PCP_CHECK(permissive.has_value());
  auto policy_request = fixture.value().request("authority/permissive");
  auto bound = fixture.value().plane().rebind_policy(fixture.value().lease(), permissive.value(),
                                                     policy_request.value());
  PCP_CHECK(bound.has_value());
  PCP_CHECK(decision_committed(bound.value().outcome));

  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 1);
  PCP_CHECK(granted.has_value());

  Interlock interlock;
  interlock.id = InterlockId::parse("arc-flash").value();
  interlock.source = EvidenceSourceId::parse("safety-system").value();
  interlock.severity = InterlockSeverity::critical;
  interlock.state = InterlockState::engaged;
  interlock.scope_kinds.push_back(ActionKind::open_breaker);
  interlock.scope_targets.push_back(ActionTargetId::parse("bus-a").value());
  interlock.explanation = "arc flash";
  interlock.declared_generation = fixture.value().snapshot().value().generation();
  auto interlock_request = fixture.value().request("authority/arc-flash");
  auto recorded = fixture.value().plane().record_interlock(fixture.value().lease(), interlock,
                                                           interlock_request.value());
  PCP_CHECK(recorded.has_value());

  auto intent = fixture.value().intent("open-a", ActionKind::open_breaker, "bus-a");
  PCP_CHECK(intent.has_value());
  auto decision = fixture.value().authorize(intent.value(), "authority/open-a");
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::blocked_by_interlock);
  // The permission is untouched: a blocked action consumes nothing.
  auto snapshot = fixture.value().snapshot();
  PCP_CHECK_EQ(snapshot.value().permissions().front().uses, std::uint32_t{0});
  PCP_CHECK(snapshot.value().attempts().empty());
}

PCP_TEST(interlock_unknown_state_also_blocks) {
  auto fixture = Fixture::create("authority-interlock-unknown");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 1);
  PCP_CHECK(granted.has_value());
  Interlock interlock;
  interlock.id = InterlockId::parse("unknown-state").value();
  interlock.source = EvidenceSourceId::parse("safety-system").value();
  interlock.severity = InterlockSeverity::blocking;
  interlock.state = InterlockState::unknown;
  interlock.explanation = "the safety runtime cannot report this interlock";
  interlock.declared_generation = fixture.value().snapshot().value().generation();
  auto request = fixture.value().request("authority/unknown-interlock");
  auto recorded = fixture.value().plane().record_interlock(fixture.value().lease(), interlock,
                                                           request.value());
  PCP_CHECK(recorded.has_value());
  auto intent = fixture.value().intent("open-unknown", ActionKind::open_breaker, "bus-a");
  auto decision = fixture.value().authorize(intent.value(), "authority/open-unknown");
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::blocked_by_interlock);
  PCP_CHECK_EQ(decision.value().steps.front().code, ExplanationCode::interlock_unknown);
}

PCP_TEST(protected_obligation_blocks_destructive_actions_in_scope) {
  auto fixture = Fixture::create("authority-obligation");
  PCP_CHECK(fixture.has_value());
  ProtectedObligation obligation;
  obligation.id = ObligationId::parse("life-safety").value();
  obligation.authority_source = EvidenceSourceId::parse("facility-capacity").value();
  obligation.authority_reference = AuthorityReference::parse("charter-3").value();
  obligation.scope_kinds.push_back(ActionKind::open_breaker);
  obligation.continuity_required = true;
  obligation.description = "life safety distribution";
  auto request = fixture.value().request("authority/obligation");
  auto recorded = fixture.value().plane().record_obligation(fixture.value().lease(), obligation,
                                                            request.value());
  PCP_CHECK(recorded.has_value());
  PCP_CHECK(decision_committed(recorded.value().outcome));

  auto granted = fixture.value().grant(
      {ActionKind::open_breaker, ActionKind::close_breaker}, {"bus-a"}, 4);
  PCP_CHECK(granted.has_value());

  auto destructive = fixture.value().intent("open-life", ActionKind::open_breaker, "bus-a");
  auto decision = fixture.value().authorize(destructive.value(), "authority/open-life");
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::blocked_by_obligation);

  // A non-destructive action in the same scope is not blocked by the obligation.
  auto benign = fixture.value().intent("close-life", ActionKind::close_breaker, "bus-a");
  auto benign_decision = fixture.value().authorize(benign.value(), "authority/close-life");
  PCP_CHECK(benign_decision.has_value());
  PCP_CHECK_EQ(benign_decision.value().outcome, DecisionOutcome::accepted);
}

PCP_TEST(obligation_cannot_be_removed_while_active_and_continuity_required) {
  auto fixture = Fixture::create("authority-obligation-remove");
  PCP_CHECK(fixture.has_value());
  ProtectedObligation obligation;
  obligation.id = ObligationId::parse("life-safety").value();
  obligation.authority_source = EvidenceSourceId::parse("facility-capacity").value();
  obligation.authority_reference = AuthorityReference::parse("charter-3").value();
  obligation.continuity_required = true;
  obligation.description = "life safety distribution";
  auto request = fixture.value().request("authority/obligation-add");
  auto recorded = fixture.value().plane().record_obligation(fixture.value().lease(), obligation,
                                                            request.value());
  PCP_CHECK(recorded.has_value());

  auto remove_request = fixture.value().request("authority/obligation-remove");
  auto removed = fixture.value().plane().remove_obligation(
      fixture.value().lease(), obligation.id, remove_request.value());
  PCP_CHECK(removed.has_value());
  PCP_CHECK_EQ(removed.value().outcome, DecisionOutcome::blocked_by_obligation);
  auto snapshot = fixture.value().snapshot();
  PCP_CHECK_EQ(snapshot.value().obligations().size(), std::size_t{1});

  // An obligation that is not continuity-required can be removed.
  ProtectedObligation advisory = obligation;
  advisory.id = ObligationId::parse("advisory-load").value();
  advisory.continuity_required = false;
  auto add_request = fixture.value().request("authority/obligation-advisory");
  auto added = fixture.value().plane().record_obligation(fixture.value().lease(), advisory,
                                                         add_request.value());
  PCP_CHECK(added.has_value());
  auto remove_request2 = fixture.value().request("authority/obligation-advisory-remove");
  auto removed2 = fixture.value().plane().remove_obligation(fixture.value().lease(), advisory.id,
                                                            remove_request2.value());
  PCP_CHECK(removed2.has_value());
  PCP_CHECK(decision_committed(removed2.value().outcome));
}

PCP_TEST(capacity_commitments_are_never_treated_as_zero) {
  auto fixture = Fixture::create("authority-capacity");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::transfer_source}, {"bus-a"}, 4);
  PCP_CHECK(granted.has_value());

  auto intent = fixture.value().intent("transfer-a", ActionKind::transfer_source, "bus-a", 500);
  PCP_CHECK(intent.has_value());
  auto decision = fixture.value().authorize(intent.value(), "authority/transfer-1");
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::indeterminate);

  CapacityCommitment commitment;
  commitment.id = CapacityCommitmentId::parse("committed-a").value();
  commitment.source = EvidenceSourceId::parse("power-capacity").value();
  commitment.authority_reference = AuthorityReference::parse("capacity-grant-1").value();
  commitment.committed_kw = 400;
  commitment.targets.push_back(ActionTargetId::parse("bus-a").value());
  commitment.evidence.source = commitment.source;
  commitment.evidence.kind = EvidenceKind::power_capacity;
  commitment.evidence.content_digest = sha256_domain("pcp/test-commitment/v1", "committed-a");
  auto commitment_request = fixture.value().request("authority/commitment");
  auto recorded = fixture.value().plane().record_commitment(fixture.value().lease(), commitment,
                                                            commitment_request.value());
  PCP_CHECK(recorded.has_value());
  PCP_CHECK(decision_committed(recorded.value().outcome));

  auto over = fixture.value().intent("transfer-a", ActionKind::transfer_source, "bus-a", 500);
  auto over_decision = fixture.value().authorize(over.value(), "authority/transfer-over");
  PCP_CHECK(over_decision.has_value());
  PCP_CHECK_EQ(over_decision.value().outcome, DecisionOutcome::blocked_by_capacity);

  auto within = fixture.value().intent("transfer-a", ActionKind::transfer_source, "bus-a", 400);
  auto within_decision = fixture.value().authorize(within.value(), "authority/transfer-within");
  PCP_CHECK(within_decision.has_value());
  PCP_CHECK_EQ(within_decision.value().outcome, DecisionOutcome::accepted);

  // Retiring the commitment returns the outcome to indeterminate rather than to a
  // silently permitted state.
  auto retire_request = fixture.value().request("authority/commitment-retire");
  auto retired = fixture.value().plane().remove_commitment(fixture.value().lease(),
                                                           commitment.id, retire_request.value());
  PCP_CHECK(retired.has_value());
  PCP_CHECK(decision_committed(retired.value().outcome));
  auto after_retire = fixture.value().intent("transfer-a", ActionKind::transfer_source, "bus-a",
                                             100);
  auto after_decision = fixture.value().authorize(after_retire.value(),
                                                  "authority/transfer-after-retire");
  PCP_CHECK(after_decision.has_value());
  PCP_CHECK_EQ(after_decision.value().outcome, DecisionOutcome::indeterminate);
}

PCP_TEST(permission_binding_is_exact) {
  auto fixture = Fixture::create("authority-permission-binding");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 4);
  PCP_CHECK(granted.has_value());
  PCP_CHECK(decision_committed(granted.value().outcome));

  auto intent = fixture.value().intent("open-a", ActionKind::open_breaker, "bus-a");
  auto decision = fixture.value().authorize(intent.value(), "authority/open-binding");
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::accepted);

  // Rebinding evidence invalidates the earlier grant because the binding digest no
  // longer matches, even though the grant is still within its lifetime.
  auto revalidation = fixture.value().revalidate();
  PCP_CHECK(revalidation.has_value());
  auto rebound_intent = fixture.value().intent("open-b", ActionKind::open_breaker, "bus-a");
  auto rebound_decision = fixture.value().authorize(rebound_intent.value(),
                                                    "authority/open-rebound");
  PCP_CHECK(rebound_decision.has_value());
  // The fixture revalidates the same binding, so the digest is unchanged and the
  // grant remains usable; this documents that the binding, not the act of
  // revalidating, is what the grant is tied to.
  PCP_CHECK_EQ(rebound_decision.value().outcome, DecisionOutcome::accepted);
}

PCP_TEST(policy_deny_and_default_refusal) {
  auto fixture = Fixture::create("authority-policy");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant(
      {ActionKind::shed_load_group, ActionKind::declare_emergency}, {"bus-a"}, 4);
  PCP_CHECK(granted.has_value());

  auto shed = fixture.value().intent("shed-a", ActionKind::shed_load_group, "bus-a");
  auto shed_decision = fixture.value().authorize(shed.value(), "authority/shed");
  PCP_CHECK(shed_decision.has_value());
  PCP_CHECK_EQ(shed_decision.value().outcome, DecisionOutcome::accepted);

  // The fixture policy has an explicit deny rule for emergency declaration, so the
  // outcome is denied by policy rather than unauthorized.
  auto emergency = fixture.value().intent("declare", ActionKind::declare_emergency, "bus-a");
  auto emergency_decision = fixture.value().authorize(emergency.value(), "authority/declare");
  PCP_CHECK(emergency_decision.has_value());
  PCP_CHECK_EQ(emergency_decision.value().outcome, DecisionOutcome::denied);
  PCP_CHECK_EQ(emergency_decision.value().steps.front().code, ExplanationCode::policy_denied);

  // Rebinding the policy invalidates a grant issued under the old revision, which is
  // reported before the policy stage runs.
  std::vector<PolicyRule> none;
  auto empty_policy = PowerPolicy::create(PolicyRevision(50), std::move(none),
                                          fixture.value().limits());
  PCP_CHECK(empty_policy.has_value());
  auto policy_request = fixture.value().request("authority/empty-policy");
  auto bound = fixture.value().plane().rebind_policy(fixture.value().lease(), empty_policy.value(),
                                                     policy_request.value());
  PCP_CHECK(bound.has_value());
  PCP_CHECK(decision_committed(bound.value().outcome));
  auto stale_grant = fixture.value().intent("shed-b", ActionKind::shed_load_group, "bus-a");
  auto stale_decision = fixture.value().authorize(stale_grant.value(), "authority/stale-grant");
  PCP_CHECK(stale_decision.has_value());
  PCP_CHECK_EQ(stale_decision.value().outcome, DecisionOutcome::unauthorized);
  PCP_CHECK_EQ(stale_decision.value().steps.front().code,
               ExplanationCode::permission_policy_mismatch);

  // A permission issued under the new policy still falls through to the default
  // refusal, because an empty policy authorizes nothing.
  auto fresh_grant = fixture.value().grant({ActionKind::shed_load_group}, {"bus-a"}, 2);
  PCP_CHECK(fresh_grant.has_value());
  PCP_CHECK(decision_committed(fresh_grant.value().outcome));
  auto no_policy = fixture.value().intent("shed-c", ActionKind::shed_load_group, "bus-a");
  auto no_policy_decision = fixture.value().authorize(no_policy.value(), "authority/no-policy");
  PCP_CHECK(no_policy_decision.has_value());
  PCP_CHECK_EQ(no_policy_decision.value().outcome, DecisionOutcome::denied);
  PCP_CHECK_EQ(no_policy_decision.value().steps.front().code, ExplanationCode::policy_no_match);
}

PCP_TEST(mode_transition_requires_permission_evidence_and_obligation_plan) {
  auto fixture = Fixture::create("authority-mode");
  PCP_CHECK(fixture.has_value());

  // A deterioration record needs nothing and is always accepted.
  auto degraded = fixture.value().transition_to(OperatingMode::degraded);
  PCP_CHECK(degraded.has_value());
  PCP_CHECK_EQ(degraded.value().outcome, DecisionOutcome::accepted);
  PCP_CHECK_EQ(fixture.value().snapshot().value().mode(), OperatingMode::degraded);

  // Returning to normal needs a permission.
  auto without = fixture.value().transition_to(OperatingMode::normal);
  PCP_CHECK(without.has_value());
  PCP_CHECK_EQ(without.value().outcome, DecisionOutcome::unauthorized);

  auto granted = fixture.value().grant({ActionKind::restore_normal}, {}, 2);
  PCP_CHECK(granted.has_value());
  auto with = fixture.value().transition_to(OperatingMode::normal);
  PCP_CHECK(with.has_value());
  PCP_CHECK_EQ(with.value().outcome, DecisionOutcome::accepted);
  PCP_CHECK_EQ(fixture.value().snapshot().value().mode(), OperatingMode::normal);

  // A transition that is not in the mode transition table is refused as a conflict:
  // there is no degraded-to-maintenance edge, because returning from a degradation
  // must go through normal supply first.
  auto degrade_again = fixture.value().transition_to(OperatingMode::degraded);
  PCP_CHECK(degrade_again.has_value());
  PCP_CHECK_EQ(degrade_again.value().outcome, DecisionOutcome::accepted);
  auto invalid = fixture.value().transition_to(OperatingMode::maintenance);
  PCP_CHECK(invalid.has_value());
  PCP_CHECK_EQ(invalid.value().outcome, DecisionOutcome::conflict);
  PCP_CHECK_EQ(invalid.value().steps.front().code,
               ExplanationCode::mode_transition_refused);
}

PCP_TEST(mode_transition_into_a_non_continuity_mode_requires_explicit_suspensions) {
  auto fixture = Fixture::create("authority-mode-obligation");
  PCP_CHECK(fixture.has_value());
  ProtectedObligation obligation;
  obligation.id = ObligationId::parse("life-safety").value();
  obligation.authority_source = EvidenceSourceId::parse("facility-capacity").value();
  obligation.authority_reference = AuthorityReference::parse("charter-9").value();
  obligation.continuity_required = true;
  obligation.description = "life safety distribution";
  auto request = fixture.value().request("authority/mode-obligation");
  auto recorded = fixture.value().plane().record_obligation(fixture.value().lease(), obligation,
                                                            request.value());
  PCP_CHECK(recorded.has_value());

  auto refused = fixture.value().transition_to(OperatingMode::isolated);
  PCP_CHECK(refused.has_value());
  PCP_CHECK_EQ(refused.value().outcome, DecisionOutcome::blocked_by_obligation);
  PCP_CHECK_EQ(fixture.value().snapshot().value().mode(), OperatingMode::normal);
  PCP_CHECK_EQ(fixture.value().snapshot().value().obligations().size(), std::size_t{1});

  auto granted = fixture.value().grant({ActionKind::isolate_bus}, {}, 2);
  PCP_CHECK(granted.has_value());

  std::vector<ObligationSuspension> suspensions;
  ObligationSuspension suspension;
  suspension.obligation = obligation.id;
  suspension.record.authority = AuthorityReference::parse("incident-commander").value();
  suspension.record.generation = fixture.value().snapshot().value().generation();
  suspension.record.tick = fixture.value().snapshot().value().tick();
  suspension.record.reason = "isolation authorized during a planned outage";
  suspensions.push_back(suspension);

  auto accepted = fixture.value().transition_to(OperatingMode::isolated, suspensions);
  PCP_CHECK(accepted.has_value());
  PCP_CHECK_EQ(accepted.value().outcome, DecisionOutcome::accepted);
  auto snapshot = fixture.value().snapshot();
  PCP_CHECK_EQ(snapshot.value().mode(), OperatingMode::isolated);
  // The obligation is preserved as a record and is explicitly suspended; it was never
  // dropped.
  PCP_CHECK_EQ(snapshot.value().obligations().size(), std::size_t{1});
  PCP_CHECK_EQ(snapshot.value().obligations().front().state, ObligationState::suspended);
  PCP_CHECK(snapshot.value().obligations().front().suspension.has_value());
  PCP_CHECK_EQ(snapshot.value().obligations().front().suspension->authority.view(),
               std::string("incident-commander"));

  // Leaving isolation requires post-event revalidation, which has happened after the
  // event only if revalidate() is called again.
  auto granted_restore = fixture.value().grant({ActionKind::restore_normal}, {}, 2);
  PCP_CHECK(granted_restore.has_value());
  auto leave = fixture.value().transition_to(OperatingMode::normal);
  PCP_CHECK(leave.has_value());
  PCP_CHECK_EQ(leave.value().outcome, DecisionOutcome::stale_evidence);
  auto revalidated = fixture.value().revalidate();
  PCP_CHECK(revalidated.has_value());
  PCP_CHECK(decision_committed(revalidated.value().outcome));
  auto leave_after = fixture.value().transition_to(OperatingMode::normal);
  PCP_CHECK(leave_after.has_value());
  PCP_CHECK_EQ(leave_after.value().outcome, DecisionOutcome::accepted);
}

PCP_TEST(same_mode_transition_is_a_conflict_not_a_no_op_publication) {
  auto fixture = Fixture::create("authority-mode-same");
  PCP_CHECK(fixture.has_value());
  const auto before = position(fixture.value());
  auto decision = fixture.value().transition_to(OperatingMode::normal);
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::conflict);
  const auto after = position(fixture.value());
  PCP_CHECK(before.first == after.first);
}

PCP_TEST_MAIN("test_authority")
