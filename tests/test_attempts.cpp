// Proof obligations: authorization, issued command, acknowledgement, observed
// effect, and verified completion are separate states; verification is independent;
// the attempt state machine refuses illegal progress; terminal states are final.

#include <string>
#include <vector>

#include "support/fixture.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

IssuedCommand command_for(const AttemptId attempt, const ActionIntent& intent,
                          ControlGeneration generation, StateRevision revision) {
  IssuedCommand command;
  command.attempt = attempt;
  command.action = intent.id;
  command.kind = intent.kind;
  command.target = intent.target;
  command.generation = generation;
  command.revision = revision;
  command.command_digest = command_digest(command);
  return command;
}

}  // namespace

PCP_TEST(acknowledgement_alone_does_not_produce_a_verified_attempt) {
  auto fixture = Fixture::create("attempts-ack-only");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::close_breaker}, {"bus-a"}, 1);
  PCP_CHECK(granted.has_value());

  auto intent = fixture.value().intent("close-a", ActionKind::close_breaker, "bus-a");
  auto request = fixture.value().request("attempts/ack-only");
  PCP_CHECK(intent.has_value() && request.has_value());
  SimulationAdapter adapter(AdapterId::parse("adapter-a").value(),
                            SimulationBehaviour::acknowledge_only);
  ActuationOutcome outcome;
  auto decision = fixture.value().plane().actuate(fixture.value().lease(), intent.value(),
                                                 request.value(), adapter, outcome);
  PCP_CHECK(decision.has_value());
  PCP_CHECK(decision_committed(decision.value().outcome));
  PCP_CHECK(outcome.command_issued);
  PCP_CHECK(outcome.acknowledged);
  PCP_CHECK(!outcome.effect_observed);
  PCP_CHECK(!outcome.verified);
  PCP_CHECK_EQ(outcome.final_state, AttemptState::acknowledged);

  auto snapshot = fixture.value().snapshot();
  const AttemptRecord* record = snapshot.value().state().find_attempt(outcome.attempt);
  PCP_CHECK(record != nullptr);
  PCP_CHECK(record->acknowledgement.has_value());
  PCP_CHECK(!record->effect.has_value());
  PCP_CHECK(!record->verification.has_value());
  PCP_CHECK_EQ(record->state, AttemptState::acknowledged);
  PCP_CHECK(!attempt_is_terminal(record->state));
}

PCP_TEST(refused_command_never_reaches_the_adapter_state_machine) {
  auto fixture = Fixture::create("attempts-refused");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::close_breaker}, {"bus-a"}, 1);
  PCP_CHECK(granted.has_value());
  auto intent = fixture.value().intent("close-a", ActionKind::close_breaker, "bus-a");
  auto request = fixture.value().request("attempts/refused");
  PCP_CHECK(intent.has_value() && request.has_value());
  SimulationAdapter adapter(AdapterId::parse("adapter-a").value(),
                            SimulationBehaviour::refuse_command);
  ActuationOutcome outcome;
  auto decision = fixture.value().plane().actuate(fixture.value().lease(), intent.value(),
                                                 request.value(), adapter, outcome);
  PCP_CHECK(decision.has_value());
  PCP_CHECK(decision_committed(decision.value().outcome));
  PCP_CHECK(!outcome.command_issued);
  PCP_CHECK(!outcome.acknowledged);
  PCP_CHECK(!outcome.effect_observed);
  PCP_CHECK(!outcome.verified);
  PCP_CHECK_EQ(outcome.final_state, AttemptState::effect_failed);
  PCP_CHECK_EQ(adapter.issues(), std::size_t{1});
}

PCP_TEST(a_refused_authorization_never_invokes_the_adapter) {
  auto fixture = Fixture::create("attempts-no-permission");
  PCP_CHECK(fixture.has_value());
  auto intent = fixture.value().intent("close-a", ActionKind::close_breaker, "bus-a");
  auto request = fixture.value().request("attempts/no-permission");
  PCP_CHECK(intent.has_value() && request.has_value());
  SimulationAdapter adapter(AdapterId::parse("adapter-a").value(),
                            SimulationBehaviour::full_success);
  ActuationOutcome outcome;
  auto decision = fixture.value().plane().actuate(fixture.value().lease(), intent.value(),
                                                 request.value(), adapter, outcome);
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::unauthorized);
  PCP_CHECK_EQ(adapter.issues(), std::size_t{0});
  PCP_CHECK_EQ(adapter.observations(), std::size_t{0});
  PCP_CHECK_EQ(adapter.verifications(), std::size_t{0});
  PCP_CHECK(fixture.value().snapshot().value().attempts().empty());
}

PCP_TEST(verification_from_the_acknowledging_adapter_is_refused) {
  auto fixture = Fixture::create("attempts-independence");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::close_breaker}, {"bus-a"}, 1);
  PCP_CHECK(granted.has_value());
  auto intent = fixture.value().intent("close-a", ActionKind::close_breaker, "bus-a");
  auto request = fixture.value().request("attempts/independence");
  PCP_CHECK(intent.has_value() && request.has_value());
  auto decision = fixture.value().authorize(intent.value(), "attempts/independence");
  PCP_CHECK(decision.has_value());
  PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::accepted);
  const AttemptId attempt = decision.value().attempt.value();
  auto snapshot = fixture.value().snapshot();
  const IssuedCommand command = command_for(attempt, intent.value(),
                                            snapshot.value().generation(),
                                            snapshot.value().revision());

  Acknowledgement acknowledgement;
  acknowledgement.adapter = AdapterId::parse("adapter-a").value();
  acknowledgement.command_digest = command.command_digest;
  acknowledgement.detail = "receipt";
  auto issued_request = fixture.value().request("attempts/issued");
  auto issued = fixture.value().plane().record_issued(fixture.value().lease(), attempt,
                                                     command.command_digest, "issued",
                                                     issued_request.value());
  PCP_CHECK(issued.has_value());
  PCP_CHECK(decision_committed(issued.value().outcome));

  auto ack_request = fixture.value().request("attempts/ack");
  auto acknowledged = fixture.value().plane().record_acknowledgement(
      fixture.value().lease(), attempt, acknowledgement, ack_request.value());
  PCP_CHECK(acknowledged.has_value());
  PCP_CHECK(decision_committed(acknowledged.value().outcome));

  ObservedEffect effect;
  effect.adapter = acknowledgement.adapter;
  effect.observation_digest = sha256_domain("pcp/test-observation/v1", "observed");
  effect.detail = "observed";
  auto effect_request = fixture.value().request("attempts/effect");
  auto observed = fixture.value().plane().record_observed_effect(
      fixture.value().lease(), attempt, effect, effect_request.value());
  PCP_CHECK(observed.has_value());
  PCP_CHECK(decision_committed(observed.value().outcome));

  // The same adapter identity acknowledged and now claims verification: refused,
  // because a report from the adapter that acknowledged the command is not
  // independent evidence.
  VerificationReport report;
  report.verifier = acknowledgement.adapter;
  report.matches_intent = true;
  report.evidence_digest = effect.observation_digest;
  report.detail = "self reported";
  auto verify_request = fixture.value().request("attempts/verify-self");
  auto verified = fixture.value().plane().record_verification(
      fixture.value().lease(), attempt, report, verify_request.value());
  PCP_CHECK(verified.has_value());
  PCP_CHECK_EQ(verified.value().outcome, DecisionOutcome::conflict);
  auto after = fixture.value().snapshot();
  const AttemptRecord* record = after.value().state().find_attempt(attempt);
  PCP_CHECK(record != nullptr);
  PCP_CHECK(!record->verification.has_value());
  PCP_CHECK_EQ(record->state, AttemptState::effect_observed);

  // A different adapter identity can verify.
  report.verifier = AdapterId::parse("verifier-b").value();
  auto independent_request = fixture.value().request("attempts/verify-independent");
  auto independent = fixture.value().plane().record_verification(
      fixture.value().lease(), attempt, report, independent_request.value());
  PCP_CHECK(independent.has_value());
  PCP_CHECK(decision_committed(independent.value().outcome));
  auto final_state = fixture.value().snapshot();
  const AttemptRecord* finished = final_state.value().state().find_attempt(attempt);
  PCP_CHECK(finished != nullptr);
  PCP_CHECK_EQ(finished->state, AttemptState::verified);
  PCP_CHECK(attempt_is_terminal(finished->state));

  // A verified attempt accepts no further progress.
  auto further = fixture.value().plane().cancel_attempt(fixture.value().lease(), attempt,
                                                        fixture.value().request(
                                                            "attempts/cancel-verified").value());
  PCP_CHECK(further.has_value());
  PCP_CHECK_EQ(further.value().outcome, DecisionOutcome::conflict);
}

PCP_TEST(illegal_attempt_progress_is_refused) {
  auto fixture = Fixture::create("attempts-illegal");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::close_breaker}, {"bus-a"}, 4);
  PCP_CHECK(granted.has_value());
  auto intent = fixture.value().intent("close-a", ActionKind::close_breaker, "bus-a");
  auto decision = fixture.value().authorize(intent.value(), "attempts/illegal");
  PCP_CHECK(decision.has_value());
  const AttemptId attempt = decision.value().attempt.value();

  // Acknowledging before the command was issued is not a legal transition.
  Acknowledgement acknowledgement;
  acknowledgement.adapter = AdapterId::parse("adapter-a").value();
  acknowledgement.command_digest = sha256_domain("pcp/test-command/v1", "x");
  acknowledgement.detail = "receipt";
  auto early = fixture.value().plane().record_acknowledgement(
      fixture.value().lease(), attempt, acknowledgement,
      fixture.value().request("attempts/early-ack").value());
  PCP_CHECK(early.has_value());
  PCP_CHECK_EQ(early.value().outcome, DecisionOutcome::conflict);

  // An unknown attempt identity is a conflict rather than a crash.
  auto unknown = fixture.value().plane().cancel_attempt(
      fixture.value().lease(), AttemptId(9999),
      fixture.value().request("attempts/unknown").value());
  PCP_CHECK(unknown.has_value());
  PCP_CHECK_EQ(unknown.value().outcome, DecisionOutcome::conflict);
}

PCP_TEST(cancel_and_supersede_are_distinct_recorded_states) {
  auto fixture = Fixture::create("attempts-cancel");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::close_breaker}, {"bus-a"}, 4);
  PCP_CHECK(granted.has_value());
  auto first = fixture.value().authorize(
      fixture.value().intent("close-1", ActionKind::close_breaker, "bus-a").value(),
      "attempts/cancel-1");
  PCP_CHECK(first.has_value());
  auto second = fixture.value().authorize(
      fixture.value().intent("close-2", ActionKind::close_breaker, "bus-a").value(),
      "attempts/supersede-2");
  PCP_CHECK(second.has_value());

  auto cancelled = fixture.value().plane().cancel_attempt(
      fixture.value().lease(), first.value().attempt.value(),
      fixture.value().request("attempts/cancel").value());
  PCP_CHECK(cancelled.has_value());
  PCP_CHECK(decision_committed(cancelled.value().outcome));
  auto superseded = fixture.value().plane().supersede_attempt(
      fixture.value().lease(), second.value().attempt.value(),
      fixture.value().request("attempts/supersede").value());
  PCP_CHECK(superseded.has_value());
  PCP_CHECK(decision_committed(superseded.value().outcome));

  auto snapshot = fixture.value().snapshot();
  const AttemptRecord* first_record =
      snapshot.value().state().find_attempt(first.value().attempt.value());
  const AttemptRecord* second_record =
      snapshot.value().state().find_attempt(second.value().attempt.value());
  PCP_CHECK(first_record != nullptr && second_record != nullptr);
  PCP_CHECK_EQ(first_record->state, AttemptState::cancelled);
  PCP_CHECK_EQ(second_record->state, AttemptState::superseded);
  PCP_CHECK(first_record->state != second_record->state);
}

PCP_TEST_MAIN("test_attempts")
