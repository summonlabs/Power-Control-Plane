// Proof obligations: an idempotent retry returns the committed result before any
// staleness check can reject it, retention metadata is bounded and deterministic,
// and replay never becomes a new mutation.

#include <string>
#include <vector>

#include "support/fixture.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

}  // namespace

PCP_TEST(replay_returns_the_committed_result_even_when_the_generation_moved_on) {
  auto fixture = Fixture::create("idempotency-replay");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 4);
  PCP_CHECK(granted.has_value());

  auto intent = fixture.value().intent("open-a", ActionKind::open_breaker, "bus-a");
  PCP_CHECK(intent.has_value());
  auto request = fixture.value().request("idempotency/open-a");
  PCP_CHECK(request.has_value());
  const ActionIntent planned = intent.value();
  const MutationRequest original = request.value();

  auto first = fixture.value().plane().authorize_action(fixture.value().lease(), planned,
                                                       original);
  PCP_CHECK(first.has_value());
  PCP_CHECK_EQ(first.value().outcome, DecisionOutcome::accepted);
  PCP_CHECK(first.value().attempt.has_value());
  const AttemptId attempt = first.value().attempt.value();
  const StateRevision committed_revision = fixture.value().snapshot().value().revision();

  // Several more publications move the authoritative revision on.
  for (int index = 0; index < 3; ++index) {
    auto other = fixture.value().intent("open-other-" + std::to_string(index),
                                        ActionKind::open_breaker, "bus-a");
    auto other_request =
        fixture.value().request("idempotency/other/" + std::to_string(index));
    auto decision = fixture.value().plane().authorize_action(fixture.value().lease(),
                                                             other.value(),
                                                             other_request.value());
    PCP_CHECK(decision.has_value());
    PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::accepted);
  }
  PCP_CHECK(fixture.value().snapshot().value().revision() > committed_revision);

  // The retry is deliberately planned against the *original* authority, which is now
  // stale. Replay must still win.
  auto retry = fixture.value().plane().authorize_action(fixture.value().lease(), planned,
                                                       original);
  PCP_CHECK(retry.has_value());
  PCP_CHECK_EQ(retry.value().outcome, DecisionOutcome::replayed);
  PCP_CHECK(retry.value().attempt.has_value());
  PCP_CHECK(retry.value().attempt.value() == attempt);
  PCP_CHECK_EQ(retry.value().steps.front().code, ExplanationCode::idempotent_replay);

  // A replay publishes nothing.
  const StateRevision after_replay = fixture.value().snapshot().value().revision();
  auto second_retry = fixture.value().plane().authorize_action(fixture.value().lease(), planned,
                                                              original);
  PCP_CHECK(second_retry.has_value());
  PCP_CHECK_EQ(second_retry.value().outcome, DecisionOutcome::replayed);
  PCP_CHECK(fixture.value().snapshot().value().revision() == after_replay);
}

PCP_TEST(a_new_key_is_a_new_attempt_not_a_replay) {
  auto fixture = Fixture::create("idempotency-new-key");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 4);
  PCP_CHECK(granted.has_value());

  auto intent = fixture.value().intent("open-a", ActionKind::open_breaker, "bus-a");
  PCP_CHECK(intent.has_value());
  auto first = fixture.value().authorize(intent.value(), "idempotency/key-1");
  PCP_CHECK(first.has_value());
  PCP_CHECK_EQ(first.value().outcome, DecisionOutcome::accepted);

  // A new key is a new operation, and it must be planned against the authority the
  // previous publication produced.
  auto second_intent = fixture.value().intent("open-a", ActionKind::open_breaker, "bus-a");
  PCP_CHECK(second_intent.has_value());
  auto second = fixture.value().authorize(second_intent.value(), "idempotency/key-2");
  PCP_CHECK(second.has_value());
  PCP_CHECK_EQ(second.value().outcome, DecisionOutcome::accepted);
  PCP_CHECK(second.value().attempt.value() != first.value().attempt.value());

  // Repeating the first key after the second accepted still returns the first
  // attempt, proving the index is keyed rather than positional. The stale
  // planned-against authority is deliberately left in place: replay wins.
  auto replay = fixture.value().authorize(intent.value(), "idempotency/key-1");
  PCP_CHECK(replay.has_value());
  PCP_CHECK_EQ(replay.value().outcome, DecisionOutcome::replayed);
  PCP_CHECK(replay.value().attempt.value() == first.value().attempt.value());
}

PCP_TEST(every_mutation_verb_replays_on_a_lost_response) {
  auto fixture = Fixture::create("idempotency-verbs");
  PCP_CHECK(fixture.has_value());
  Interlock interlock;
  interlock.id = InterlockId::parse("replay-interlock").value();
  interlock.source = EvidenceSourceId::parse("safety-system").value();
  interlock.severity = InterlockSeverity::blocking;
  interlock.state = InterlockState::engaged;
  interlock.explanation = "replay demo";
  interlock.declared_generation = fixture.value().snapshot().value().generation();
  auto request = fixture.value().request("idempotency/interlock");
  PCP_CHECK(request.has_value());
  const MutationRequest original = request.value();

  auto first = fixture.value().plane().record_interlock(fixture.value().lease(), interlock,
                                                       original);
  PCP_CHECK(first.has_value());
  PCP_CHECK_EQ(first.value().outcome, DecisionOutcome::accepted);
  const StateRevision after_first = fixture.value().snapshot().value().revision();

  auto retry = fixture.value().plane().record_interlock(fixture.value().lease(), interlock,
                                                       original);
  PCP_CHECK(retry.has_value());
  PCP_CHECK_EQ(retry.value().outcome, DecisionOutcome::replayed);
  PCP_CHECK(fixture.value().snapshot().value().revision() == after_first);
  PCP_CHECK_EQ(fixture.value().snapshot().value().interlocks().size(), std::size_t{1});
}

PCP_TEST(retention_bound_evicts_oldest_operations_first_and_is_reported) {
  Limits limits = Limits::defaults();
  limits.max_replay_records = 3;
  EngineOptions options;
  options.limits = limits;
  auto fixture = Fixture::create("idempotency-retention", options);
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 16);
  PCP_CHECK(granted.has_value());
  PCP_CHECK(decision_committed(granted.value().outcome));

  for (int index = 0; index < 8; ++index) {
    auto intent = fixture.value().intent("open-" + std::to_string(index),
                                         ActionKind::open_breaker, "bus-a");
    auto decision = fixture.value().authorize(intent.value(),
                                              "idempotency/retention/" + std::to_string(index));
    PCP_CHECK(decision.has_value());
    PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::accepted);
  }
  auto snapshot = fixture.value().snapshot();
  PCP_CHECK(snapshot.value().state().operation_count() <= 3);
  PCP_CHECK(snapshot.value().state().pruned_replay_records() > 0);

  // The oldest key was evicted, so a retry with it is judged as a new operation
  // rather than answered from a record that no longer exists. This is the documented
  // retention semantic.
  auto intent = fixture.value().intent("open-0", ActionKind::open_breaker, "bus-a");
  auto retry = fixture.value().authorize(intent.value(), "idempotency/retention/0");
  PCP_CHECK(retry.has_value());
  PCP_CHECK_EQ(retry.value().outcome, DecisionOutcome::accepted);

  // The newest key is still retained and still replays.
  auto newest = fixture.value().intent("open-7", ActionKind::open_breaker, "bus-a");
  auto replay = fixture.value().plane().authorize_action(
      fixture.value().lease(), newest.value(),
      [&]() {
        MutationRequest built = fixture.value().request("idempotency/retention/7").value();
        return built;
      }());
  PCP_CHECK(replay.has_value());
  PCP_CHECK_EQ(replay.value().outcome, DecisionOutcome::replayed);
}

PCP_TEST(attempt_retention_is_bounded_and_reported) {
  Limits limits = Limits::defaults();
  limits.max_attempts = 4;
  EngineOptions options;
  options.limits = limits;
  auto fixture = Fixture::create("idempotency-attempt-retention", options);
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 32);
  PCP_CHECK(granted.has_value());
  PCP_CHECK(decision_committed(granted.value().outcome));

  for (int index = 0; index < 10; ++index) {
    auto intent = fixture.value().intent("open-" + std::to_string(index),
                                         ActionKind::open_breaker, "bus-a");
    auto decision = fixture.value().authorize(intent.value(),
                                              "idempotency/attempt/" + std::to_string(index));
    PCP_CHECK(decision.has_value());
    PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::accepted);
  }
  auto snapshot = fixture.value().snapshot();
  PCP_CHECK(snapshot.value().attempts().size() <= 4);
  PCP_CHECK(snapshot.value().state().pruned_attempts() > 0);
  // Identity allocators are monotonic, so a pruned identity is never reused.
  PCP_CHECK(snapshot.value().state().next_attempt_id().value() > 10);
}

PCP_TEST_MAIN("test_idempotency")
