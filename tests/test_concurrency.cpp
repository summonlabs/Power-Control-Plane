// Proof obligations: the documented concurrency model holds, readers always observe
// a whole snapshot, exactly one writer authority is current, and a stale authority
// race between validation and commit cannot publish.
//
// The tests count what each side did, so a passing result cannot be vacuous because
// one side never ran.

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "support/fixture.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

}  // namespace

PCP_TEST(concurrent_writer_acquisition_yields_exactly_one_current_authority) {
  auto fixture = Fixture::create("concurrency-acquire");
  PCP_CHECK(fixture.has_value());
  constexpr int kThreads = 8;
  std::vector<ControllerEpoch> epochs(static_cast<std::size_t>(kThreads));
  std::vector<bool> succeeded(static_cast<std::size_t>(kThreads), false);
  std::atomic<int> ready{0};
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int index = 0; index < kThreads; ++index) {
    threads.emplace_back([&, index]() {
      ready.fetch_add(1);
      auto lease = fixture.value().plane().acquire_writer();
      if (lease.has_value()) {
        succeeded[static_cast<std::size_t>(index)] = true;
        epochs[static_cast<std::size_t>(index)] = lease.value().epoch();
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  PCP_CHECK_EQ(ready.load(), kThreads);
  int success_count = 0;
  for (const bool value : succeeded) {
    if (value) {
      ++success_count;
    }
  }
  // Every caller receives the same current lease: a second acquisition in the same
  // process is idempotent rather than a new epoch.
  PCP_CHECK_EQ(success_count, kThreads);
  for (const ControllerEpoch epoch : epochs) {
    PCP_CHECK(epoch == epochs.front());
  }
  PCP_CHECK(epochs.front().value() >= 1);
}

PCP_TEST(concurrent_authorizations_produce_exactly_one_winner_per_revision) {
  auto fixture = Fixture::create("concurrency-authorize");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 64);
  PCP_CHECK(granted.has_value());
  PCP_CHECK(decision_committed(granted.value().outcome));

  constexpr int kThreads = 8;
  std::vector<ActionIntent> intents;
  std::vector<MutationRequest> requests;
  for (int index = 0; index < kThreads; ++index) {
    auto intent = fixture.value().intent("open-" + std::to_string(index),
                                         ActionKind::open_breaker, "bus-a");
    auto request = fixture.value().request("concurrency/authorize/" + std::to_string(index));
    PCP_CHECK(intent.has_value() && request.has_value());
    intents.push_back(intent.value());
    requests.push_back(request.value());
  }
  const StateRevision planned_revision = requests.front().planned.revision;

  std::vector<DecisionOutcome> outcomes(static_cast<std::size_t>(kThreads),
                                        DecisionOutcome::invalid_request);
  std::atomic<int> ready{0};
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int index = 0; index < kThreads; ++index) {
    threads.emplace_back([&, index]() {
      const std::size_t slot = static_cast<std::size_t>(index);
      ready.fetch_add(1);
      auto decision = fixture.value().plane().authorize_action(
          fixture.value().lease(), intents[slot], requests[slot]);
      if (decision.has_value()) {
        outcomes[slot] = decision.value().outcome;
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  PCP_CHECK_EQ(ready.load(), kThreads);
  int accepted = 0;
  int stale = 0;
  for (const DecisionOutcome outcome : outcomes) {
    if (outcome == DecisionOutcome::accepted) {
      ++accepted;
    } else if (outcome == DecisionOutcome::stale_generation) {
      ++stale;
    }
  }
  // Exactly one thread committed the revision the others were planned against; the
  // rest were refused as stale rather than silently merged.
  PCP_CHECK_EQ(accepted, 1);
  PCP_CHECK_EQ(stale, kThreads - 1);
  PCP_CHECK(fixture.value().snapshot().value().revision() > planned_revision);
}

PCP_TEST(readers_observe_whole_snapshots_while_a_writer_publishes) {
  auto fixture = Fixture::create("concurrency-readers");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 64);
  PCP_CHECK(granted.has_value());

  constexpr int kWriters = 24;
  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> reads{0};
  std::atomic<std::uint64_t> inconsistent{0};
  std::atomic<std::uint64_t> writes{0};
  std::vector<std::thread> threads;

  threads.emplace_back([&]() {
    for (int index = 0; index < kWriters; ++index) {
      auto intent = fixture.value().intent("open-" + std::to_string(index),
                                           ActionKind::open_breaker, "bus-a");
      auto request =
          fixture.value().request("concurrency/reader-writer/" + std::to_string(index));
      if (!intent.has_value() || !request.has_value()) {
        break;
      }
      auto decision = fixture.value().plane().authorize_action(fixture.value().lease(),
                                                               intent.value(),
                                                               request.value());
      if (decision.has_value() && decision_committed(decision.value().outcome)) {
        writes.fetch_add(1);
      }
    }
    stop.store(true);
  });

  for (int reader = 0; reader < 3; ++reader) {
    threads.emplace_back([&]() {
      while (!stop.load()) {
        auto snapshot = fixture.value().plane().snapshot();
        if (!snapshot.has_value()) {
          inconsistent.fetch_add(1);
          continue;
        }
        // A snapshot is immutable and self-consistent: its cached digest equals a
        // digest recomputed from the bytes it encodes.
        const Digest cached = snapshot.value().digest();
        const Digest recomputed = snapshot.value().state().canonical_digest();
        if (!(cached == recomputed)) {
          inconsistent.fetch_add(1);
        }
        if (snapshot.value().state().facility().empty()) {
          inconsistent.fetch_add(1);
        }
        reads.fetch_add(1);
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  // Both sides must have actually run for this test to mean anything.
  PCP_CHECK(writes.load() >= 1);
  PCP_CHECK(reads.load() >= 1);
  PCP_CHECK_EQ(inconsistent.load(), std::uint64_t{0});
  auto integrity = fixture.value().plane().verify_store();
  PCP_CHECK(integrity.has_value() && integrity.value().ok);
}

PCP_TEST(a_released_lease_cannot_publish_after_a_successor_takes_authority) {
  auto fixture = Fixture::create("concurrency-fencing");
  PCP_CHECK(fixture.has_value());
  WriterLease first = fixture.value().lease();
  const Status released = fixture.value().plane().release_writer(first);
  PCP_CHECK(released.ok());
  auto successor = fixture.value().plane().acquire_writer();
  PCP_CHECK(successor.has_value());
  PCP_CHECK(successor.value().epoch() > first.epoch());

  Interlock interlock;
  interlock.id = InterlockId::parse("fenced").value();
  interlock.source = EvidenceSourceId::parse("safety-system").value();
  interlock.severity = InterlockSeverity::blocking;
  interlock.state = InterlockState::engaged;
  interlock.explanation = "fencing";
  interlock.declared_generation = fixture.value().snapshot().value().generation();
  auto request = fixture.value().request("concurrency/fencing");
  PCP_CHECK(request.has_value());
  auto refused = fixture.value().plane().record_interlock(first, interlock, request.value());
  PCP_CHECK(refused.has_value());
  PCP_CHECK_EQ(refused.value().outcome, DecisionOutcome::stale_authority);
  PCP_CHECK(fixture.value().snapshot().value().interlocks().empty());

  // The successor can publish.
  auto accepted = fixture.value().plane().record_interlock(successor.value(), interlock,
                                                           request.value());
  PCP_CHECK(accepted.has_value());
  PCP_CHECK_EQ(accepted.value().outcome, DecisionOutcome::accepted);
}

PCP_TEST_MAIN("test_concurrency")
