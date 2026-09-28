// Proof obligations: deterministic replay reproduces every retained publication byte
// for byte from the published bytes plus the logged transition, and a tampered
// generation is detected.

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "power_control_plane/store.hpp"
#include "support/fixture.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

std::string path_of(const std::string& root, std::string_view name) {
  return (std::filesystem::path(root) / std::string(name)).string();
}

Bytes read_all(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  Bytes bytes;
  char buffer[4096];
  while (input.read(buffer, sizeof(buffer)) || input.gcount() > 0) {
    bytes.insert(bytes.end(), buffer, buffer + input.gcount());
  }
  return bytes;
}

void write_all(const std::string& path, const Bytes& bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
}

}  // namespace

PCP_TEST(replay_reproduces_every_retained_publication) {
  EngineOptions options;
  options.retained_publications = 6;
  auto fixture = Fixture::create("replay-window", options);
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant(
      {ActionKind::open_breaker, ActionKind::close_breaker, ActionKind::restore_normal}, {}, 64);
  PCP_CHECK(granted.has_value());
  for (int index = 0; index < 6; ++index) {
    auto intent = fixture.value().intent("open-" + std::to_string(index),
                                         ActionKind::open_breaker, "bus-a");
    auto decision = fixture.value().authorize(intent.value(),
                                              "replay/" + std::to_string(index));
    PCP_CHECK(decision.has_value());
    PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::accepted);
  }
  auto replay = fixture.value().plane().verify_replay();
  PCP_CHECK(replay.has_value());
  for (const ReplayStepReport& step : replay.value().steps) {
    context.note("revision " + std::to_string(step.from_revision.value()) + " -> " +
                 std::to_string(step.to_revision.value()) + " kind=" +
                 std::string(to_string(step.kind)) + " matched=" +
                 (step.matched ? "yes" : "no"));
  }
  PCP_CHECK_MSG(replay.value().ok, replay.value().detail);
  PCP_CHECK(replay.value().steps_checked >= 5);
  for (const ReplayStepReport& step : replay.value().steps) {
    PCP_CHECK(step.matched);
    PCP_CHECK(step.expected_digest == step.actual_digest);
  }
}

PCP_TEST(replay_reports_a_mismatch_when_a_logged_transition_is_replaced) {
  EngineOptions options;
  options.retained_publications = 6;
  auto fixture = Fixture::create("replay-tamper", options);
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 32);
  PCP_CHECK(granted.has_value());
  for (int index = 0; index < 5; ++index) {
    auto intent = fixture.value().intent("open-" + std::to_string(index),
                                         ActionKind::open_breaker, "bus-a");
    auto decision = fixture.value().authorize(intent.value(), "replay-tamper/" + std::to_string(index));
    PCP_CHECK(decision.has_value());
    PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::accepted);
  }
  const std::string root = fixture.value().root();
  const std::vector<StateRevision> retained =
      fixture.value().plane().store().retained_publications();
  PCP_CHECK(retained.size() >= 3);
  fixture.value().close();

  // A tampered generation file fails its own integrity check, which replay surfaces
  // as an error rather than a silent mismatch.
  const std::string victim = path_of(root, state_file_name(retained[1]));
  Bytes bytes = read_all(victim);
  PCP_CHECK(bytes.size() > 200);
  bytes[150] ^= 0x01;
  write_all(victim, bytes);

  auto plane = ControlPlane::open(root, StoreOpenMode::read_only, EngineOptions{});
  PCP_CHECK(plane.has_value());
  auto replay = plane.value().verify_replay();
  // Either the load fails outright or the replay reports a mismatch; both are
  // refusals rather than an accepted result.
  PCP_CHECK(!replay.has_value() || !replay.value().ok);
}

PCP_TEST(replay_of_a_single_publication_window_is_reported_not_failed) {
  EngineOptions options;
  options.retained_publications = 2;
  auto fixture = Fixture::create("replay-single", options);
  PCP_CHECK(fixture.has_value());
  auto replay = fixture.value().plane().verify_replay();
  PCP_CHECK(replay.has_value());
  PCP_CHECK(replay.value().ok);
  PCP_CHECK_EQ(replay.value().steps_checked, std::size_t{1});
}

PCP_TEST(integrity_and_replay_agree_after_a_clean_close) {
  EngineOptions options;
  options.retained_publications = 4;
  auto fixture = Fixture::create("replay-clean-close", options);
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 16);
  PCP_CHECK(granted.has_value());
  for (int index = 0; index < 4; ++index) {
    auto intent = fixture.value().intent("open-" + std::to_string(index),
                                         ActionKind::open_breaker, "bus-a");
    auto decision = fixture.value().authorize(intent.value(),
                                              "replay-clean/" + std::to_string(index));
    PCP_CHECK(decision.has_value());
  }
  const std::string root = fixture.value().root();
  fixture.value().close();
  auto plane = ControlPlane::open(root, StoreOpenMode::read_only, EngineOptions{});
  PCP_CHECK(plane.has_value());
  auto integrity = plane.value().verify_store();
  auto replay = plane.value().verify_replay();
  PCP_CHECK(integrity.has_value() && integrity.value().ok);
  PCP_CHECK(replay.has_value() && replay.value().ok);
  PCP_CHECK_EQ(replay.value().steps_checked, std::size_t{3});
}

PCP_TEST_MAIN("test_replay")
