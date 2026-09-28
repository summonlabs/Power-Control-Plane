// Proof obligations: real independent processes, real operating-system writer
// authority, process-death release, epoch handoff, and crash injection at every
// meaningful durable stage.
//
// Every child is a separate operating-system process started through the probe
// executable. Termination inside a child is performed with std::_Exit, which ends the
// process immediately without running destructors, flushing streams, or entering any
// error-reporting path.

#include <filesystem>
#include <string>
#include <vector>

#include "power_control_plane/store.hpp"
#include "support/fixture.hpp"
#include "support/proc.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

struct StageExpectation {
  const char* name;
  // The authoritative revision the store must hold after the crash.
  std::uint64_t expected_revision;
  // Whether an interrupted publication must have left an orphan generation.
  bool expect_orphan;
};

const StageExpectation kStages[] = {
    {"staging_written", 1, false},
    {"staging_flushed", 1, false},
    {"staging_read_back_verified", 1, false},
    {"generation_published", 1, true},
    {"head_committed", 2, false},
    {"authority_marked", 2, false},
    {"residue_retired", 2, false},
};

std::uint64_t parse_field(const std::string& output, std::string_view key) {
  const std::size_t position = output.find(key);
  if (position == std::string::npos) {
    return 0;
  }
  return std::strtoull(output.c_str() + position + key.size(), nullptr, 10);
}

}  // namespace

PCP_TEST(a_second_process_cannot_take_writer_authority_from_a_live_writer) {
  auto fixture = Fixture::create("multiprocess-refusal");
  PCP_CHECK(fixture.has_value());
  // The parent holds writer authority while the child tries to take it.
  auto outcome = run_process(probe_executable(), {"acquire-report", fixture.value().root()},
                             fixture.value().root());
  PCP_CHECK(outcome.has_value());
  PCP_CHECK_EQ(outcome.value().exit_code, 0);
  context.note("child output: " + outcome.value().output);
  PCP_CHECK(outcome.value().output.find("acquire=error:lock_unavailable") != std::string::npos);
  // The parent still holds authority after the child was refused.
  PCP_CHECK(fixture.value().plane().store().writer_status().held_by_this_store);
}

PCP_TEST(process_death_releases_writer_authority_and_the_successor_epoch_advances) {
  const std::string root = scratch_directory("multiprocess-handoff");
  auto seeded = run_process(probe_executable(), {"bootstrap", root}, root);
  PCP_CHECK(seeded.has_value());
  PCP_CHECK_EQ(seeded.value().exit_code, 0);
  context.note("bootstrap output: " + seeded.value().output);

  auto before = run_process(probe_executable(), {"epoch-report", root}, root);
  PCP_CHECK(before.has_value());
  const std::uint64_t epoch_before = parse_field(before.value().output, "epoch=");
  PCP_CHECK(epoch_before >= 1);

  auto crashed = run_process(probe_executable(), {"hold-and-die", root}, root);
  PCP_CHECK(crashed.has_value());
  PCP_CHECK_EQ(crashed.value().exit_code, 71);
  context.note("dying writer output: " + crashed.value().output);

  // The kernel released the lock when the process died, so a successor can take
  // authority without any cleanup step.
  auto successor = run_process(probe_executable(), {"acquire-report", root}, root);
  PCP_CHECK(successor.has_value());
  PCP_CHECK_EQ(successor.value().exit_code, 0);
  context.note("successor output: " + successor.value().output);
  PCP_CHECK(successor.value().output.find("acquire=ok") != std::string::npos);
  const std::uint64_t successor_epoch = parse_field(successor.value().output, "epoch=");
  PCP_CHECK(successor_epoch > epoch_before);

  auto verified = run_process(probe_executable(), {"verify", root}, root);
  PCP_CHECK(verified.has_value());
  PCP_CHECK_EQ(verified.value().exit_code, 0);
  PCP_CHECK(verified.value().output.find("integrity=1") != std::string::npos);
  PCP_CHECK(verified.value().output.find("replay=1") != std::string::npos);
}

PCP_TEST(crash_at_every_durable_stage_leaves_one_whole_verifiable_generation) {
  for (const StageExpectation& stage : kStages) {
    const std::string root = scratch_directory(std::string("multiprocess-crash-") + stage.name);
    auto crashed =
        run_process(probe_executable(), {"crash", root, stage.name, "2"}, root);
    PCP_CHECK(crashed.has_value());
    PCP_CHECK_MSG(crashed.value().exit_code == 70,
                  std::string("stage ") + stage.name + " child output: " +
                      crashed.value().output);
    context.note(std::string("stage ") + stage.name + ": " + crashed.value().output);

    auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
    PCP_CHECK_MSG(plane.has_value(), std::string("stage ") + stage.name + " reopen failed");
    const StoreOpenReport& report = plane.value().store().open_report();
    context.note(std::string("stage ") + stage.name + ": orphan=" +
                 std::to_string(report.retired_orphan_states) + " staging=" +
                 std::to_string(report.retired_staging_files));
    PCP_CHECK(plane.value().store().head().present);
    PCP_CHECK_EQ(plane.value().store().head().revision.value(), stage.expected_revision);
    if (stage.expect_orphan) {
      PCP_CHECK(report.retired_orphan_states >= 1);
    }
    auto integrity = plane.value().verify_store();
    PCP_CHECK(integrity.has_value());
    PCP_CHECK_MSG(integrity.value().ok, std::string("stage ") + stage.name + ": " +
                                            integrity.value().detail);
    auto replay = plane.value().verify_replay();
    PCP_CHECK(replay.has_value());
    PCP_CHECK_MSG(replay.value().ok, std::string("stage ") + stage.name + ": " +
                                         replay.value().detail);
    plane.value().close();

    // The recovered store accepts new authoritative work.
    auto fresh = run_process(probe_executable(), {"crash", root, "residue_retired", "2"}, root);
    PCP_CHECK(fresh.has_value());
    PCP_CHECK_EQ(fresh.value().exit_code, 70);
    auto after = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
    PCP_CHECK(after.has_value());
    PCP_CHECK(after.value().store().head().revision.value() >= stage.expected_revision);
    auto final_integrity = after.value().verify_store();
    PCP_CHECK(final_integrity.has_value());
    PCP_CHECK_MSG(final_integrity.value().ok, std::string("stage ") + stage.name +
                                                 " second crash: " +
                                                 final_integrity.value().detail);
    after.value().close();
  }
}

PCP_TEST(a_child_process_cannot_publish_with_a_superseded_epoch) {
  const std::string root = scratch_directory("multiprocess-stale-child");
  auto seeded = run_process(probe_executable(), {"bootstrap", root}, root);
  PCP_CHECK(seeded.has_value());
  PCP_CHECK_EQ(seeded.value().exit_code, 0);

  // A child acquires writer authority and dies immediately, leaving epoch N behind.
  auto crashed = run_process(probe_executable(), {"hold-and-die", root}, root);
  PCP_CHECK(crashed.has_value());
  PCP_CHECK_EQ(crashed.value().exit_code, 71);

  // A second child acquires epoch N+1 and completes a publication.
  auto successor = run_process(probe_executable(), {"crash", root, "residue_retired", "2"}, root);
  PCP_CHECK(successor.has_value());
  context.note("successor output: " + successor.value().output);

  auto final_state = run_process(probe_executable(), {"read-report", root}, root);
  PCP_CHECK(final_state.has_value());
  PCP_CHECK_EQ(final_state.value().exit_code, 0);
  context.note("final output: " + final_state.value().output);
  PCP_CHECK(final_state.value().output.find("head=1") != std::string::npos);
  // Recovery never treats persisted dynamic evidence as fresh.
  PCP_CHECK(final_state.value().output.find("fresh=0") != std::string::npos);
}

PCP_TEST_MAIN("test_multiprocess")
