// Example: process death during a durable publication, then reopen and revalidation.
//
// The example re-executes itself as an independent child process. The child commits
// a transition and terminates abruptly at the exact durable stage where the new
// generation file has been published but the authoritative head marker has not yet
// been committed. The parent then reopens the store and shows that:
//
//   * the authoritative generation is still the pre-crash one,
//   * the published-but-uncommitted generation is retired as residue, never adopted,
//   * the bound evidence is not treated as fresh,
//   * revalidation re-establishes freshness, and
//   * the store verifies and replays deterministically afterwards.
//
// The child terminates through std::_Exit, which ends the process immediately
// without running destructors, flushing streams, or entering any error-reporting
// path.

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

#include "example_support.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_examples;

constexpr int kCrashExitCode = 70;

class CrashAtStage final : public CommitObserver {
 public:
  CrashAtStage(CommitStage target, std::uint64_t arm_revision)
      : target_(target), arm_revision_(arm_revision) {}

  void on_commit_stage(CommitStage stage, const CommitReport& report) override {
    if (stage != target_ || report.revision.value() < arm_revision_) {
      return;
    }
    std::cout << "child: terminating inside the publication at stage " << to_string(stage)
              << " (revision " << report.revision.value() << ")" << std::endl;
    std::cout.flush();
    std::_Exit(kCrashExitCode);
  }

 private:
  CommitStage target_;
  std::uint64_t arm_revision_;
};

int run_child(const std::string& root) {
  // The bootstrap publication must succeed; the crash is armed for the next one.
  CrashAtStage observer(CommitStage::generation_published, 2);
  EngineOptions options;
  options.commit_observer = &observer;
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, options);
  if (!plane.has_value()) {
    return fail(plane.error().describe());
  }
  auto lease = plane.value().acquire_writer();
  if (!lease.has_value()) {
    return fail(lease.error().describe());
  }
  auto topology = make_evidence("power-topology", EvidenceKind::power_topology, 31, 1);
  if (!topology.has_value()) {
    return fail("evidence construction failed");
  }
  const auto facility = FacilityId::parse("dc1");
  auto key = IdempotencyKey::derive("crash/bootstrap");
  auto booted = plane.value().bootstrap(lease.value(), facility.value(), OperatingMode::normal,
                                        topology.value(), key.value());
  if (!booted.has_value() || !decision_committed(booted.value().outcome)) {
    return fail("the child could not bootstrap the facility");
  }
  auto first = plane.value().snapshot();
  if (!first.has_value()) {
    return fail(first.error().describe());
  }
  line("child: bootstrap committed at revision " +
       std::to_string(first.value().revision().value()));

  ModeTransitionRequest transition;
  transition.target = OperatingMode::degraded;
  transition.authority = AuthorityReference::parse("watchdog").value();
  auto request = make_request(first.value().state(), "crash/degrade");
  if (!request.has_value()) {
    return fail(request.error().describe());
  }
  transition.planned = request.value().planned;
  transition.key = request.value().key;
  auto decision = plane.value().request_mode_transition(lease.value(), transition);
  if (!decision.has_value()) {
    return fail(decision.error().describe());
  }
  return fail("the child was expected to terminate inside the publication");
}

int run_parent(const std::string& root, const std::string& executable) {
  heading("crash child");
  // The whole command is wrapped in an extra pair of quotes: the host command
  // interpreter strips the outermost quotes, which is what makes an executable path
  // containing spaces survive.
  const std::string command =
      "\"\"" + executable + "\" --crash-child \"" + root + "\"\"";
  const int child_status = std::system(command.c_str());
  line("child exit status: " + std::to_string(child_status));
  if (child_status == 0) {
    return fail("the crash child exited successfully, so no crash was exercised");
  }

  heading("reopen after process death");
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  if (!plane.has_value()) {
    return fail(plane.error().describe());
  }
  const StoreOpenReport& report = plane.value().store().open_report();
  line("head present: " + std::string(plane.value().store().head().present ? "yes" : "no"));
  line("head revision: " + std::to_string(plane.value().store().head().revision.value()) +
       " (the crashed revision was never committed)");
  line("retired orphan generations: " + std::to_string(report.retired_orphan_states));
  line("retired staging files: " + std::to_string(report.retired_staging_files));
  line("recovery detail: " + report.detail);

  auto status = plane.value().status();
  if (!status.has_value()) {
    return fail(status.error().describe());
  }
  line("operating mode after recovery: " + std::string(to_string(status.value().mode)));
  if (report.retired_orphan_states == 0) {
    return fail("the interrupted publication should have left an orphan generation");
  }
  if (status.value().mode != OperatingMode::normal) {
    return fail("the uncommitted mode transition must not be visible after recovery");
  }

  heading("recovered evidence is not fresh");
  const RevalidationReport freshness = plane.value().revalidation_status();
  line("evidence fresh after reopen: " +
       std::string(freshness.evidence_fresh ? "yes" : "no"));
  line("detail: " + freshness.detail);

  heading("revalidation");
  auto lease = plane.value().acquire_writer();
  if (!lease.has_value()) {
    return fail(lease.error().describe());
  }
  auto topology = make_evidence("power-topology", EvidenceKind::power_topology, 31, 1);
  auto snapshot = plane.value().snapshot();
  auto request = make_request(snapshot.value().state(), "crash/revalidate");
  auto revalidated =
      plane.value().revalidate(lease.value(), topology.value(), request.value());
  if (!revalidated.has_value()) {
    return fail(revalidated.error().describe());
  }
  show_decision(plane.value().limits(), revalidated.value());
  line("evidence fresh after revalidation: " +
       std::string(plane.value().revalidation_status().evidence_fresh ? "yes" : "no"));

  heading("verification");
  auto integrity = plane.value().verify_store();
  auto replay = plane.value().verify_replay();
  if (!integrity.has_value() || !replay.has_value()) {
    return fail("verification could not run");
  }
  line("store integrity ok: " + std::string(integrity.value().ok ? "yes" : "no"));
  line("deterministic replay ok: " + std::string(replay.value().ok ? "yes" : "no") +
       " steps=" + std::to_string(replay.value().steps_checked));
  static_cast<void>(plane.value().release_writer(lease.value()));
  plane.value().close();
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  const std::string root = argc > 2 ? argv[2] : "example-crash-recovery-store";
  if (argc > 1 && std::string(argv[1]) == "--crash-child") {
    return run_child(root);
  }
  std::error_code error;
  std::filesystem::remove_all(root, error);
  const int code = run_parent(root, argv[0]);
  std::filesystem::remove_all(root, error);
  return code;
}
