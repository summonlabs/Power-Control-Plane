// Independent child process used by the multiprocess and crash-injection tests.
//
// Every verb is a real, separate operating-system process. Termination is performed
// with std::_Exit, which ends the process immediately: no destructors run, no
// buffers are flushed, and no error-reporting path is entered.

#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "power_control_plane/engine.hpp"

namespace {

using namespace power_control_plane;

constexpr int kCrashExitCode = 70;
constexpr int kHoldExitCode = 71;

class CrashAtStage final : public CommitObserver {
 public:
  // The crash is armed from a given publication revision onwards so that the setup
  // publications a test needs (bootstrap, policy, evidence) always complete.
  CrashAtStage(CommitStage target, std::uint64_t arm_revision)
      : target_(target), arm_revision_(arm_revision) {}

  void on_commit_stage(CommitStage stage, const CommitReport& report) override {
    if (stage != target_ || report.revision.value() < arm_revision_) {
      return;
    }
    std::cout << "probe: crash at stage " << to_string(stage)
              << " revision=" << report.revision.value() << std::endl;
    std::cout.flush();
    std::_Exit(kCrashExitCode);
  }

 private:
  CommitStage target_;
  std::uint64_t arm_revision_;
};

Result<EvidenceBinding> fixed_evidence() {
  std::vector<EvidenceRef> references;
  for (const auto& spec : {std::pair<const char*, EvidenceKind>{"power-topology",
                                                                EvidenceKind::power_topology},
                           std::pair<const char*, EvidenceKind>{"power-capacity",
                                                                EvidenceKind::power_capacity}}) {
    EvidenceRef reference;
    reference.source = EvidenceSourceId::parse(spec.first).value();
    reference.kind = spec.second;
    reference.generation = EvidenceGeneration(5);
    reference.revision = EvidenceRevision(3);
    reference.epoch = ControllerEpoch(11);
    reference.incarnation = ControllerIncarnation::from_parts(0xAAAA5555AAAA5555ull,
                                                              0x5555AAAA5555AAAAull);
    reference.content_digest = sha256_domain("pcp/probe-evidence/v1", spec.first);
    references.push_back(reference);
  }
  return EvidenceBinding::create(std::move(references), Limits::defaults());
}

Result<PowerPolicy> fixed_policy() {
  std::vector<PolicyRule> rules;
  for (const auto& spec :
       {std::pair<const char*, ActionKind>{"allow-open", ActionKind::open_breaker},
        std::pair<const char*, ActionKind>{"allow-close", ActionKind::close_breaker},
        std::pair<const char*, ActionKind>{"allow-transfer", ActionKind::transfer_source},
        std::pair<const char*, ActionKind>{"allow-degrade", ActionKind::declare_emergency},
        std::pair<const char*, ActionKind>{"allow-restore", ActionKind::restore_normal},
        std::pair<const char*, ActionKind>{"allow-isolate", ActionKind::isolate_bus}}) {
    PolicyRule rule;
    rule.id = RuleId::parse(spec.first).value();
    rule.order = 10;
    rule.condition.kind = PolicyConditionKind::action_kind_is;
    rule.condition.action_kind = spec.second;
    rule.effect = PolicyEffect::allow;
    rule.explanation = "probe policy";
    rules.push_back(std::move(rule));
  }
  return PowerPolicy::create(PolicyRevision(1), std::move(rules), Limits::defaults());
}

Result<MutationRequest> make_request(const FacilityState& state, std::string_view seed) {
  MutationRequest request;
  request.planned.generation = state.generation();
  request.planned.revision = state.revision();
  request.planned.policy_revision = state.policy_revision();
  request.planned.evidence_digest = state.evidence().digest();
  auto key = IdempotencyKey::derive(seed);
  if (!key.has_value()) {
    return key.error();
  }
  request.key = key.value();
  return request;
}

int bootstrap_facility(ControlPlane& plane, WriterLease& lease) {
  auto evidence = fixed_evidence();
  if (!evidence.has_value()) {
    return 1;
  }
  const auto facility = FacilityId::parse("dc1");
  auto key = IdempotencyKey::derive("probe/bootstrap");
  auto decision = plane.bootstrap(lease, facility.value(), OperatingMode::normal,
                                  evidence.value(), key.value());
  if (!decision.has_value()) {
    return 1;
  }
  auto policy = fixed_policy();
  auto state = plane.snapshot();
  if (!state.has_value()) {
    return 1;
  }
  auto request = make_request(state.value().state(), "probe/policy");
  if (!request.has_value()) {
    return 1;
  }
  auto bound = plane.rebind_policy(lease, policy.value(), request.value());
  if (!bound.has_value()) {
    return 1;
  }
  state = plane.snapshot();
  request = make_request(state.value().state(), "probe/revalidate");
  if (!request.has_value()) {
    return 1;
  }
  auto revalidated = plane.revalidate(lease, evidence.value(), request.value());
  if (!revalidated.has_value()) {
    return 1;
  }
  return 0;
}

int verb_acquire_report(const std::string& root) {
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  if (!plane.has_value()) {
    std::cout << "open=error:" << to_string(plane.error().code()) << std::endl;
    return 0;
  }
  auto lease = plane.value().acquire_writer();
  if (!lease.has_value()) {
    std::cout << "acquire=error:" << to_string(lease.error().code()) << std::endl;
    return 0;
  }
  std::cout << "acquire=ok epoch=" << lease.value().epoch().value()
            << " incarnation=" << lease.value().incarnation().to_hex() << std::endl;
  return 0;
}

int verb_hold_and_die(const std::string& root) {
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  if (!plane.has_value()) {
    std::cout << "open=error" << std::endl;
    return 1;
  }
  auto lease = plane.value().acquire_writer();
  if (!lease.has_value()) {
    std::cout << "acquire=error" << std::endl;
    return 1;
  }
  std::cout << "acquired epoch=" << lease.value().epoch().value() << std::endl;
  std::cout.flush();
  std::_Exit(kHoldExitCode);
}

std::uint64_t g_arm_revision = 2;

std::uint64_t argc_arm_revision() { return g_arm_revision; }

int verb_crash(const std::string& root, const std::string& stage_name) {
  auto stage = std::optional<CommitStage>{};
  for (const CommitStage candidate :
       {CommitStage::staging_written, CommitStage::staging_flushed,
        CommitStage::staging_read_back_verified, CommitStage::generation_published,
        CommitStage::head_committed, CommitStage::authority_marked,
        CommitStage::residue_retired}) {
    if (to_string(candidate) == stage_name) {
      stage = candidate;
    }
  }
  if (!stage.has_value()) {
    std::cout << "unknown stage" << std::endl;
    return 2;
  }
  const std::uint64_t arm_revision = argc_arm_revision();
  CrashAtStage observer(stage.value(), arm_revision);
  EngineOptions options;
  options.commit_observer = &observer;
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, options);
  if (!plane.has_value()) {
    std::cout << "open=error" << std::endl;
    return 1;
  }
  auto lease = plane.value().acquire_writer();
  if (!lease.has_value()) {
    std::cout << "acquire=error" << std::endl;
    return 1;
  }
  auto state = plane.value().snapshot();
  if (!state.has_value()) {
    // The store is empty: bootstrap first, in the same process, then crash on the
    // next transition so the crash always happens on a store with authority.
    if (bootstrap_facility(plane.value(), lease.value()) != 0) {
      std::cout << "bootstrap=failed" << std::endl;
      return 1;
    }
    state = plane.value().snapshot();
    if (!state.has_value()) {
      return 1;
    }
  }
  ModeTransitionRequest transition;
  transition.target = state.value().mode() == OperatingMode::normal ? OperatingMode::degraded
                                                                    : OperatingMode::normal;
  transition.authority = AuthorityReference::parse("probe").value();
  auto request = make_request(state.value().state(), "probe/crash-transition");
  if (!request.has_value()) {
    return 1;
  }
  transition.planned = request.value().planned;
  transition.key = request.value().key;
  auto decision = plane.value().request_mode_transition(lease.value(), transition);
  if (!decision.has_value()) {
    std::cout << "transition=error " << decision.error().describe() << std::endl;
    return 1;
  }
  std::cout << "transition=survived" << std::endl;
  return 0;
}

int verb_bootstrap(const std::string& root) {
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  if (!plane.has_value()) {
    return 1;
  }
  auto lease = plane.value().acquire_writer();
  if (!lease.has_value()) {
    std::cout << "acquire=error:" << to_string(lease.error().code()) << std::endl;
    return 1;
  }
  if (bootstrap_facility(plane.value(), lease.value()) != 0) {
    std::cout << "bootstrap=failed" << std::endl;
    return 1;
  }
  auto state = plane.value().snapshot();
  std::cout << "bootstrap=ok revision=" << state.value().revision().value()
            << " mode=" << to_string(state.value().mode()) << std::endl;
  return 0;
}

int verb_read_report(const std::string& root) {
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  if (!plane.has_value()) {
    std::cout << "open=error:" << to_string(plane.error().code()) << std::endl;
    return 0;
  }
  auto status = plane.value().status();
  if (!status.has_value()) {
    std::cout << "status=error" << std::endl;
    return 0;
  }
  std::cout << "revision=" << status.value().revision.value()
            << " generation=" << status.value().generation.value()
            << " mode=" << to_string(status.value().mode)
            << " fresh=" << (status.value().revalidation.evidence_fresh ? 1 : 0)
            << " head=" << (status.value().head.present ? 1 : 0) << std::endl;
  return 0;
}

// Reads the writer authority epoch without taking it, so a test can observe the
// epoch a crashed writer left behind.
int verb_epoch_report(const std::string& root) {
  auto plane = ControlPlane::open(root, StoreOpenMode::read_only, EngineOptions{});
  if (!plane.has_value()) {
    std::cout << "open=error:" << to_string(plane.error().code()) << std::endl;
    return 0;
  }
  std::cout << "epoch=" << plane.value().store().writer_status().epoch.value() << std::endl;
  return 0;
}

int verb_verify(const std::string& root) {
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  if (!plane.has_value()) {
    std::cout << "open=error:" << to_string(plane.error().code()) << std::endl;
    return 1;
  }
  auto integrity = plane.value().verify_store();
  auto replay = plane.value().verify_replay();
  if (!integrity.has_value() || !replay.has_value()) {
    std::cout << "verify=error" << std::endl;
    return 1;
  }
  std::cout << "integrity=" << (integrity.value().ok ? 1 : 0)
            << " replay=" << (replay.value().ok ? 1 : 0)
            << " steps=" << replay.value().steps_checked << std::endl;
  return (integrity.value().ok && replay.value().ok) ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cout << "usage: pcp_probe <verb> <store> [argument]" << std::endl;
    return 2;
  }
  const std::string verb = argv[1];
  const std::string root = argv[2];
  const std::string extra = argc > 3 ? argv[3] : std::string();
  if (verb == "acquire-report") {
    return verb_acquire_report(root);
  }
  if (verb == "hold-and-die") {
    return verb_hold_and_die(root);
  }
  if (verb == "crash") {
    // An optional fourth argument arms the crash at a specific publication revision.
    if (argc > 4) {
      g_arm_revision = std::strtoull(argv[4], nullptr, 10);
    }
    return verb_crash(root, extra);
  }
  if (verb == "bootstrap") {
    return verb_bootstrap(root);
  }
  if (verb == "read-report") {
    return verb_read_report(root);
  }
  if (verb == "epoch-report") {
    return verb_epoch_report(root);
  }
  if (verb == "verify") {
    return verb_verify(root);
  }
  std::cout << "unknown verb" << std::endl;
  return 2;
}
