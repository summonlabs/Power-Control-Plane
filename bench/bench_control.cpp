// Completed-operation benchmark.
//
// Every scenario times only completed operations. The timed region of a mutation
// includes validation, canonical encoding, the staging write, the required durable
// flush, read-back verification, the atomic generation publish, the authoritative
// head-marker commit, the rollback-fence advance, and residue retirement. Nothing
// here times enqueue or submission latency and calls it completion.
//
// All results are labelled REAL: the durable work is performed against the real
// file system of the host, and the actuation evidence comes from the deterministic
// simulator (so the actuation semantics are SYNTHETIC while the store work is REAL).
//
// The benchmark removes its own store root before and after the run.

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

#include "power_control_plane/engine.hpp"
#include "power_control_plane/version.hpp"

namespace {

using namespace power_control_plane;

struct Measurement {
  std::string name;
  std::string label;
  std::uint64_t operations = 0;
  double total_seconds = 0.0;
  std::string note;
};

std::vector<Measurement> g_measurements;

class Stopwatch {
 public:
  void start() { started_ = std::chrono::steady_clock::now(); }
  [[nodiscard]] double seconds() const {
    const auto finished = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(finished - started_).count();
  }

 private:
  std::chrono::steady_clock::time_point started_{};
};

void report(const std::string& name, const std::string& label, std::uint64_t operations,
            double seconds, const std::string& note) {
  Measurement measurement;
  measurement.name = name;
  measurement.label = label;
  measurement.operations = operations;
  measurement.total_seconds = seconds;
  measurement.note = note;
  g_measurements.push_back(std::move(measurement));
  const double per_operation =
      operations == 0 ? 0.0 : (seconds * 1e6) / static_cast<double>(operations);
  const double throughput = seconds <= 0.0 ? 0.0 : static_cast<double>(operations) / seconds;
  std::cout << std::left << std::setw(34) << name << std::setw(10) << label << std::right
            << std::setw(9) << operations << " ops  " << std::fixed << std::setprecision(3)
            << std::setw(9) << seconds << " s  " << std::setprecision(2) << std::setw(11)
            << per_operation << " us/op " << std::setprecision(1) << std::setw(10)
            << throughput << " ops/s\n";
}

Result<EvidenceBinding> benchmark_evidence() {
  std::vector<EvidenceRef> references;
  const std::pair<const char*, EvidenceKind> sources[] = {
      {"power-topology", EvidenceKind::power_topology},
      {"power-capacity", EvidenceKind::power_capacity},
      {"feed-authority", EvidenceKind::feed_authority},
      {"safety-system", EvidenceKind::safety_system},
      {"pdu-device", EvidenceKind::pdu_device},
      {"ups-device", EvidenceKind::ups_device},
  };
  for (const auto& source : sources) {
    EvidenceRef reference;
    reference.source = EvidenceSourceId::parse(source.first).value();
    reference.kind = source.second;
    reference.generation = EvidenceGeneration(100);
    reference.revision = EvidenceRevision(7);
    reference.epoch = ControllerEpoch(9);
    reference.incarnation = ControllerIncarnation::from_parts(0x1111222233334444ull,
                                                              0x5555666677778888ull);
    reference.content_digest = sha256_domain("pcp/bench-evidence/v1", source.first);
    references.push_back(reference);
  }
  return EvidenceBinding::create(std::move(references), Limits::defaults());
}

Result<PowerPolicy> benchmark_policy() {
  std::vector<PolicyRule> rules;
  std::uint32_t order = 10;
  for (const auto& kind :
       {ActionKind::open_breaker, ActionKind::close_breaker, ActionKind::transfer_source,
        ActionKind::set_load_limit, ActionKind::enter_maintenance,
        ActionKind::exit_maintenance, ActionKind::isolate_bus, ActionKind::restore_bus,
        ActionKind::restore_normal, ActionKind::shed_load_group,
        ActionKind::restore_load_group}) {
    PolicyRule rule;
    rule.id = RuleId::parse("allow-" + std::to_string(order)).value();
    rule.order = order;
    order += 10;
    rule.condition.kind = PolicyConditionKind::action_kind_is;
    rule.condition.action_kind = kind;
    rule.effect = PolicyEffect::allow;
    rule.explanation = "benchmark policy";
    rules.push_back(std::move(rule));
  }
  return PowerPolicy::create(PolicyRevision(1), std::move(rules), Limits::defaults());
}

Result<MutationRequest> make_request(const ControlPlane& plane, std::string_view seed) {
  auto state = plane.snapshot();
  if (!state.has_value()) {
    return state.error();
  }
  MutationRequest request;
  request.planned.generation = state.value().generation();
  request.planned.revision = state.value().revision();
  request.planned.policy_revision = state.value().policy_revision();
  request.planned.evidence_digest = state.value().evidence().digest();
  auto key = IdempotencyKey::derive(seed);
  if (!key.has_value()) {
    return key.error();
  }
  request.key = key.value();
  return request;
}

Result<ActionIntent> make_intent(const ControlPlane& plane, std::string_view id,
                                 ActionKind kind, std::string_view target,
                                 std::uint64_t load_kw) {
  auto state = plane.snapshot();
  if (!state.has_value()) {
    return state.error();
  }
  ActionIntent intent;
  intent.id = ActionId::parse(id).value();
  intent.kind = kind;
  intent.target = ActionTargetId::parse(target).value();
  intent.requested_load_kw = load_kw;
  intent.planned.generation = state.value().generation();
  intent.planned.revision = state.value().revision();
  intent.planned.policy_revision = state.value().policy_revision();
  intent.planned.evidence_digest = state.value().evidence().digest();
  return intent;
}

Result<AuthorizationDecision> grant_permission(ControlPlane& plane, WriterLease& lease,
                                               const std::vector<ActionKind>& kinds,
                                               const std::vector<std::string>& targets,
                                               std::uint32_t uses, std::uint64_t revisions) {
  auto state = plane.snapshot();
  if (!state.has_value()) {
    return state.error();
  }
  PermissionGrant grant;
  grant.kinds = kinds;
  for (const std::string& target : targets) {
    grant.targets.push_back(ActionTargetId::parse(target).value());
  }
  grant.granted_by = AuthorityReference::parse("benchmark").value();
  grant.max_uses = uses;
  grant.issued_generation = state.value().generation();
  grant.issued_revision = state.value().revision();
  grant.expiry_generation = ControlGeneration(state.value().generation().value() + 1000000);
  grant.expiry_revision = StateRevision(state.value().revision().value() + revisions);
  grant.policy_revision = state.value().policy_revision();
  grant.evidence = state.value().evidence();
  auto request = make_request(plane, "bench/grant/" + std::to_string(state.value().revision().value()));
  if (!request.has_value()) {
    return request.error();
  }
  return plane.grant_permission(lease, grant, request.value());
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t scale = 1;
  std::string root = "pcp-bench-store";
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--scale" && index + 1 < argc) {
      scale = std::strtoull(argv[++index], nullptr, 10);
    } else if (argument == "--root" && index + 1 < argc) {
      root = argv[++index];
    }
  }
  if (scale == 0) {
    scale = 1;
  }

  std::error_code error;
  std::filesystem::remove_all(root, error);

  std::cout << "Power Control Plane " << kVersionString << " completed-operation benchmark\n";
  std::cout << "store format version: " << kStoreFormatVersion
            << ", state encoding version: " << kStateFormatVersion << "\n";
  std::cout << "compiler: "
#if defined(_MSC_VER)
            << "MSVC " << _MSC_VER
#elif defined(__clang__)
            << "Clang " << __clang_major__ << '.' << __clang_minor__
#elif defined(__GNUC__)
            << "GCC " << __GNUC__ << '.' << __GNUC_MINOR__
#else
            << "unknown"
#endif
            << ", C++ standard: " << __cplusplus << "\n";
  std::cout << "build type: "
#if defined(NDEBUG)
            << "release (NDEBUG)"
#else
            << "debug (assertions enabled)"
#endif
            << "\n";
  std::cout << "scale multiplier: " << scale << ", store root: " << root << "\n";
  std::cout << "durable filesystem: real host file system\n\n";
  std::cout << std::left << std::setw(34) << "scenario" << std::setw(10) << "label"
            << std::right << std::setw(13) << "completed" << std::setw(13) << "wall"
            << std::setw(18) << "per operation" << std::setw(16) << "throughput" << '\n';

  EngineOptions options;
  options.retained_publications = 8;
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, options);
  if (!plane.has_value()) {
    std::cerr << "open failed: " << plane.error().describe() << '\n';
    return 1;
  }
  auto lease = plane.value().acquire_writer();
  if (!lease.has_value()) {
    std::cerr << "writer authority failed: " << lease.error().describe() << '\n';
    return 1;
  }
  auto evidence = benchmark_evidence();
  auto policy = benchmark_policy();
  if (!evidence.has_value() || !policy.has_value()) {
    std::cerr << "fixture construction failed\n";
    return 1;
  }

  // Setup: bootstrap, policy, revalidation, and the permission pool. Setup is not
  // measured; each scenario below states exactly what it completed.
  auto booted = plane.value().bootstrap(lease.value(), FacilityId::parse("bench").value(),
                                        OperatingMode::normal, evidence.value(),
                                        IdempotencyKey::derive("bench/bootstrap").value());
  if (!booted.has_value() || !decision_committed(booted.value().outcome)) {
    std::cerr << "bootstrap failed\n";
    return 1;
  }
  auto policy_request = make_request(plane.value(), "bench/policy");
  auto bound = plane.value().rebind_policy(lease.value(), policy.value(), policy_request.value());
  if (!bound.has_value() || !decision_committed(bound.value().outcome)) {
    std::cerr << "policy installation failed\n";
    return 1;
  }
  auto revalidate_request = make_request(plane.value(), "bench/revalidate");
  auto revalidated = plane.value().revalidate(lease.value(), evidence.value(),
                                              revalidate_request.value());
  if (!revalidated.has_value() || !decision_committed(revalidated.value().outcome)) {
    std::cerr << "revalidation failed\n";
    return 1;
  }

  const std::vector<ActionKind> all_kinds = {
      ActionKind::open_breaker, ActionKind::close_breaker, ActionKind::restore_normal,
      ActionKind::isolate_bus, ActionKind::enter_maintenance, ActionKind::exit_maintenance,
      ActionKind::transfer_source, ActionKind::restore_bus, ActionKind::shed_load_group,
      ActionKind::restore_load_group, ActionKind::set_load_limit};
  auto permission_pool = grant_permission(plane.value(), lease.value(), all_kinds,
                                          std::vector<std::string>{}, 4000000u, 40000000u);
  if (!permission_pool.has_value() || !decision_committed(permission_pool.value().outcome)) {
    std::cerr << "permission pool creation failed\n";
    return 1;
  }

  // 1. Canonical encoding and digest of the authoritative state.
  {
    auto snapshot = plane.value().snapshot();
    if (!snapshot.has_value()) {
      return 1;
    }
    const std::uint64_t operations = 2000ull * scale;
    Stopwatch watch;
    watch.start();
    Digest sink;
    for (std::uint64_t index = 0; index < operations; ++index) {
      sink = snapshot.value().state().canonical_digest();
    }
    const double seconds = watch.seconds();
    report("canonical encode + SHA-256", "REAL", operations, seconds,
           "digest sink " + sink.to_hex().substr(0, 8));
  }

  // 2. Full proposed-action evaluation with no publication.
  {
    const std::uint64_t operations = 5000ull * scale;
    auto intent = make_intent(plane.value(), "bench-evaluate", ActionKind::close_breaker,
                              "bus-a", 0);
    if (!intent.has_value()) {
      return 1;
    }
    Stopwatch watch;
    watch.start();
    std::size_t accepted = 0;
    for (std::uint64_t index = 0; index < operations; ++index) {
      auto decision = plane.value().evaluate_action(intent.value());
      if (!decision.has_value()) {
        return 1;
      }
      if (decision.value().outcome == DecisionOutcome::accepted) {
        ++accepted;
      }
    }
    const double seconds = watch.seconds();
    report("evaluate_action (no publish)", "REAL", operations, seconds,
           std::to_string(accepted) + " accepted");
    if (accepted != operations) {
      std::cerr << "evaluate_action did not accept every evaluation\n";
      return 1;
    }
  }

  // 3. Authorization with a full durable publication.
  {
    const std::uint64_t operations = 200ull * scale;
    Stopwatch watch;
    watch.start();
    std::uint64_t committed = 0;
    for (std::uint64_t index = 0; index < operations; ++index) {
      auto intent = make_intent(plane.value(), "bench-auth-" + std::to_string(index),
                                ActionKind::close_breaker, "bus-a", 0);
      auto request = make_request(plane.value(), "bench/auth/" + std::to_string(index));
      if (!intent.has_value() || !request.has_value()) {
        return 1;
      }
      auto decision =
          plane.value().authorize_action(lease.value(), intent.value(), request.value());
      if (!decision.has_value()) {
        std::cerr << "authorize failed: " << decision.error().describe() << '\n';
        return 1;
      }
      if (decision_committed(decision.value().outcome)) {
        ++committed;
      }
    }
    const double seconds = watch.seconds();
    report("authorize_action + durable commit", "REAL", operations, seconds,
           std::to_string(committed) + " committed");
    if (committed != operations) {
      std::cerr << "not every authorization committed\n";
      return 1;
    }
  }

  // 4. Operating mode transition with a full durable publication.
  {
    const std::uint64_t operations = 200ull * scale;
    Stopwatch watch;
    watch.start();
    std::uint64_t committed = 0;
    for (std::uint64_t index = 0; index < operations; ++index) {
      auto state = plane.value().snapshot();
      if (!state.has_value()) {
        return 1;
      }
      ModeTransitionRequest request;
      request.target = state.value().mode() == OperatingMode::normal ? OperatingMode::degraded
                                                                    : OperatingMode::normal;
      request.authority = AuthorityReference::parse("benchmark").value();
      auto built = make_request(plane.value(), "bench/mode/" + std::to_string(index));
      if (!built.has_value()) {
        return 1;
      }
      request.planned = built.value().planned;
      request.key = built.value().key;
      auto decision = plane.value().request_mode_transition(lease.value(), request);
      if (!decision.has_value()) {
        std::cerr << "mode transition failed: " << decision.error().describe() << '\n';
        return 1;
      }
      if (decision_committed(decision.value().outcome)) {
        ++committed;
      } else {
        std::cerr << "mode transition refused: " << describe_decision(decision.value(),
                                                                      plane.value().limits());
        return 1;
      }
    }
    const double seconds = watch.seconds();
    report("mode transition + durable commit", "REAL", operations, seconds,
           std::to_string(committed) + " committed");
  }

  // 5. Full attempt lifecycle through the deterministic simulator. Each of the six
  //    published facts is a separate durable commit.
  {
    const std::uint64_t operations = 40ull * scale;
    Stopwatch watch;
    watch.start();
    std::uint64_t verified = 0;
    for (std::uint64_t index = 0; index < operations; ++index) {
      auto intent = make_intent(plane.value(), "bench-attempt-" + std::to_string(index),
                                ActionKind::close_breaker, "bus-a", 0);
      auto request = make_request(plane.value(), "bench/attempt/" + std::to_string(index));
      if (!intent.has_value() || !request.has_value()) {
        return 1;
      }
      SimulationAdapter adapter(AdapterId::parse("bench-adapter").value(),
                                SimulationBehaviour::full_success);
      ActuationOutcome outcome;
      auto decision = plane.value().actuate(lease.value(), intent.value(), request.value(),
                                            adapter, outcome);
      if (!decision.has_value()) {
        std::cerr << "actuate failed: " << decision.error().describe() << '\n';
        return 1;
      }
      if (outcome.verified) {
        ++verified;
      }
    }
    const double seconds = watch.seconds();
    report("attempt lifecycle (6 commits)", "REAL", operations, seconds,
           std::to_string(verified) + " verified, SYNTHETIC actuation evidence");
    if (verified != operations) {
      std::cerr << "not every attempt reached verified\n";
      return 1;
    }
  }

  // 6. Store integrity verification.
  {
    const std::uint64_t operations = 50ull * scale;
    Stopwatch watch;
    watch.start();
    bool ok = true;
    for (std::uint64_t index = 0; index < operations; ++index) {
      auto integrity = plane.value().verify_store();
      if (!integrity.has_value() || !integrity.value().ok) {
        ok = false;
        break;
      }
    }
    const double seconds = watch.seconds();
    report("verify_store integrity check", "REAL", operations, seconds,
           ok ? "all checks passed" : "FAILED");
    if (!ok) {
      std::cerr << "store integrity verification failed\n";
      return 1;
    }
  }

  // 7. Deterministic replay verification across the retained publications.
  {
    const std::uint64_t operations = 20ull * scale;
    Stopwatch watch;
    watch.start();
    std::size_t steps = 0;
    bool ok = true;
    for (std::uint64_t index = 0; index < operations; ++index) {
      auto replay = plane.value().verify_replay();
      if (!replay.has_value() || !replay.value().ok) {
        ok = false;
        break;
      }
      steps = replay.value().steps_checked;
    }
    const double seconds = watch.seconds();
    report("verify_replay deterministic replay", "REAL", operations, seconds,
           std::to_string(steps) + " steps per run");
    if (!ok) {
      std::cerr << "deterministic replay verification failed\n";
      return 1;
    }
  }

  auto status = plane.value().status();
  if (!status.has_value()) {
    return 1;
  }
  std::cout << "\nfinal: generation " << status.value().generation.value() << ", revision "
            << status.value().revision.value() << ", mode "
            << to_string(status.value().mode) << ", interlock "
            << status.value().interlock_count << ", attempts " << status.value().attempt_count
            << '\n';
  std::cout << "final state digest: " << status.value().state_digest.to_hex() << '\n';
  static_cast<void>(plane.value().release_writer(lease.value()));
  plane.value().close();

  std::filesystem::remove_all(root, error);
  std::cout << "benchmark residue removed: " << root << '\n';
  return 0;
}
