// Example: authorization, acknowledgement, and verified effect are separate facts.
//
// Every step is published as its own authoritative revision, so the recorded state
// can distinguish "the control plane permitted this", "the command was handed to an
// adapter", "the adapter acknowledged receipt", "an effect was observed", and "an
// independent check confirmed the intended state".
//
// All evidence produced here is SYNTHETIC: it comes from a deterministic simulator.
// Nothing in this repository has been validated against electrical hardware.

#include <cstddef>
#include <filesystem>
#include <iostream>
#include <string>

#include "example_support.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_examples;

struct Scenario {
  std::string name;
  SimulationBehaviour behaviour;
};

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
  auto topology = make_evidence("power-topology", EvidenceKind::power_topology, 44, 6);
  auto capacity = make_evidence("power-capacity", EvidenceKind::power_capacity, 44, 6);
  if (!topology.has_value() || !capacity.has_value()) {
    return fail("evidence construction failed");
  }
  auto binding = merge_evidence(topology.value(), capacity.value(), limits);
  if (!binding.has_value()) {
    return fail(binding.error().describe());
  }
  const auto facility = FacilityId::parse("dc1");
  auto boot_key = IdempotencyKey::derive("adapter/bootstrap");
  auto booted = plane.value().bootstrap(lease.value(), facility.value(), OperatingMode::normal,
                                        binding.value(), boot_key.value());
  if (!booted.has_value()) {
    return fail(booted.error().describe());
  }
  auto policy = make_baseline_policy(PolicyRevision(1), limits);
  auto state = plane.value().snapshot();
  auto policy_request = make_request(state.value().state(), "adapter/policy");
  if (!policy.has_value() || !policy_request.has_value()) {
    return fail("policy construction failed");
  }
  auto policy_decision =
      plane.value().rebind_policy(lease.value(), policy.value(), policy_request.value());
  if (!policy_decision.has_value()) {
    return fail(policy_decision.error().describe());
  }
  state = plane.value().snapshot();
  auto revalidate_request = make_request(state.value().state(), "adapter/revalidate");
  auto revalidated =
      plane.value().revalidate(lease.value(), binding.value(), revalidate_request.value());
  if (!revalidated.has_value()) {
    return fail(revalidated.error().describe());
  }

  const Scenario scenarios[] = {
      {"full success", SimulationBehaviour::full_success},
      {"acknowledgement without effect", SimulationBehaviour::acknowledge_only},
      {"adapter refuses the command", SimulationBehaviour::refuse_command},
      {"effect contradicts the intent", SimulationBehaviour::effect_contradicts_intent},
      {"no independent verification", SimulationBehaviour::effect_unverified},
  };
  const std::size_t scenario_count = sizeof(scenarios) / sizeof(scenarios[0]);

  for (std::size_t index = 0; index < scenario_count; ++index) {
    const Scenario& scenario = scenarios[index];
    heading(scenario.name);
    state = plane.value().snapshot();
    const std::string target = "bus-" + std::to_string(index);
    PermissionGrant grant;
    grant.kinds.push_back(ActionKind::close_breaker);
    auto target_id = ActionTargetId::parse(target);
    if (!target_id.has_value()) {
      return fail(target_id.error().describe());
    }
    grant.targets.push_back(target_id.value());
    grant.granted_by = AuthorityReference::parse("shift-supervisor").value();
    grant.max_uses = 1;
    grant.issued_generation = state.value().generation();
    grant.issued_revision = state.value().revision();
    grant.expiry_generation = ControlGeneration(state.value().generation().value() + 8);
    grant.expiry_revision = StateRevision(state.value().revision().value() + 128);
    grant.policy_revision = state.value().policy_revision();
    grant.evidence = state.value().evidence();
    auto grant_request =
        make_request(state.value().state(), "adapter/permission/" + std::to_string(index));
    auto grant_decision =
        plane.value().grant_permission(lease.value(), grant, grant_request.value());
    if (!grant_decision.has_value() || !decision_committed(grant_decision.value().outcome)) {
      return fail("the scenario permission could not be granted");
    }

    state = plane.value().snapshot();
    const ActionIntent intent =
        make_intent(state.value().state(), "close-breaker-" + std::to_string(index),
                    ActionKind::close_breaker, target);
    auto attempt_request =
        make_request(state.value().state(), "adapter/attempt/" + std::to_string(index));
    if (!attempt_request.has_value()) {
      return fail(attempt_request.error().describe());
    }
    // The verifier is a different adapter identity, which is what makes the
    // verification independent of the acknowledgement.
    SimulationAdapter adapter(AdapterId::parse("adapter-a").value(), scenario.behaviour);
    SimulationAdapter verifier(AdapterId::parse("verifier-b").value(), scenario.behaviour);
    ActuationOutcome outcome;
    auto decision = plane.value().actuate(lease.value(), intent, attempt_request.value(), adapter,
                                          outcome);
    if (!decision.has_value()) {
      return fail(decision.error().describe());
    }
    line("authorization committed: " +
         std::string(decision_committed(decision.value().outcome) ? "yes" : "no"));
    line("command issued: " + std::string(outcome.command_issued ? "yes" : "no"));
    line("acknowledged: " + std::string(outcome.acknowledged ? "yes" : "no"));
    line("effect observed: " + std::string(outcome.effect_observed ? "yes" : "no"));
    line("verified: " + std::string(outcome.verified ? "yes" : "no"));
    line("final attempt state: " + std::string(to_string(outcome.final_state)));
    line("detail: " + outcome.detail);
    static_cast<void>(verifier);

    auto after = plane.value().snapshot();
    const AttemptRecord* record = after.value().state().find_attempt(outcome.attempt);
    if (record == nullptr) {
      return fail("the attempt was not recorded");
    }
    line("acknowledgement recorded: " +
         std::string(record->acknowledgement.has_value() ? "yes" : "no"));
    line("observed effect recorded: " +
         std::string(record->effect.has_value() ? "yes" : "no"));
    line("verification recorded: " +
         std::string(record->verification.has_value() ? "yes" : "no"));
    line("SYNTHETIC evidence: produced by a deterministic simulator, not by hardware");
  }

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
  const std::string root = argc > 1 ? argv[1] : "example-adapter-store";
  std::error_code error;
  std::filesystem::remove_all(root, error);
  const int code = run(root);
  std::filesystem::remove_all(root, error);
  return code;
}
