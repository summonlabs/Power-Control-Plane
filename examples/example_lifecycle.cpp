// Example: clean startup, authoritative state, and an operating mode transition.
//
// Demonstrates: bootstrap of a facility control generation, policy installation,
// evidence revalidation, permission issuance, a mode transition that preserves a
// protected obligation, an authorized action, and store verification.

#include <filesystem>
#include <iostream>
#include <string>

#include "example_support.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_examples;

int run(const std::string& root) {
  heading("startup");
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
  line("writer authority epoch " + std::to_string(lease.value().epoch().value()) +
       " incarnation " + lease.value().incarnation().to_hex());

  auto topology = make_evidence("power-topology", EvidenceKind::power_topology, 12, 4);
  auto capacity = make_evidence("power-capacity", EvidenceKind::power_capacity, 9, 2);
  if (!topology.has_value() || !capacity.has_value()) {
    return fail("evidence construction failed");
  }
  auto binding = merge_evidence(topology.value(), capacity.value(), limits);
  if (!binding.has_value()) {
    return fail(binding.error().describe());
  }

  const auto facility = FacilityId::parse("dc1");
  auto key = IdempotencyKey::derive("example/bootstrap");
  if (!facility.has_value() || !key.has_value()) {
    return fail("identifier construction failed");
  }
  auto booted = plane.value().bootstrap(lease.value(), facility.value(), OperatingMode::normal,
                                        binding.value(), key.value());
  if (!booted.has_value()) {
    return fail(booted.error().describe());
  }
  show_decision(limits, booted.value());

  heading("policy installation");
  auto policy = make_baseline_policy(PolicyRevision(1), limits);
  if (!policy.has_value()) {
    return fail(policy.error().describe());
  }
  auto state = plane.value().snapshot();
  if (!state.has_value()) {
    return fail(state.error().describe());
  }
  auto policy_request = make_request(state.value().state(), "example/policy-1");
  if (!policy_request.has_value()) {
    return fail(policy_request.error().describe());
  }
  auto policy_decision =
      plane.value().rebind_policy(lease.value(), policy.value(), policy_request.value());
  if (!policy_decision.has_value()) {
    return fail(policy_decision.error().describe());
  }
  show_decision(limits, policy_decision.value());

  heading("evidence revalidation");
  state = plane.value().snapshot();
  auto revalidate_request = make_request(state.value().state(), "example/revalidate-1");
  if (!revalidate_request.has_value()) {
    return fail(revalidate_request.error().describe());
  }
  auto revalidated =
      plane.value().revalidate(lease.value(), binding.value(), revalidate_request.value());
  if (!revalidated.has_value()) {
    return fail(revalidated.error().describe());
  }
  show_decision(limits, revalidated.value());
  const RevalidationReport freshness = plane.value().revalidation_status();
  line("evidence fresh: " + std::string(freshness.evidence_fresh ? "yes" : "no"));
  line("freshness detail: " + freshness.detail);

  heading("protected obligation and capacity commitment");
  state = plane.value().snapshot();
  ProtectedObligation obligation;
  auto obligation_id = ObligationId::parse("life-safety-continuity");
  if (!obligation_id.has_value()) {
    return fail("obligation identifier construction failed");
  }
  obligation.id = obligation_id.value();
  obligation.authority_source = EvidenceSourceId::parse("facility-capacity").value();
  obligation.authority_reference = AuthorityReference::parse("obligation-charter-7").value();
  obligation.scope_kinds.push_back(ActionKind::open_breaker);
  obligation.scope_kinds.push_back(ActionKind::isolate_bus);
  obligation.scope_targets.push_back(ActionTargetId::parse("bus-life-safety").value());
  obligation.continuity_required = true;
  obligation.description = "life safety distribution must remain energized";
  auto obligation_request = make_request(state.value().state(), "example/obligation-1");
  if (!obligation_request.has_value()) {
    return fail(obligation_request.error().describe());
  }
  auto obligation_decision = plane.value().record_obligation(
      lease.value(), obligation, obligation_request.value());
  if (!obligation_decision.has_value()) {
    return fail(obligation_decision.error().describe());
  }
  show_decision(limits, obligation_decision.value());

  heading("permission issuance and mode transition");
  state = plane.value().snapshot();
  PermissionGrant grant;
  grant.kinds.push_back(ActionKind::enter_maintenance);
  grant.kinds.push_back(ActionKind::exit_maintenance);
  grant.kinds.push_back(ActionKind::open_breaker);
  grant.granted_by = AuthorityReference::parse("shift-supervisor").value();
  grant.max_uses = 4;
  grant.issued_generation = state.value().generation();
  grant.issued_revision = state.value().revision();
  grant.expiry_generation = ControlGeneration(state.value().generation().value() + 2);
  grant.expiry_revision = StateRevision(state.value().revision().value() + 16);
  grant.policy_revision = state.value().policy_revision();
  grant.evidence = state.value().evidence();
  auto grant_request = make_request(state.value().state(), "example/permission-1");
  if (!grant_request.has_value()) {
    return fail(grant_request.error().describe());
  }
  auto grant_decision =
      plane.value().grant_permission(lease.value(), grant, grant_request.value());
  if (!grant_decision.has_value()) {
    return fail(grant_decision.error().describe());
  }
  show_decision(limits, grant_decision.value());

  state = plane.value().snapshot();
  ModeTransitionRequest transition;
  transition.target = OperatingMode::maintenance;
  transition.authority = AuthorityReference::parse("shift-supervisor").value();
  auto transition_request = make_request(state.value().state(), "example/mode-maintenance");
  if (!transition_request.has_value()) {
    return fail(transition_request.error().describe());
  }
  transition.planned = transition_request.value().planned;
  transition.key = transition_request.value().key;
  auto transition_decision =
      plane.value().request_mode_transition(lease.value(), transition);
  if (!transition_decision.has_value()) {
    return fail(transition_decision.error().describe());
  }
  show_decision(limits, transition_decision.value());

  heading("action refused by a protected obligation");
  state = plane.value().snapshot();
  const ActionIntent protected_intent =
      make_intent(state.value().state(), "open-breaker-life-safety",
                  ActionKind::open_breaker, "bus-life-safety");
  auto protected_request = make_request(state.value().state(), "example/open-life-safety");
  if (!protected_request.has_value()) {
    return fail(protected_request.error().describe());
  }
  auto protected_decision =
      plane.value().authorize_action(lease.value(), protected_intent, protected_request.value());
  if (!protected_decision.has_value()) {
    return fail(protected_decision.error().describe());
  }
  show_decision(limits, protected_decision.value());
  if (protected_decision.value().outcome != DecisionOutcome::blocked_by_obligation) {
    return fail("a destructive action on a continuity-required obligation must be refused");
  }

  heading("authorized action outside the obligation scope");
  state = plane.value().snapshot();
  const ActionIntent intent = make_intent(state.value().state(), "open-breaker-a1",
                                          ActionKind::open_breaker, "bus-a");
  auto action_request = make_request(state.value().state(), "example/open-breaker-a1");
  if (!action_request.has_value()) {
    return fail(action_request.error().describe());
  }
  auto action_decision =
      plane.value().authorize_action(lease.value(), intent, action_request.value());
  if (!action_decision.has_value()) {
    return fail(action_decision.error().describe());
  }
  show_decision(limits, action_decision.value());

  heading("verification");
  auto integrity = plane.value().verify_store();
  if (!integrity.has_value()) {
    return fail(integrity.error().describe());
  }
  line("store integrity ok: " + std::string(integrity.value().ok ? "yes" : "no"));
  auto replay = plane.value().verify_replay();
  if (!replay.has_value()) {
    return fail(replay.error().describe());
  }
  line("deterministic replay ok: " + std::string(replay.value().ok ? "yes" : "no") +
       " steps=" + std::to_string(replay.value().steps_checked));

  auto status = plane.value().status();
  if (!status.has_value()) {
    return fail(status.error().describe());
  }
  line("final mode: " + std::string(to_string(status.value().mode)));
  line("final generation: " + std::to_string(status.value().generation.value()));
  line("final revision: " + std::to_string(status.value().revision.value()));
  line("final state digest: " + status.value().state_digest.to_hex());

  const Status released = plane.value().release_writer(lease.value());
  if (!released.ok()) {
    return fail(released.error().describe());
  }
  plane.value().close();
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  const std::string root = argc > 1 ? argv[1] : "example-lifecycle-store";
  std::error_code error;
  std::filesystem::remove_all(root, error);
  const int code = run(root);
  std::filesystem::remove_all(root, error);
  return code;
}
