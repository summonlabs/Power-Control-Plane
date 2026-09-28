// Out-of-tree consumer of the installed Power Control Plane package.
//
// This program is not part of the Power Control Plane build tree. It is configured
// separately with CMAKE_PREFIX_PATH pointing at an install prefix and links only
// against the exported target PowerControlPlane::power_control_plane.
//
// It exercises the documented lifecycle end to end: create a durable store,
// bootstrap a facility, install a policy, revalidate evidence, grant a permission,
// authorize and drive an action through a deterministic adapter, close, reopen,
// prove that recovered evidence is not fresh, revalidate, and verify the store.

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

#include "power_control_plane/engine.hpp"
#include "power_control_plane/version.hpp"

namespace {

using namespace power_control_plane;

int fail(const std::string& message) {
  std::cerr << "consumer failed: " << message << '\n';
  return 1;
}

Result<EvidenceBinding> consumer_evidence() {
  std::vector<EvidenceRef> references;
  const std::pair<const char*, EvidenceKind> sources[] = {
      {"power-topology", EvidenceKind::power_topology},
      {"power-capacity", EvidenceKind::power_capacity},
  };
  for (const auto& source : sources) {
    EvidenceRef reference;
    reference.source = EvidenceSourceId::parse(source.first).value();
    reference.kind = source.second;
    reference.generation = EvidenceGeneration(3);
    reference.revision = EvidenceRevision(1);
    reference.epoch = ControllerEpoch(2);
    reference.incarnation = ControllerIncarnation::from_parts(0x0102030405060708ull,
                                                              0x1112131415161718ull);
    reference.content_digest = sha256_domain("pcp/consumer-evidence/v1", source.first);
    references.push_back(reference);
  }
  return EvidenceBinding::create(std::move(references), Limits::defaults());
}

Result<PowerPolicy> consumer_policy(const Limits& limits) {
  std::vector<PolicyRule> rules;
  auto id = RuleId::parse("allow-close-breaker");
  if (!id.has_value()) {
    return id.error();
  }
  PolicyRule rule;
  rule.id = id.value();
  rule.order = 10;
  rule.condition.kind = PolicyConditionKind::action_kind_is;
  rule.condition.action_kind = ActionKind::close_breaker;
  rule.effect = PolicyEffect::allow;
  rule.explanation = "the consumer policy authorizes breaker closing";
  rules.push_back(std::move(rule));
  return PowerPolicy::create(PolicyRevision(1), std::move(rules), limits);
}

Result<MutationRequest> consumer_request(const ControlPlane& plane, std::string_view seed) {
  auto snapshot = plane.snapshot();
  if (!snapshot.has_value()) {
    return snapshot.error();
  }
  MutationRequest request;
  request.planned.generation = snapshot.value().generation();
  request.planned.revision = snapshot.value().revision();
  request.planned.policy_revision = snapshot.value().policy_revision();
  request.planned.evidence_digest = snapshot.value().evidence().digest();
  auto key = IdempotencyKey::derive(seed);
  if (!key.has_value()) {
    return key.error();
  }
  request.key = key.value();
  return request;
}

int run(const std::string& root) {
  EngineOptions options;
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, options);
  if (!plane.has_value()) {
    return fail(plane.error().describe());
  }
  std::cout << "power control plane " << kVersionString << ", store format "
            << kStoreFormatVersion << '\n';

  auto lease = plane.value().acquire_writer();
  if (!lease.has_value()) {
    return fail(lease.error().describe());
  }
  auto evidence = consumer_evidence();
  auto policy = consumer_policy(plane.value().limits());
  if (!evidence.has_value() || !policy.has_value()) {
    return fail("fixture construction failed");
  }
  if (!plane.value().store().head().present) {
    auto booted = plane.value().bootstrap(lease.value(), FacilityId::parse("consumer-dc").value(),
                                          OperatingMode::normal, evidence.value(),
                                          IdempotencyKey::derive("consumer/bootstrap").value());
    if (!booted.has_value() || !decision_committed(booted.value().outcome)) {
      return fail("bootstrap was refused");
    }
    auto policy_request = consumer_request(plane.value(), "consumer/policy");
    if (!policy_request.has_value()) {
      return fail(policy_request.error().describe());
    }
    auto bound = plane.value().rebind_policy(lease.value(), policy.value(),
                                             policy_request.value());
    if (!bound.has_value() || !decision_committed(bound.value().outcome)) {
      return fail("policy installation was refused");
    }
  }

  auto revalidate_request = consumer_request(plane.value(), "consumer/revalidate");
  if (!revalidate_request.has_value()) {
    return fail(revalidate_request.error().describe());
  }
  auto revalidated = plane.value().revalidate(lease.value(), evidence.value(),
                                              revalidate_request.value());
  if (!revalidated.has_value() || !decision_committed(revalidated.value().outcome)) {
    return fail("revalidation was refused");
  }

  auto snapshot = plane.value().snapshot();
  if (!snapshot.has_value()) {
    return fail(snapshot.error().describe());
  }
  PermissionGrant grant;
  grant.kinds.push_back(ActionKind::close_breaker);
  grant.granted_by = AuthorityReference::parse("consumer-supervisor").value();
  grant.max_uses = 2;
  grant.issued_generation = snapshot.value().generation();
  grant.issued_revision = snapshot.value().revision();
  grant.expiry_generation = ControlGeneration(snapshot.value().generation().value() + 4);
  grant.expiry_revision = StateRevision(snapshot.value().revision().value() + 64);
  grant.policy_revision = snapshot.value().policy_revision();
  grant.evidence = snapshot.value().evidence();
  auto grant_request = consumer_request(plane.value(), "consumer/permission");
  if (!grant_request.has_value()) {
    return fail(grant_request.error().describe());
  }
  auto granted = plane.value().grant_permission(lease.value(), grant, grant_request.value());
  if (!granted.has_value() || !decision_committed(granted.value().outcome)) {
    return fail("permission grant was refused");
  }

  snapshot = plane.value().snapshot();
  ActionIntent intent;
  intent.id = ActionId::parse("consumer-close-b1").value();
  intent.kind = ActionKind::close_breaker;
  intent.target = ActionTargetId::parse("bus-b1").value();
  intent.planned.generation = snapshot.value().generation();
  intent.planned.revision = snapshot.value().revision();
  intent.planned.policy_revision = snapshot.value().policy_revision();
  intent.planned.evidence_digest = snapshot.value().evidence().digest();
  auto attempt_request = consumer_request(plane.value(), "consumer/attempt");
  if (!attempt_request.has_value()) {
    return fail(attempt_request.error().describe());
  }
  SimulationAdapter adapter(AdapterId::parse("consumer-adapter").value(),
                            SimulationBehaviour::full_success);
  ActuationOutcome outcome;
  auto decision = plane.value().actuate(lease.value(), intent, attempt_request.value(), adapter,
                                        outcome);
  if (!decision.has_value()) {
    return fail(decision.error().describe());
  }
  if (!decision_committed(decision.value().outcome)) {
    std::cout << describe_decision(decision.value(), plane.value().limits());
    return fail("the action was refused");
  }
  std::cout << "authorized attempt " << outcome.attempt.value() << ", final state "
            << to_string(outcome.final_state) << ", verified=" << (outcome.verified ? 1 : 0)
            << '\n';
  std::cout << "actuation evidence is SYNTHETIC (deterministic simulator)\n";

  auto integrity = plane.value().verify_store();
  auto replay = plane.value().verify_replay();
  if (!integrity.has_value() || !integrity.value().ok) {
    return fail("store integrity verification failed");
  }
  if (!replay.has_value() || !replay.value().ok) {
    return fail("deterministic replay verification failed");
  }
  std::cout << "integrity ok, replay ok over " << replay.value().steps_checked << " steps\n";

  static_cast<void>(plane.value().release_writer(lease.value()));
  plane.value().close();

  // Reopen: recovered evidence is a binding, never a freshness claim.
  auto reopened = ControlPlane::open(root, StoreOpenMode::read_write, options);
  if (!reopened.has_value()) {
    return fail(reopened.error().describe());
  }
  const RevalidationReport freshness = reopened.value().revalidation_status();
  if (freshness.evidence_fresh) {
    return fail("recovery reported persisted evidence as fresh");
  }
  std::cout << "after reopen: evidence fresh=0 (" << freshness.detail << ")\n";
  auto status = reopened.value().status();
  if (!status.has_value()) {
    return fail(status.error().describe());
  }
  std::cout << "final revision " << status.value().revision.value() << ", generation "
            << status.value().generation.value() << ", mode " << to_string(status.value().mode)
            << ", attempts " << status.value().attempt_count << '\n';
  std::cout << "state digest " << status.value().state_digest.to_hex() << '\n';
  reopened.value().close();
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  const std::string root = argc > 1 ? argv[1] : "consumer-store";
  std::error_code error;
  std::filesystem::remove_all(root, error);
  const int code = run(root);
  std::filesystem::remove_all(root, error);
  if (code == 0) {
    std::cout << "consumer lifecycle completed\n";
  }
  return code;
}
