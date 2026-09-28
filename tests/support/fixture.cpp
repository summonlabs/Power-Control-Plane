#include "fixture.hpp"

#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace pcp_test {

using namespace power_control_plane;

std::string scratch_directory(std::string_view name) {
  std::error_code error;
  const std::filesystem::path path = std::filesystem::current_path() / "pcp-test-state" /
                                     std::string(name);
  std::filesystem::remove_all(path, error);
  std::filesystem::create_directories(path, error);
  return path.string();
}

Result<EvidenceBinding> fixture_evidence(std::uint64_t generation, std::uint64_t revision) {
  std::vector<EvidenceRef> references;
  const std::pair<const char*, EvidenceKind> sources[] = {
      {"power-topology", EvidenceKind::power_topology},
      {"power-capacity", EvidenceKind::power_capacity},
      {"feed-authority", EvidenceKind::feed_authority},
      {"safety-system", EvidenceKind::safety_system},
  };
  for (const auto& source : sources) {
    auto id = EvidenceSourceId::parse(source.first);
    if (!id.has_value()) {
      return id.error();
    }
    EvidenceRef reference;
    reference.source = id.value();
    reference.kind = source.second;
    reference.generation = EvidenceGeneration(generation);
    reference.revision = EvidenceRevision(revision);
    reference.epoch = ControllerEpoch(21);
    reference.incarnation = ControllerIncarnation::from_parts(0x0123456789ABCDEFull,
                                                              0xFEDCBA9876543210ull);
    reference.content_digest =
        sha256_domain("pcp/fixture-evidence/v1", std::string(source.first));
    references.push_back(reference);
  }
  return EvidenceBinding::create(std::move(references), Limits::defaults());
}

Result<PowerPolicy> fixture_policy(PolicyRevision revision, const Limits& limits) {
  std::vector<PolicyRule> rules;
  const std::pair<const char*, ActionKind> allowed[] = {
      {"allow-open-breaker", ActionKind::open_breaker},
      {"allow-close-breaker", ActionKind::close_breaker},
      {"allow-transfer-source", ActionKind::transfer_source},
      {"allow-set-load-limit", ActionKind::set_load_limit},
      {"allow-enter-maintenance", ActionKind::enter_maintenance},
      {"allow-exit-maintenance", ActionKind::exit_maintenance},
      {"allow-isolate-bus", ActionKind::isolate_bus},
      {"allow-restore-bus", ActionKind::restore_bus},
      {"allow-restore-normal", ActionKind::restore_normal},
      {"allow-shed-load-group", ActionKind::shed_load_group},
      {"allow-restore-load-group", ActionKind::restore_load_group},
  };
  std::uint32_t order = 10;
  for (const auto& entry : allowed) {
    auto id = RuleId::parse(entry.first);
    if (!id.has_value()) {
      return id.error();
    }
    PolicyRule rule;
    rule.id = id.value();
    rule.order = order;
    order += 10;
    rule.condition.kind = PolicyConditionKind::action_kind_is;
    rule.condition.action_kind = entry.second;
    rule.effect = PolicyEffect::allow;
    rule.explanation = "fixture policy allows this action kind";
    rules.push_back(std::move(rule));
  }
  auto deny_id = RuleId::parse("deny-declare-emergency");
  if (!deny_id.has_value()) {
    return deny_id.error();
  }
  PolicyRule deny;
  deny.id = deny_id.value();
  deny.order = 5;
  deny.condition.kind = PolicyConditionKind::action_kind_is;
  deny.condition.action_kind = ActionKind::declare_emergency;
  deny.effect = PolicyEffect::deny;
  deny.explanation = "the fixture policy refuses emergency declaration as an action";
  rules.push_back(std::move(deny));
  return PowerPolicy::create(revision, std::move(rules), limits);
}

Result<PowerPolicy> permissive_policy(PolicyRevision revision, const Limits& limits) {
  std::vector<PolicyRule> rules;
  auto id = RuleId::parse("allow-everything");
  if (!id.has_value()) {
    return id.error();
  }
  PolicyRule rule;
  rule.id = id.value();
  rule.order = 0;
  rule.condition.kind = PolicyConditionKind::always;
  rule.effect = PolicyEffect::allow;
  rule.explanation = "deliberately permissive rule";
  rules.push_back(std::move(rule));
  return PowerPolicy::create(revision, std::move(rules), limits);
}

Result<Fixture> Fixture::create(std::string_view name, EngineOptions options) {
  Fixture fixture;
  fixture.root_ = scratch_directory(name);
  auto plane = ControlPlane::open(fixture.root_, StoreOpenMode::read_write, options);
  if (!plane.has_value()) {
    return plane.error();
  }
  fixture.plane_ = std::make_unique<ControlPlane>(std::move(plane).value());
  auto lease = fixture.plane_->acquire_writer();
  if (!lease.has_value()) {
    return lease.error();
  }
  fixture.lease_ = std::make_unique<WriterLease>(lease.value());

  auto evidence = fixture_evidence();
  if (!evidence.has_value()) {
    return evidence.error();
  }
  fixture.evidence_ = evidence.value();

  const auto facility = FacilityId::parse("dc-test");
  auto key = IdempotencyKey::derive("fixture/bootstrap");
  if (!facility.has_value() || !key.has_value()) {
    return Error(ErrorCode::internal_failure, "fixture bootstrap identifiers");
  }
  auto booted = fixture.plane_->bootstrap(*fixture.lease_, facility.value(),
                                          OperatingMode::normal, fixture.evidence_, key.value());
  if (!booted.has_value() || !decision_committed(booted.value().outcome)) {
    return Error(ErrorCode::internal_failure, "fixture bootstrap failed");
  }
  auto policy = fixture_policy(PolicyRevision(1), fixture.plane_->limits());
  if (!policy.has_value()) {
    return policy.error();
  }
  auto state = fixture.plane_->snapshot();
  if (!state.has_value()) {
    return state.error();
  }
  auto policy_request = fixture.request("fixture/policy");
  if (!policy_request.has_value()) {
    return policy_request.error();
  }
  auto bound = fixture.plane_->rebind_policy(*fixture.lease_, policy.value(),
                                             policy_request.value());
  if (!bound.has_value() || !decision_committed(bound.value().outcome)) {
    return Error(ErrorCode::internal_failure, "fixture policy installation failed");
  }
  auto revalidated = fixture.revalidate();
  if (!revalidated.has_value() || !decision_committed(revalidated.value().outcome)) {
    return Error(ErrorCode::internal_failure, "fixture revalidation failed");
  }
  return fixture;
}

Result<MutationRequest> Fixture::request(std::string_view seed) const {
  auto state = plane_->snapshot();
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

Result<ActionIntent> Fixture::intent(std::string_view id, ActionKind kind,
                                     std::string_view target,
                                     std::uint64_t requested_load_kw) const {
  auto state = plane_->snapshot();
  if (!state.has_value()) {
    return state.error();
  }
  ActionIntent built;
  auto action_id = ActionId::parse(id);
  if (!action_id.has_value()) {
    return action_id.error();
  }
  auto target_id = ActionTargetId::parse(target);
  if (!target_id.has_value()) {
    return target_id.error();
  }
  built.id = action_id.value();
  built.kind = kind;
  built.target = target_id.value();
  built.requested_load_kw = requested_load_kw;
  built.planned.generation = state.value().generation();
  built.planned.revision = state.value().revision();
  built.planned.policy_revision = state.value().policy_revision();
  built.planned.evidence_digest = state.value().evidence().digest();
  return built;
}

Result<AuthorizationDecision> Fixture::revalidate() {
  auto request = this->request("fixture/revalidate/" + std::to_string(plane_->store().head().revision.value()));
  if (!request.has_value()) {
    return request.error();
  }
  return plane_->revalidate(*lease_, evidence_, request.value());
}

Result<AuthorizationDecision> Fixture::grant(
    const std::vector<ActionKind>& kinds, const std::vector<std::string>& targets,
    std::uint32_t max_uses, std::uint64_t generation_lifetime, std::uint64_t revision_lifetime) {
  auto state = plane_->snapshot();
  if (!state.has_value()) {
    return state.error();
  }
  PermissionGrant grant;
  grant.kinds = kinds;
  for (const std::string& target : targets) {
    auto parsed = ActionTargetId::parse(target);
    if (!parsed.has_value()) {
      return parsed.error();
    }
    grant.targets.push_back(parsed.value());
  }
  grant.granted_by = AuthorityReference::parse("test-supervisor").value();
  grant.max_uses = max_uses;
  grant.issued_generation = state.value().generation();
  grant.issued_revision = state.value().revision();
  auto expiry_generation =
      checked_add(grant.issued_generation.value(), generation_lifetime);
  auto expiry_revision = checked_add(grant.issued_revision.value(), revision_lifetime);
  if (!expiry_generation.has_value() || !expiry_revision.has_value()) {
    return Error(ErrorCode::arithmetic_overflow, "fixture permission lifetime");
  }
  grant.expiry_generation = ControlGeneration(expiry_generation.value());
  grant.expiry_revision = StateRevision(expiry_revision.value());
  grant.policy_revision = state.value().policy_revision();
  grant.evidence = state.value().evidence();
  auto request = this->request("fixture/permission/" + std::to_string(state.value().revision().value()));
  if (!request.has_value()) {
    return request.error();
  }
  return plane_->grant_permission(*lease_, grant, request.value());
}

Result<AuthorizationDecision> Fixture::transition_to(
    OperatingMode target, std::vector<ObligationSuspension> suspensions) {
  auto state = plane_->snapshot();
  if (!state.has_value()) {
    return state.error();
  }
  ModeTransitionRequest request;
  request.target = target;
  request.authority = AuthorityReference::parse("test-supervisor").value();
  request.suspensions = std::move(suspensions);
  auto built = this->request("fixture/mode/" + std::string(to_string(target)) + "/" +
                             std::to_string(state.value().revision().value()));
  if (!built.has_value()) {
    return built.error();
  }
  request.planned = built.value().planned;
  request.key = built.value().key;
  return plane_->request_mode_transition(*lease_, request);
}

Result<AuthorizationDecision> Fixture::authorize(const ActionIntent& intent,
                                                 std::string_view seed) {
  auto request = this->request(seed);
  if (!request.has_value()) {
    return request.error();
  }
  return plane_->authorize_action(*lease_, intent, request.value());
}

void Fixture::close() {
  if (lease_ && plane_) {
    static_cast<void>(plane_->release_writer(*lease_));
  }
  if (plane_) {
    plane_->close();
  }
}

}  // namespace pcp_test
