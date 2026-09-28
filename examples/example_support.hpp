#pragma once

// Shared helpers for the Power Control Plane examples.
//
// The examples are ordinary library clients. They use only the installed public
// API; nothing here reaches into internal headers or bypasses the engine.

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/engine.hpp"

namespace pcp_examples {

using namespace power_control_plane;

inline void line(const std::string& text) { std::cout << text << '\n'; }

inline void heading(const std::string& text) {
  line("");
  line("== " + text + " ==");
}

inline int fail(const std::string& text) {
  std::cerr << "example failed: " << text << '\n';
  return 1;
}

// A deterministic evidence binding. Fixed generation, revision, epoch, and
// incarnation keep example output reproducible across runs, which is what makes an
// example useful as a regression signal.
inline Result<EvidenceBinding> make_evidence(std::string_view source, EvidenceKind kind,
                                             std::uint64_t generation,
                                             std::uint64_t revision) {
  EvidenceRef reference;
  auto id = EvidenceSourceId::parse(source);
  if (!id.has_value()) {
    return id.error();
  }
  reference.source = id.value();
  reference.kind = kind;
  reference.generation = EvidenceGeneration(generation);
  reference.revision = EvidenceRevision(revision);
  reference.epoch = ControllerEpoch(7);
  reference.incarnation = ControllerIncarnation::from_parts(0x0123456789ABCDEFull,
                                                            0xFEDCBA9876543210ull);
  reference.content_digest = sha256_domain("pcp/example-evidence/v1",
                                           std::string(source) + "/" +
                                               std::to_string(generation) + "/" +
                                               std::to_string(revision));
  std::vector<EvidenceRef> references;
  references.push_back(reference);
  return EvidenceBinding::create(std::move(references), Limits::defaults());
}

inline Result<EvidenceBinding> merge_evidence(const EvidenceBinding& first,
                                              const EvidenceBinding& second,
                                              const Limits& limits) {
  std::vector<EvidenceRef> references = first.refs();
  for (const EvidenceRef& reference : second.refs()) {
    references.push_back(reference);
  }
  return EvidenceBinding::create(std::move(references), limits);
}

// A policy that authorizes the normal operating vocabulary and refuses everything
// else by default. The rules are ordered and the trace is complete, so the same
// request always produces the same explanation.
inline Result<PowerPolicy> make_baseline_policy(PolicyRevision revision,
                                                const Limits& limits) {
  std::vector<PolicyRule> rules;
  const auto add_allow = [&rules](std::string_view id_text, std::uint32_t order,
                                  ActionKind kind, std::string explanation) -> Status {
    auto id = RuleId::parse(id_text);
    if (!id.has_value()) {
      return Status(id.error());
    }
    PolicyRule rule;
    rule.id = id.value();
    rule.order = order;
    rule.condition.kind = PolicyConditionKind::action_kind_is;
    rule.condition.action_kind = kind;
    rule.effect = PolicyEffect::allow;
    rule.explanation = std::move(explanation);
    rules.push_back(std::move(rule));
    return Status::success();
  };

  PCP_TRY_STATUS(add_allow("allow-open-breaker", 10, ActionKind::open_breaker,
                           "breaker opening is authorized when every other stage passes"));
  PCP_TRY_STATUS(add_allow("allow-close-breaker", 20, ActionKind::close_breaker,
                           "breaker closing is authorized when every other stage passes"));
  PCP_TRY_STATUS(add_allow("allow-transfer", 30, ActionKind::transfer_source,
                           "source transfer is authorized when every other stage passes"));
  PCP_TRY_STATUS(add_allow("allow-restore-normal", 40, ActionKind::restore_normal,
                           "returning to normal supply is authorized when every other stage "
                           "passes"));
  PCP_TRY_STATUS(add_allow("allow-enter-maintenance", 50, ActionKind::enter_maintenance,
                           "entering maintenance is authorized when every other stage passes"));
  PCP_TRY_STATUS(add_allow("allow-exit-maintenance", 60, ActionKind::exit_maintenance,
                           "leaving maintenance is authorized when every other stage passes"));
  PCP_TRY_STATUS(add_allow("allow-isolate", 70, ActionKind::isolate_bus,
                           "isolation is authorized when every other stage passes"));
  PCP_TRY_STATUS(add_allow("allow-shed", 80, ActionKind::shed_load_group,
                           "shedding a load group is authorized when every other stage "
                           "passes"));
  PCP_TRY_STATUS(add_allow("allow-restore-load", 90, ActionKind::restore_load_group,
                           "restoring a load group is authorized when every other stage "
                           "passes"));

  // An explicit deny rule for emergency declaration: this runtime never executes a
  // black-start sequence, and declaring an emergency from an isolated facility is
  // refused by policy in addition to being absent from the mode transition table.
  auto deny_id = RuleId::parse("deny-declare-emergency-while-isolated");
  if (!deny_id.has_value()) {
    return deny_id.error();
  }
  PolicyRule deny;
  deny.id = deny_id.value();
  deny.order = 5;
  deny.condition.kind = PolicyConditionKind::action_kind_is;
  deny.condition.action_kind = ActionKind::declare_emergency;
  deny.effect = PolicyEffect::deny;
  deny.explanation =
      "emergency declaration is not an action this runtime authorizes; use the mode "
      "transition verb, which records a deterioration without granting actuation";
  rules.push_back(std::move(deny));

  return PowerPolicy::create(revision, std::move(rules), limits);
}

inline ActionIntent make_intent(const FacilityState& state, std::string_view action,
                                ActionKind kind, std::string_view target) {
  ActionIntent intent;
  auto id = ActionId::parse(action);
  if (id.has_value()) {
    intent.id = id.value();
  }
  intent.kind = kind;
  auto target_id = ActionTargetId::parse(target);
  if (target_id.has_value()) {
    intent.target = target_id.value();
  }
  intent.planned.generation = state.generation();
  intent.planned.revision = state.revision();
  intent.planned.policy_revision = state.policy_revision();
  intent.planned.evidence_digest = state.evidence().digest();
  return intent;
}

inline Result<MutationRequest> make_request(const FacilityState& state,
                                            std::string_view seed) {
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

inline void show_decision(const Limits& limits, const AuthorizationDecision& decision) {
  std::cout << describe_decision(decision, limits);
}

}  // namespace pcp_examples
