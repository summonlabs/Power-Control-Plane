#include <algorithm>
#include <string>

#include "power_control_plane/adapter.hpp"
#include "power_control_plane/attempt.hpp"
#include "power_control_plane/canonical.hpp"
#include "power_control_plane/decision.hpp"
#include "power_control_plane/interlock.hpp"
#include "power_control_plane/mode.hpp"
#include "power_control_plane/obligation.hpp"
#include "power_control_plane/permission.hpp"
#include "power_control_plane/version.hpp"

// Deterministic model rules: what an operating mode means, which transitions are
// legal, when an interlock blocks, when a permission is usable, and how a request
// is structurally validated. Everything in this file is pure: no state, no I/O, no
// ordering dependence.

namespace power_control_plane {

const Limits& Limits::defaults() noexcept {
  static const Limits kLimits{};
  return kLimits;
}

std::string_view control_plane_version() noexcept { return kVersionString; }

namespace {

// Restrictiveness rank of an operating mode. Movement to a strictly higher rank in
// the fail-safe set (degraded, failover, emergency, isolated) is a deterioration
// record and is never blocked by missing evidence or missing permission: refusing
// to record a deterioration would be the less safe behaviour.
constexpr int mode_rank(OperatingMode mode) noexcept {
  switch (mode) {
    case OperatingMode::normal:
      return 0;
    case OperatingMode::maintenance:
      return 1;
    case OperatingMode::degraded:
      return 2;
    case OperatingMode::failover:
      return 3;
    case OperatingMode::emergency:
      return 4;
    case OperatingMode::isolated:
      return 5;
  }
  return 0;
}

constexpr bool is_deterioration_mode(OperatingMode mode) noexcept {
  return mode == OperatingMode::degraded || mode == OperatingMode::failover ||
         mode == OperatingMode::emergency || mode == OperatingMode::isolated;
}

constexpr std::uint8_t ordinal(ActionKind kind) noexcept {
  return static_cast<std::uint8_t>(kind);
}

using Rule = ModeTransitionRule;

constexpr Rule kModeTransitions[] = {
    {ModeTransitionId::enter_maintenance, OperatingMode::normal, OperatingMode::maintenance,
     true, true, ordinal(ActionKind::enter_maintenance), true, false,
     "normal to maintenance requires current evidence, an explicit maintenance "
     "permission, and a plan for every continuity-required obligation"},
    {ModeTransitionId::exit_maintenance, OperatingMode::maintenance, OperatingMode::normal,
     true, true, ordinal(ActionKind::exit_maintenance), false, false,
     "maintenance to normal requires current evidence and an exit permission"},
    {ModeTransitionId::degrade, OperatingMode::normal, OperatingMode::degraded, false, false, 0,
     false, false, "deterioration record: never blocked"},
    {ModeTransitionId::degrade, OperatingMode::maintenance, OperatingMode::degraded, false,
     false, 0, false, false, "deterioration record: never blocked"},
    {ModeTransitionId::recover_from_degraded, OperatingMode::degraded, OperatingMode::normal,
     true, true, ordinal(ActionKind::restore_normal), true, false,
     "degraded to normal requires current evidence, a restore permission, and a plan "
     "for every continuity-required obligation"},
    {ModeTransitionId::enter_failover, OperatingMode::normal, OperatingMode::failover, true,
     true, ordinal(ActionKind::transfer_source), true, false,
     "normal to failover requires current evidence, a transfer permission, and an "
     "obligation plan"},
    {ModeTransitionId::enter_failover, OperatingMode::maintenance, OperatingMode::failover,
     true, true, ordinal(ActionKind::transfer_source), true, false,
     "maintenance to failover requires current evidence, a transfer permission, and an "
     "obligation plan"},
    {ModeTransitionId::enter_failover, OperatingMode::degraded, OperatingMode::failover, false,
     false, 0, false, false, "deterioration record: never blocked"},
    {ModeTransitionId::exit_failover, OperatingMode::failover, OperatingMode::normal, true,
     true, ordinal(ActionKind::restore_normal), true, true,
     "leaving failover requires post-event revalidation, current evidence, a restore "
     "permission, and an obligation plan"},
    {ModeTransitionId::degrade, OperatingMode::failover, OperatingMode::degraded, false, false,
     0, false, false, "deterioration record: never blocked"},
    {ModeTransitionId::declare_emergency, OperatingMode::normal, OperatingMode::emergency,
     false, false, 0, false, false, "deterioration record: never blocked"},
    {ModeTransitionId::declare_emergency, OperatingMode::maintenance, OperatingMode::emergency,
     false, false, 0, false, false, "deterioration record: never blocked"},
    {ModeTransitionId::declare_emergency, OperatingMode::degraded, OperatingMode::emergency,
     false, false, 0, false, false, "deterioration record: never blocked"},
    {ModeTransitionId::declare_emergency, OperatingMode::failover, OperatingMode::emergency,
     false, false, 0, false, false, "deterioration record: never blocked"},
    {ModeTransitionId::exit_emergency, OperatingMode::emergency, OperatingMode::degraded, true,
     false, 0, false, true,
     "leaving emergency requires post-event revalidation and current evidence"},
    {ModeTransitionId::exit_emergency, OperatingMode::emergency, OperatingMode::failover, true,
     true, ordinal(ActionKind::transfer_source), false, true,
     "leaving emergency into failover requires post-event revalidation, current "
     "evidence, and a transfer permission"},
    {ModeTransitionId::exit_emergency, OperatingMode::emergency, OperatingMode::normal, true,
     true, ordinal(ActionKind::restore_normal), true, true,
     "leaving emergency into normal requires post-event revalidation, current evidence, a "
     "restore permission, and an obligation plan"},
    {ModeTransitionId::isolate, OperatingMode::normal, OperatingMode::isolated, true, true,
     ordinal(ActionKind::isolate_bus), true, false,
     "isolation requires current evidence, an isolation permission, and an obligation "
     "plan"},
    {ModeTransitionId::isolate, OperatingMode::maintenance, OperatingMode::isolated, true, true,
     ordinal(ActionKind::isolate_bus), true, false,
     "isolation requires current evidence, an isolation permission, and an obligation "
     "plan"},
    {ModeTransitionId::isolate, OperatingMode::degraded, OperatingMode::isolated, true, true,
     ordinal(ActionKind::isolate_bus), true, false,
     "isolation requires current evidence, an isolation permission, and an obligation "
     "plan"},
    {ModeTransitionId::isolate, OperatingMode::failover, OperatingMode::isolated, true, true,
     ordinal(ActionKind::isolate_bus), true, false,
     "isolation requires current evidence, an isolation permission, and an obligation "
     "plan"},
    {ModeTransitionId::isolate, OperatingMode::emergency, OperatingMode::isolated, false, false,
     0, false, false, "deterioration record: never blocked"},
    {ModeTransitionId::isolate, OperatingMode::isolated, OperatingMode::emergency, false, false,
     0, false, false, "deterioration record: never blocked"},
    {ModeTransitionId::restore_from_isolation, OperatingMode::isolated, OperatingMode::normal,
     true, true, ordinal(ActionKind::restore_normal), true, true,
     "leaving isolation requires post-event revalidation, current evidence, a restore "
     "permission, and an obligation plan"},
};

}  // namespace

const ModeTransitionRule* find_mode_transition(OperatingMode from,
                                               OperatingMode to) noexcept {
  for (const Rule& rule : kModeTransitions) {
    if (rule.from == from && rule.to == to) {
      return &rule;
    }
  }
  return nullptr;
}

bool is_fail_safe_direction(OperatingMode from, OperatingMode to) noexcept {
  if (!is_deterioration_mode(to)) {
    return false;
  }
  return mode_rank(to) > mode_rank(from);
}

bool is_physical_action(ActionKind kind) noexcept {
  return kind != ActionKind::revalidate_evidence;
}

Status validate_intent_structure(const ActionIntent& intent, const Limits& limits) {
  static_cast<void>(limits);
  if (intent.id.empty()) {
    return Status::failure(ErrorCode::invalid_argument, "action id is not set");
  }
  if (intent.target.empty()) {
    return Status::failure(ErrorCode::invalid_argument, "action target is not set");
  }
  // Declared demand bound. This is a documented physical bound, not a policy: a
  // request above one terawatt is refused as malformed rather than clamped, so a
  // typo can never silently become a smaller demand.
  constexpr std::uint64_t kMaximumDeclaredDemandKw = 1'000'000'000ull;
  if (intent.requested_load_kw > kMaximumDeclaredDemandKw) {
    return Status::failure(ErrorCode::invalid_argument,
                           "declared demand exceeds the physical bound of 1 TW");
  }
  if (intent.kind == ActionKind::revalidate_evidence && intent.requested_load_kw != 0) {
    return Status::failure(ErrorCode::invalid_argument,
                           "evidence revalidation cannot declare a demand");
  }
  return Status::success();
}

Result<ActionId> make_action_id(std::string_view tag) { return ActionId::parse(tag); }

bool interlock_blocks(const Interlock& interlock, ActionKind kind,
                      const ActionTargetId& target) noexcept {
  if (interlock.severity == InterlockSeverity::advisory) {
    return false;
  }
  if (interlock.state == InterlockState::cleared) {
    return false;
  }
  // An empty scope means "all kinds" and "all targets": an interlock whose scope
  // could not be determined covers everything rather than nothing.
  const bool kind_matches = interlock.scope_kinds.empty() ||
                            std::find(interlock.scope_kinds.begin(),
                                      interlock.scope_kinds.end(),
                                      kind) != interlock.scope_kinds.end();
  if (!kind_matches) {
    return false;
  }
  if (interlock.scope_targets.empty()) {
    return true;
  }
  return std::find(interlock.scope_targets.begin(), interlock.scope_targets.end(),
                   target) != interlock.scope_targets.end();
}

bool obligation_in_scope(const ProtectedObligation& obligation, ActionKind kind,
                         const ActionTargetId& target) noexcept {
  const bool kind_matches =
      obligation.scope_kinds.empty() ||
      std::find(obligation.scope_kinds.begin(), obligation.scope_kinds.end(), kind) !=
          obligation.scope_kinds.end();
  if (!kind_matches) {
    return false;
  }
  if (obligation.scope_targets.empty()) {
    return true;
  }
  return std::find(obligation.scope_targets.begin(), obligation.scope_targets.end(),
                   target) != obligation.scope_targets.end();
}

bool obligation_requires_service(const ProtectedObligation& obligation, ActionKind kind,
                                 const ActionTargetId& target) noexcept {
  if (!obligation.continuity_required) {
    return false;
  }
  if (obligation.state != ObligationState::active) {
    return false;
  }
  return obligation_in_scope(obligation, kind, target);
}

bool permission_covers(const PermissionGrant& grant, ActionKind kind,
                       const ActionTargetId& target) noexcept {
  const bool kind_matches =
      std::find(grant.kinds.begin(), grant.kinds.end(), kind) != grant.kinds.end();
  if (!kind_matches) {
    return false;
  }
  if (grant.targets.empty()) {
    return true;
  }
  return std::find(grant.targets.begin(), grant.targets.end(), target) !=
         grant.targets.end();
}

bool permission_within_lifetime(const PermissionGrant& grant,
                                ControlGeneration current_generation,
                                StateRevision current_revision) noexcept {
  if (current_generation < grant.issued_generation ||
      current_generation >= grant.expiry_generation) {
    return false;
  }
  return current_revision >= grant.issued_revision &&
         current_revision < grant.expiry_revision;
}

std::optional<PermissionRejection> permission_rejection(
    const PermissionGrant& grant, ActionKind kind, const ActionTargetId& target,
    ControlGeneration current_generation, StateRevision current_revision) noexcept {
  // Fixed evaluation order so the reported reason is deterministic when a grant is
  // unusable for several reasons at once.
  if (grant.state == PermissionState::revoked) {
    return PermissionRejection::revoked;
  }
  if (grant.state == PermissionState::superseded) {
    return PermissionRejection::superseded;
  }
  if (grant.state == PermissionState::exhausted || grant.uses >= grant.max_uses) {
    return PermissionRejection::exhausted;
  }
  if (current_generation < grant.issued_generation ||
      current_revision < grant.issued_revision) {
    return PermissionRejection::not_yet_issued;
  }
  if (!permission_within_lifetime(grant, current_generation, current_revision)) {
    return PermissionRejection::expired;
  }
  if (!permission_covers(grant, kind, target)) {
    return PermissionRejection::scope_mismatch;
  }
  return std::nullopt;
}

Digest command_digest(const IssuedCommand& command) {
  CanonicalWriter writer;
  writer.u64(command.attempt.value());
  if (!writer.text(command.action.view(), ActionId::kMaxLength).ok() ||
      !writer.text(command.target.view(), ActionTargetId::kMaxLength).ok()) {
    return Digest::zero();
  }
  writer.u8(static_cast<std::uint8_t>(command.kind));
  writer.u64(command.generation.value());
  writer.u64(command.revision.value());
  const Bytes payload = writer.take();
  return sha256_domain("pcp/issued-command/v1", payload.data(), payload.size());
}

namespace {

std::string_view subject_kind_text(SubjectKind kind) noexcept {
  switch (kind) {
    case SubjectKind::none:
      return "none";
    case SubjectKind::rule:
      return "rule";
    case SubjectKind::interlock:
      return "interlock";
    case SubjectKind::obligation:
      return "obligation";
    case SubjectKind::commitment:
      return "commitment";
    case SubjectKind::permission:
      return "permission";
    case SubjectKind::evidence_source:
      return "evidence_source";
    case SubjectKind::attempt:
      return "attempt";
    case SubjectKind::action:
      return "action";
    case SubjectKind::mode:
      return "mode";
  }
  return "none";
}

}  // namespace

std::string describe_decision(const AuthorizationDecision& decision, const Limits& limits) {
  std::string out;
  out.reserve(256);
  out.append("outcome=");
  out.append(to_string(decision.outcome));
  out.append(" generation=");
  out.append(std::to_string(decision.authoritative_generation.value()));
  out.append(" revision=");
  out.append(std::to_string(decision.authoritative_revision.value()));
  out.append(" policy=");
  out.append(std::to_string(decision.policy_revision.value()));
  out.append(" evidence=");
  out.append(decision.evidence_digest.to_hex());
  out.append(" planned_generation=");
  out.append(std::to_string(decision.planned_generation.value()));
  if (decision.attempt.has_value()) {
    out.append(" attempt=");
    out.append(std::to_string(decision.attempt->value()));
  }
  out.push_back('\n');

  const std::size_t step_limit = limits.max_explanation_steps;
  std::size_t emitted = 0;
  for (const ExplanationStep& step : decision.steps) {
    if (emitted >= step_limit) {
      out.append("  ... explanation trace truncated by Limits::max_explanation_steps\n");
      break;
    }
    out.append("  ");
    out.append(to_string(step.code));
    out.push_back(' ');
    out.append(subject_kind_text(step.subject.kind));
    out.push_back(':');
    out.append(step.subject.id.substr(0, limits.max_identifier_length));
    if (!step.detail.empty()) {
      out.append(" | ");
      out.append(step.detail.substr(0, limits.max_explanation_detail_bytes));
    }
    out.push_back('\n');
    ++emitted;
  }
  return out;
}

}  // namespace power_control_plane
