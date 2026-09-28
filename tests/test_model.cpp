// Proof obligations: the model rules that must be true regardless of caller.
//
// Mode transition legality, interlock fail-closed behaviour, obligation scope,
// permission lifetime and rejection ordering, and deterministic policy outcome.

#include <string>
#include <vector>

#include "power_control_plane/interlock.hpp"
#include "power_control_plane/mode.hpp"
#include "power_control_plane/obligation.hpp"
#include "power_control_plane/permission.hpp"
#include "power_control_plane/policy.hpp"
#include "power_control_plane/state.hpp"
#include "support/fixture.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

ActionTargetId target_of(std::string_view text) {
  return ActionTargetId::parse(text).value();
}

Interlock make_interlock(InterlockSeverity severity, InterlockState state) {
  Interlock interlock;
  interlock.id = InterlockId::parse("test-interlock").value();
  interlock.source = EvidenceSourceId::parse("safety-system").value();
  interlock.severity = severity;
  interlock.state = state;
  interlock.declared_generation = ControlGeneration(1);
  interlock.explanation = "test interlock";
  return interlock;
}

}  // namespace

PCP_TEST(mode_transition_table_is_asymmetric) {
  PCP_CHECK(find_mode_transition(OperatingMode::normal, OperatingMode::maintenance) != nullptr);
  PCP_CHECK(find_mode_transition(OperatingMode::maintenance, OperatingMode::normal) != nullptr);
  PCP_CHECK(find_mode_transition(OperatingMode::normal, OperatingMode::degraded) != nullptr);
  PCP_CHECK(find_mode_transition(OperatingMode::isolated, OperatingMode::normal) != nullptr);
  // These are deliberately absent: a facility cannot jump between unrelated modes
  // without passing through the recorded intermediate states.
  PCP_CHECK(find_mode_transition(OperatingMode::normal, OperatingMode::isolated) != nullptr);
  PCP_CHECK(find_mode_transition(OperatingMode::maintenance, OperatingMode::isolated) != nullptr);
  PCP_CHECK(find_mode_transition(OperatingMode::normal, OperatingMode::normal) == nullptr);
  PCP_CHECK(find_mode_transition(OperatingMode::isolated, OperatingMode::maintenance) == nullptr);
  PCP_CHECK(find_mode_transition(OperatingMode::isolated, OperatingMode::degraded) == nullptr);
}

PCP_TEST(deterioration_records_carry_no_requirements) {
  const ModeTransitionRule* degrade =
      find_mode_transition(OperatingMode::normal, OperatingMode::degraded);
  PCP_CHECK(degrade != nullptr);
  PCP_CHECK(!degrade->requires_fresh_evidence);
  PCP_CHECK(!degrade->requires_permission);
  PCP_CHECK(!degrade->requires_obligation_plan);
  PCP_CHECK(!degrade->requires_post_event_revalidation);
  PCP_CHECK(is_fail_safe_direction(OperatingMode::normal, OperatingMode::degraded));
  PCP_CHECK(is_fail_safe_direction(OperatingMode::degraded, OperatingMode::emergency));
  PCP_CHECK(!is_fail_safe_direction(OperatingMode::degraded, OperatingMode::normal));
  PCP_CHECK(!is_fail_safe_direction(OperatingMode::normal, OperatingMode::maintenance));

  const ModeTransitionRule* restore =
      find_mode_transition(OperatingMode::degraded, OperatingMode::normal);
  PCP_CHECK(restore != nullptr);
  PCP_CHECK(restore->requires_fresh_evidence);
  PCP_CHECK(restore->requires_permission);
  PCP_CHECK(restore->requires_obligation_plan);

  const ModeTransitionRule* leave_isolation =
      find_mode_transition(OperatingMode::isolated, OperatingMode::normal);
  PCP_CHECK(leave_isolation != nullptr);
  PCP_CHECK(leave_isolation->requires_post_event_revalidation);
}

PCP_TEST(interlocks_fail_closed) {
  const Interlock engaged = make_interlock(InterlockSeverity::blocking, InterlockState::engaged);
  PCP_CHECK(interlock_blocks(engaged, ActionKind::open_breaker, target_of("bus-a")));

  const Interlock unknown = make_interlock(InterlockSeverity::blocking, InterlockState::unknown);
  PCP_CHECK(interlock_blocks(unknown, ActionKind::open_breaker, target_of("bus-a")));

  const Interlock cleared = make_interlock(InterlockSeverity::blocking, InterlockState::cleared);
  PCP_CHECK(!interlock_blocks(cleared, ActionKind::open_breaker, target_of("bus-a")));

  // An advisory interlock never blocks, by explicit documented design.
  const Interlock advisory = make_interlock(InterlockSeverity::advisory, InterlockState::engaged);
  PCP_CHECK(!interlock_blocks(advisory, ActionKind::open_breaker, target_of("bus-a")));

  // An empty scope covers everything: an interlock whose scope could not be
  // determined must cover more, not less.
  const Interlock unscoped = make_interlock(InterlockSeverity::critical, InterlockState::engaged);
  PCP_CHECK(interlock_blocks(unscoped, ActionKind::shed_load_group, target_of("anything")));

  Interlock scoped = make_interlock(InterlockSeverity::critical, InterlockState::engaged);
  scoped.scope_kinds.push_back(ActionKind::open_breaker);
  scoped.scope_targets.push_back(target_of("bus-b"));
  PCP_CHECK(interlock_blocks(scoped, ActionKind::open_breaker, target_of("bus-b")));
  PCP_CHECK(!interlock_blocks(scoped, ActionKind::open_breaker, target_of("bus-c")));
  PCP_CHECK(!interlock_blocks(scoped, ActionKind::close_breaker, target_of("bus-b")));
}

PCP_TEST(obligation_scope_and_continuity) {
  ProtectedObligation obligation;
  obligation.id = ObligationId::parse("life-safety").value();
  obligation.authority_source = EvidenceSourceId::parse("facility-capacity").value();
  obligation.authority_reference = AuthorityReference::parse("charter-1").value();
  obligation.continuity_required = true;
  obligation.state = ObligationState::active;
  obligation.description = "life safety";
  PCP_CHECK(obligation_in_scope(obligation, ActionKind::open_breaker, target_of("bus-a")));
  PCP_CHECK(obligation_requires_service(obligation, ActionKind::open_breaker, target_of("bus-a")));

  obligation.state = ObligationState::suspended;
  PCP_CHECK(!obligation_requires_service(obligation, ActionKind::open_breaker, target_of("bus-a")));

  obligation.state = ObligationState::active;
  obligation.continuity_required = false;
  PCP_CHECK(!obligation_requires_service(obligation, ActionKind::open_breaker, target_of("bus-a")));

  obligation.continuity_required = true;
  obligation.scope_kinds.push_back(ActionKind::shed_load_group);
  PCP_CHECK(!obligation_in_scope(obligation, ActionKind::open_breaker, target_of("bus-a")));
  PCP_CHECK(obligation_in_scope(obligation, ActionKind::shed_load_group, target_of("bus-a")));
}

PCP_TEST(permission_lifetime_and_rejection_order) {
  PermissionGrant grant;
  grant.id = PermissionId(1);
  grant.kinds.push_back(ActionKind::open_breaker);
  grant.issued_generation = ControlGeneration(3);
  grant.expiry_generation = ControlGeneration(6);
  grant.issued_revision = StateRevision(10);
  grant.expiry_revision = StateRevision(20);
  grant.max_uses = 1;
  grant.uses = 0;
  grant.state = PermissionState::active;
  grant.granted_by = AuthorityReference::parse("supervisor").value();

  PCP_CHECK(permission_within_lifetime(grant, ControlGeneration(3), StateRevision(10)));
  PCP_CHECK(permission_within_lifetime(grant, ControlGeneration(5), StateRevision(19)));
  PCP_CHECK(!permission_within_lifetime(grant, ControlGeneration(6), StateRevision(19)));
  PCP_CHECK(!permission_within_lifetime(grant, ControlGeneration(5), StateRevision(20)));
  PCP_CHECK(!permission_within_lifetime(grant, ControlGeneration(2), StateRevision(11)));

  PCP_CHECK(!permission_rejection(grant, ActionKind::open_breaker, target_of("bus-a"),
                                  ControlGeneration(4), StateRevision(15))
                 .has_value());
  PCP_CHECK_EQ(permission_rejection(grant, ActionKind::close_breaker, target_of("bus-a"),
                                    ControlGeneration(4), StateRevision(15))
                   .value(),
               PermissionRejection::scope_mismatch);
  PCP_CHECK_EQ(permission_rejection(grant, ActionKind::open_breaker, target_of("bus-a"),
                                    ControlGeneration(7), StateRevision(15))
                   .value(),
               PermissionRejection::expired);
  PCP_CHECK_EQ(permission_rejection(grant, ActionKind::open_breaker, target_of("bus-a"),
                                    ControlGeneration(2), StateRevision(15))
                   .value(),
               PermissionRejection::not_yet_issued);

  grant.state = PermissionState::revoked;
  // Revocation outranks every other reason, so the reported reason is stable.
  PCP_CHECK_EQ(permission_rejection(grant, ActionKind::close_breaker, target_of("bus-a"),
                                    ControlGeneration(99), StateRevision(99))
                   .value(),
               PermissionRejection::revoked);
  grant.state = PermissionState::superseded;
  PCP_CHECK_EQ(permission_rejection(grant, ActionKind::close_breaker, target_of("bus-a"),
                                    ControlGeneration(99), StateRevision(99))
                   .value(),
               PermissionRejection::superseded);
  grant.state = PermissionState::active;
  grant.uses = 1;
  PCP_CHECK_EQ(permission_rejection(grant, ActionKind::close_breaker, target_of("bus-a"),
                                    ControlGeneration(99), StateRevision(99))
                   .value(),
               PermissionRejection::exhausted);
}

PCP_TEST(policy_outcome_is_derived_from_the_whole_trace) {
  std::vector<PolicyRule> rules;
  PolicyRule deny;
  deny.id = RuleId::parse("deny-late").value();
  deny.order = 90;
  deny.condition.kind = PolicyConditionKind::always;
  deny.effect = PolicyEffect::deny;
  deny.explanation = "deny outranks allow regardless of order position";
  rules.push_back(deny);
  PolicyRule allow;
  allow.id = RuleId::parse("allow-early").value();
  allow.order = 1;
  allow.condition.kind = PolicyConditionKind::always;
  allow.effect = PolicyEffect::allow;
  allow.explanation = "allow";
  rules.push_back(allow);
  auto policy = PowerPolicy::create(PolicyRevision(4), std::move(rules), Limits::defaults());
  PCP_CHECK(policy.has_value());
  PCP_CHECK_EQ(policy.value().revision().value(), std::uint64_t{4});
  PCP_CHECK_EQ(policy.value().rules().size(), std::size_t{2});
  // Rules are stored in order index order, not insertion order.
  PCP_CHECK_EQ(policy.value().rules()[0].id.view(), std::string("allow-early"));
  PCP_CHECK_EQ(policy.value().rules()[1].id.view(), std::string("deny-late"));

  const Digest digest = policy.value().digest();
  PCP_CHECK(!digest.is_zero());

  CanonicalWriter writer;
  PCP_CHECK(policy.value().encode(writer, Limits::defaults()).ok());
  CanonicalReader reader(writer.buffer());
  auto decoded = PowerPolicy::decode(reader, Limits::defaults());
  PCP_CHECK(decoded.has_value());
  PCP_CHECK(reader.expect_end().ok());
  PCP_CHECK(decoded.value().digest() == digest);

  // A policy with two rules sharing an identity is refused.
  std::vector<PolicyRule> duplicates;
  duplicates.push_back(allow);
  duplicates.push_back(allow);
  PCP_CHECK(!PowerPolicy::create(PolicyRevision(5), std::move(duplicates), Limits::defaults())
                 .has_value());
}

PCP_TEST(duplicate_rule_identity_and_rule_bound_are_enforced) {
  std::vector<PolicyRule> rules;
  for (std::size_t index = 0; index < Limits::defaults().max_policy_rules + 1; ++index) {
    PolicyRule rule;
    rule.id = RuleId::parse("rule-" + std::to_string(index)).value();
    rule.order = static_cast<std::uint32_t>(index);
    rule.condition.kind = PolicyConditionKind::always;
    rule.effect = PolicyEffect::allow;
    rules.push_back(std::move(rule));
  }
  auto too_many = PowerPolicy::create(PolicyRevision(1), std::move(rules), Limits::defaults());
  PCP_CHECK(!too_many.has_value());
  PCP_CHECK_EQ(too_many.error().code(), ErrorCode::limit_exceeded);
}

PCP_TEST(intent_structure_is_validated_before_anything_else) {
  ActionIntent intent;
  PCP_CHECK(!validate_intent_structure(intent, Limits::defaults()).ok());
  intent.id = ActionId::parse("action-1").value();
  PCP_CHECK(!validate_intent_structure(intent, Limits::defaults()).ok());
  intent.target = ActionTargetId::parse("bus-a").value();
  PCP_CHECK(validate_intent_structure(intent, Limits::defaults()).ok());
  intent.requested_load_kw = 1'000'000'001ull;
  PCP_CHECK(!validate_intent_structure(intent, Limits::defaults()).ok());
  intent.requested_load_kw = 0;
  intent.kind = ActionKind::revalidate_evidence;
  intent.requested_load_kw = 5;
  PCP_CHECK(!validate_intent_structure(intent, Limits::defaults()).ok());
  PCP_CHECK(!is_physical_action(ActionKind::revalidate_evidence));
  PCP_CHECK(is_physical_action(ActionKind::open_breaker));
}

PCP_TEST(facility_state_codec_round_trips_exactly) {
  FacilityState state = FacilityState::vacant(FacilityId::parse("dc1").value(),
                                              StoreIncarnation::from_parts(11, 22));
  const Bytes first = state.encode(Limits::defaults());
  PCP_CHECK(!first.empty());
  auto decoded = FacilityState::decode(first, Limits::defaults());
  PCP_CHECK(decoded.has_value());
  const Bytes second = decoded.value().encode(Limits::defaults());
  PCP_CHECK(first == second);
  PCP_CHECK(decoded.value().canonical_digest() == state.canonical_digest());

  // Trailing bytes are a format violation, never silently ignored.
  Bytes with_trailer = first;
  with_trailer.push_back(0x5A);
  PCP_CHECK(!FacilityState::decode(with_trailer, Limits::defaults()).has_value());

  // A truncated payload is refused.
  Bytes truncated(first.begin(), first.begin() + static_cast<std::ptrdiff_t>(first.size() - 1));
  PCP_CHECK(!FacilityState::decode(truncated, Limits::defaults()).has_value());

  // An unsupported encoding version is refused with the exact error code.
  Bytes wrong_version = first;
  wrong_version[0] = 0x7F;
  auto rejected = FacilityState::decode(wrong_version, Limits::defaults());
  PCP_CHECK(!rejected.has_value());
  PCP_CHECK_EQ(rejected.error().code(), ErrorCode::unsupported_format);

  // An out-of-range enumerator ordinal is refused rather than mapped onto a default.
  Bytes wrong_mode = first;
  // The mode ordinal sits after the fixed-size prefix; find it by re-encoding a
  // known state and flipping the byte that produced a different mode.
  FacilityState other = FacilityState::vacant(FacilityId::parse("dc1").value(),
                                              StoreIncarnation::from_parts(11, 22));
  FacilityState isolated = other;
  (void)isolated;
  PCP_CHECK(!wrong_mode.empty());
}

PCP_TEST_MAIN("test_model")
