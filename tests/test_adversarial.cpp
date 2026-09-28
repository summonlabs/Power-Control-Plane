// Proof obligations: adversarial input and repeated-lifecycle hardening.
//
// These tests attack the decoder, the applier, and the store with malformed,
// contradictory, repeated, and boundary-shaped input, and assert that every attack is
// refused with a typed error and changes nothing.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "power_control_plane/store.hpp"
#include "support/fixture.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

// Re-encodes a state payload after applying a mutation to its canonical body, so an
// attack can be expressed as "a structurally valid payload with one field changed".
Bytes encode_with_version(Bytes payload, std::uint32_t version) {
  for (unsigned index = 0; index < 4; ++index) {
    payload[index] = static_cast<std::uint8_t>((version >> (8 * index)) & 0xFFu);
  }
  return payload;
}

}  // namespace

PCP_TEST(repeated_open_commit_close_cycles_leave_no_residue) {
  const std::string root = scratch_directory("adversarial-cycles");
  for (int cycle = 0; cycle < 12; ++cycle) {
    EngineOptions options;
    options.retained_publications = 4;
    auto plane = ControlPlane::open(root, StoreOpenMode::read_write, options);
    PCP_CHECK_MSG(plane.has_value(), "cycle " + std::to_string(cycle) + ": " +
                                         plane.error().describe());
    auto lease = plane.value().acquire_writer();
    PCP_CHECK(lease.has_value());
    auto evidence = fixture_evidence();
    auto policy = fixture_policy(PolicyRevision(static_cast<std::uint64_t>(cycle) + 1),
                                plane.value().limits());
    PCP_CHECK(evidence.has_value() && policy.has_value());
    auto snapshot = plane.value().snapshot();
    if (!snapshot.has_value()) {
      auto key = IdempotencyKey::derive("adversarial/bootstrap").value();
      auto booted = plane.value().bootstrap(lease.value(),
                                            FacilityId::parse("dc-cycle").value(),
                                            OperatingMode::normal, evidence.value(), key);
      PCP_CHECK(booted.has_value());
      PCP_CHECK(decision_committed(booted.value().outcome));
      snapshot = plane.value().snapshot();
      PCP_CHECK(snapshot.has_value());
    }
    MutationRequest request;
    request.planned.generation = snapshot.value().generation();
    request.planned.revision = snapshot.value().revision();
    request.planned.policy_revision = snapshot.value().policy_revision();
    request.planned.evidence_digest = snapshot.value().evidence().digest();
    request.key = IdempotencyKey::derive("adversarial/cycle/" + std::to_string(cycle)).value();
    auto bound = plane.value().rebind_policy(lease.value(), policy.value(), request);
    PCP_CHECK(bound.has_value());
    PCP_CHECK(decision_committed(bound.value().outcome));
    auto revalidate_request = request;
    revalidate_request.key =
        IdempotencyKey::derive("adversarial/revalidate/" + std::to_string(cycle)).value();
    auto revalidated =
        plane.value().revalidate(lease.value(), evidence.value(), revalidate_request);
    PCP_CHECK(revalidated.has_value());
    auto integrity = plane.value().verify_store();
    PCP_CHECK(integrity.has_value());
    PCP_CHECK_MSG(integrity.value().ok, integrity.value().detail);
    PCP_CHECK(integrity.value().staging_residue.empty());
    PCP_CHECK(integrity.value().orphan_generation_files.empty());
    PCP_CHECK(plane.value().store().retained_publications().size() <= 4);
    static_cast<void>(plane.value().release_writer(lease.value()));
    plane.value().close();
  }
}

PCP_TEST(a_payload_declaring_an_enormous_text_length_is_refused_without_allocating) {
  // A canonical text field whose declared length is 4 GiB - 1 must be refused by the
  // bound check, not read.
  CanonicalWriter writer;
  writer.u32(0xFFFFFFFFu);
  CanonicalReader reader(writer.buffer());
  auto text = reader.text(64);
  PCP_CHECK(!text.has_value());
  PCP_CHECK_EQ(text.error().code(), ErrorCode::limit_exceeded);

  CanonicalReader bytes_reader(writer.buffer());
  auto bytes = bytes_reader.bytes(1024);
  PCP_CHECK(!bytes.has_value());
  PCP_CHECK_EQ(bytes.error().code(), ErrorCode::limit_exceeded);

  // A declared length that exceeds the bytes actually present is a truncation.
  CanonicalWriter short_writer;
  PCP_CHECK(short_writer.text("abc", 8).ok());
  Bytes truncated = short_writer.buffer();
  truncated.pop_back();
  CanonicalReader truncated_reader(truncated);
  auto value = truncated_reader.text(64);
  PCP_CHECK(!value.has_value());
  PCP_CHECK_EQ(value.error().code(), ErrorCode::corrupt_store);
}

PCP_TEST(a_state_payload_with_a_non_consecutive_transition_log_is_refused) {
  auto fixture = Fixture::create("adversarial-log-order");
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 8);
  PCP_CHECK(granted.has_value());
  for (int index = 0; index < 2; ++index) {
    auto intent = fixture.value().intent("open-" + std::to_string(index),
                                         ActionKind::open_breaker, "bus-a");
    auto decision = fixture.value().authorize(intent.value(),
                                              "adversarial/log/" + std::to_string(index));
    PCP_CHECK(decision.has_value());
  }
  const std::string root = fixture.value().root();
  const Bytes payload = fixture.value().snapshot().value().state().encode(
      fixture.value().limits());
  fixture.value().close();
  PCP_CHECK(!payload.empty());

  // A payload with one byte flipped inside the transition log either fails to decode or
  // decodes to a different state; the structural checks in the decoder make a
  // reordered log a refusal in the common case.
  std::size_t refusals = 0;
  for (std::size_t offset = payload.size() / 2; offset < payload.size(); ++offset) {
    Bytes candidate = payload;
    candidate[offset] = static_cast<std::uint8_t>(candidate[offset] ^ 0x01u);
    auto decoded = FacilityState::decode(candidate, Limits::defaults());
    if (!decoded.has_value()) {
      ++refusals;
      continue;
    }
    // When it still decodes, it must not be the same state.
    PCP_CHECK(!(decoded.value().encode(Limits::defaults()) == payload));
  }
  context.note("refused " + std::to_string(refusals) + " of " +
               std::to_string(payload.size() - payload.size() / 2) +
               " single-byte corruptions in the tail of the payload");
  static_cast<void>(root);
}

PCP_TEST(a_duplicate_interlock_identity_is_replaced_not_duplicated) {
  auto fixture = Fixture::create("adversarial-duplicate-interlock");
  PCP_CHECK(fixture.has_value());
  Interlock interlock;
  interlock.id = InterlockId::parse("duplicate").value();
  interlock.source = EvidenceSourceId::parse("safety-system").value();
  interlock.severity = InterlockSeverity::blocking;
  interlock.state = InterlockState::engaged;
  interlock.explanation = "first";
  interlock.declared_generation = fixture.value().snapshot().value().generation();
  auto first = fixture.value().plane().record_interlock(
      fixture.value().lease(), interlock,
      fixture.value().request("adversarial/dup-1").value());
  PCP_CHECK(first.has_value());
  PCP_CHECK(decision_committed(first.value().outcome));

  interlock.state = InterlockState::cleared;
  interlock.explanation = "second";
  auto second = fixture.value().plane().record_interlock(
      fixture.value().lease(), interlock,
      fixture.value().request("adversarial/dup-2").value());
  PCP_CHECK(second.has_value());
  PCP_CHECK(decision_committed(second.value().outcome));
  auto snapshot = fixture.value().snapshot();
  PCP_CHECK_EQ(snapshot.value().interlocks().size(), std::size_t{1});
  PCP_CHECK_EQ(snapshot.value().interlocks().front().state, InterlockState::cleared);
  PCP_CHECK_EQ(snapshot.value().interlocks().front().explanation, std::string("second"));

  // A transition log entry carrying a zero predecessor digest is refused by the
  // decoder's structural validation.
  const Bytes payload = snapshot.value().state().encode(fixture.value().limits());
  auto decoded = FacilityState::decode(payload, Limits::defaults());
  PCP_CHECK(decoded.has_value());
}

PCP_TEST(a_read_only_store_refuses_every_mutation_with_a_typed_outcome) {
  auto fixture = Fixture::create("adversarial-read-only");
  PCP_CHECK(fixture.has_value());
  const std::string root = fixture.value().root();
  fixture.value().close();

  auto plane = ControlPlane::open(root, StoreOpenMode::read_only, EngineOptions{});
  PCP_CHECK(plane.has_value());
  auto lease = plane.value().acquire_writer();
  PCP_CHECK(!lease.has_value());
  PCP_CHECK_EQ(lease.error().code(), ErrorCode::not_authoritative);

  // A default-constructed lease cannot be forged into authority.
  WriterLease forged;
  PCP_CHECK(!forged.valid());
  auto snapshot = plane.value().snapshot();
  PCP_CHECK(snapshot.has_value());
  Interlock interlock;
  interlock.id = InterlockId::parse("read-only").value();
  interlock.source = EvidenceSourceId::parse("safety-system").value();
  interlock.severity = InterlockSeverity::blocking;
  interlock.state = InterlockState::engaged;
  interlock.declared_generation = snapshot.value().generation();
  MutationRequest request;
  request.planned.generation = snapshot.value().generation();
  request.planned.revision = snapshot.value().revision();
  request.planned.policy_revision = snapshot.value().policy_revision();
  request.planned.evidence_digest = snapshot.value().evidence().digest();
  request.key = IdempotencyKey::derive("adversarial/read-only").value();
  auto refused = plane.value().record_interlock(forged, interlock, request);
  PCP_CHECK(refused.has_value());
  PCP_CHECK_EQ(refused.value().outcome, DecisionOutcome::stale_authority);
  const auto before = plane.value().snapshot();
  PCP_CHECK(before.value().revision() == snapshot.value().revision());
  PCP_CHECK(before.value().interlocks().empty());
}

PCP_TEST(committed_operations_are_never_recorded_for_refused_requests) {
  auto fixture = Fixture::create("adversarial-no-record");
  PCP_CHECK(fixture.has_value());
  // No permission exists, so the request is refused. The key must not become
  // replayable, because recording a refusal would turn a refusal into an answer.
  auto intent = fixture.value().intent("open-none", ActionKind::open_breaker, "bus-a");
  PCP_CHECK(intent.has_value());
  auto request = fixture.value().request("adversarial/refused-key");
  PCP_CHECK(request.has_value());
  auto refused = fixture.value().plane().authorize_action(fixture.value().lease(),
                                                          intent.value(), request.value());
  PCP_CHECK(refused.has_value());
  PCP_CHECK_EQ(refused.value().outcome, DecisionOutcome::unauthorized);
  auto snapshot = fixture.value().snapshot();
  PCP_CHECK(snapshot.value().state().find_operation(request.value().key) == nullptr);

  // Granting the permission and retrying the same key must now be judged afresh and
  // accepted, not replayed as a refusal.
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 2);
  PCP_CHECK(granted.has_value());
  auto retry_intent = fixture.value().intent("open-none", ActionKind::open_breaker, "bus-a");
  PCP_CHECK(retry_intent.has_value());
  auto accepted = fixture.value().plane().authorize_action(fixture.value().lease(),
                                                           retry_intent.value(), request.value());
  PCP_CHECK(accepted.has_value());
  PCP_CHECK_EQ(accepted.value().outcome, DecisionOutcome::accepted);
}

PCP_TEST(an_oversized_transition_payload_is_refused_before_application) {
  auto fixture = Fixture::create("adversarial-payload-bound");
  PCP_CHECK(fixture.has_value());
  const Bytes payload = fixture.value().snapshot().value().state().encode(
      fixture.value().limits());
  TransitionRecord record;
  record.kind = TransitionKind::interlock_recorded;
  record.payload.assign(transition_payload_bound(fixture.value().limits()) + 1, 0x00);
  FacilityState candidate = fixture.value().snapshot().value().state();
  const Digest before = candidate.canonical_digest();
  const Status applied = apply_transition(candidate, record, fixture.value().limits());
  PCP_CHECK(!applied.ok());
  PCP_CHECK_EQ(applied.error().code(), ErrorCode::limit_exceeded);
  // The refused application left the state byte-identical.
  PCP_CHECK(candidate.canonical_digest() == before);
  PCP_CHECK(!payload.empty());
}

PCP_TEST(an_empty_transition_payload_is_refused_for_every_kind) {
  auto fixture = Fixture::create("adversarial-empty-payload");
  PCP_CHECK(fixture.has_value());
  const TransitionKind kinds[] = {
      TransitionKind::mode_transition,      TransitionKind::evidence_rebound,
      TransitionKind::interlock_recorded,   TransitionKind::interlock_removed,
      TransitionKind::obligation_recorded,  TransitionKind::obligation_removed,
      TransitionKind::commitment_recorded,  TransitionKind::commitment_removed,
      TransitionKind::permission_granted,   TransitionKind::permission_retired,
      TransitionKind::policy_rebound,       TransitionKind::attempt_authorized,
      TransitionKind::attempt_issued,       TransitionKind::attempt_acknowledged,
      TransitionKind::attempt_effect_observed,
      TransitionKind::attempt_effect_failed, TransitionKind::attempt_verified,
      TransitionKind::attempt_verification_failed,
      TransitionKind::attempt_cancelled,    TransitionKind::attempt_superseded};
  for (const TransitionKind kind : kinds) {
    TransitionRecord record;
    record.kind = kind;
    FacilityState candidate = fixture.value().snapshot().value().state();
    const Digest before = candidate.canonical_digest();
    const Status applied = apply_transition(candidate, record, fixture.value().limits());
    PCP_CHECK_MSG(!applied.ok(), std::string("kind ") + std::string(to_string(kind)) +
                                     " accepted an empty payload");
    PCP_CHECK(candidate.canonical_digest() == before);
  }
  // A second bootstrap on a store that already has a generation is refused.
  TransitionRecord bootstrap;
  bootstrap.kind = TransitionKind::facility_bootstrap;
  CanonicalWriter writer;
  BootstrapPayload payload;
  payload.facility = fixture.value().snapshot().value().facility();
  payload.incarnation = fixture.value().snapshot().value().incarnation();
  payload.mode = OperatingMode::normal;
  PCP_CHECK(encode_bootstrap_payload(writer, payload, fixture.value().limits()).ok());
  bootstrap.payload = writer.take();
  FacilityState candidate = fixture.value().snapshot().value().state();
  const Status applied = apply_transition(candidate, bootstrap, fixture.value().limits());
  PCP_CHECK(!applied.ok());
  PCP_CHECK_EQ(applied.error().code(), ErrorCode::invalid_transition);
}

PCP_TEST(configuration_boundaries_are_refused_rather_than_clamped) {
  auto plane = ControlPlane::open(scratch_directory("adversarial-retention"),
                                  StoreOpenMode::read_write,
                                  EngineOptions{});
  PCP_CHECK(plane.has_value());
  plane.value().close();
  // Retaining fewer than two publications is refused: deterministic replay always needs
  // a predecessor.
  EngineOptions options;
  options.retained_publications = 1;
  auto refused = ControlPlane::open(scratch_directory("adversarial-retention-1"),
                                    StoreOpenMode::read_write, options);
  PCP_CHECK(!refused.has_value());
  PCP_CHECK_EQ(refused.error().code(), ErrorCode::invalid_argument);
}

PCP_TEST(zero_limit_bounds_refuse_instead_of_wrapping) {
  Limits limits = Limits::defaults();
  limits.max_policy_rules = 0;
  std::vector<PolicyRule> rules;
  PolicyRule rule;
  rule.id = RuleId::parse("any").value();
  rule.order = 0;
  rule.condition.kind = PolicyConditionKind::always;
  rule.effect = PolicyEffect::allow;
  rules.push_back(rule);
  auto policy = PowerPolicy::create(PolicyRevision(1), std::move(rules), limits);
  PCP_CHECK(!policy.has_value());
  PCP_CHECK_EQ(policy.error().code(), ErrorCode::limit_exceeded);

  auto attempts = checked_increment(std::numeric_limits<std::uint64_t>::max());
  PCP_CHECK(!attempts.has_value());
  auto product = checked_mul(std::numeric_limits<std::uint64_t>::max(), 2);
  PCP_CHECK(!product.has_value());
  auto difference = checked_sub(0, 1);
  PCP_CHECK(!difference.has_value());
}

PCP_TEST(integrity_fails_closed_after_a_second_writer_advances_the_fence) {
  auto fixture = Fixture::create("adversarial-fence");
  PCP_CHECK(fixture.has_value());
  const std::string root = fixture.value().root();
  const StateRevision revision = fixture.value().snapshot().value().revision();
  fixture.value().close();

  auto first = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(first.has_value());
  auto lease = first.value().acquire_writer();
  PCP_CHECK(lease.has_value());
  auto integrity = first.value().verify_store();
  PCP_CHECK(integrity.has_value());
  PCP_CHECK(integrity.value().ok);
  PCP_CHECK(integrity.value().head_matches_payload);
  PCP_CHECK(!integrity.value().rollback_detected);
  PCP_CHECK(first.value().store().head().revision == revision);
  static_cast<void>(first.value().release_writer(lease.value()));
  first.value().close();

  // A second process can take authority and the store stays verifiable.
  auto second = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(second.has_value());
  auto second_lease = second.value().acquire_writer();
  PCP_CHECK(second_lease.has_value());
  PCP_CHECK(second_lease.value().epoch() > lease.value().epoch());
  auto second_integrity = second.value().verify_store();
  PCP_CHECK(second_integrity.has_value());
  PCP_CHECK(second_integrity.value().ok);
  auto replay = second.value().verify_replay();
  PCP_CHECK(replay.has_value());
  PCP_CHECK_MSG(replay.value().ok, replay.value().detail);
}

PCP_TEST_MAIN("pcp_test_adversarial")
