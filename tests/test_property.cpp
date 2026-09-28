// Proof obligations: seeded randomized state-machine invariants.
//
// Each seed drives a long sequence of real verbs against the engine and checks the
// invariants after every step. A failing seed is reported by name so the exact
// sequence can be reproduced.

#include <cstdint>
#include <string>
#include <vector>

#include "power_control_plane/mode.hpp"
#include "support/fixture.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

struct Observation {
  StateRevision revision;
  ControlGeneration generation;
  std::size_t obligation_count = 0;
  std::size_t attempt_count = 0;
  std::size_t permission_count = 0;
  bool authoritative = false;
};

Observation observe(const Fixture& fixture) {
  Observation observation;
  auto snapshot = fixture.snapshot();
  if (!snapshot.has_value()) {
    return observation;
  }
  observation.authoritative = true;
  observation.revision = snapshot.value().revision();
  observation.generation = snapshot.value().generation();
  observation.obligation_count = snapshot.value().obligations().size();
  observation.attempt_count = snapshot.value().attempts().size();
  observation.permission_count = snapshot.value().permissions().size();
  return observation;
}

// Runs one seeded sequence. Returns an empty string on success or the violated
// invariant with the step number.
std::string run_sequence(Fixture& fixture, std::uint64_t seed, int steps) {
  SeededRandom random(seed);
  Observation previous = observe(fixture);
  std::vector<std::string> obligation_ids;
  std::vector<ActionKind> kinds = {
      ActionKind::open_breaker, ActionKind::close_breaker, ActionKind::transfer_source,
      ActionKind::set_load_limit, ActionKind::isolate_bus, ActionKind::restore_bus,
      ActionKind::shed_load_group, ActionKind::restore_load_group};

  for (int step = 0; step < steps; ++step) {
    const std::uint64_t choice = random.below(10);
    const std::string tag = "property/" + std::to_string(seed) + "/" + std::to_string(step);
    if (choice == 0) {
      // Deterioration record: always accepted, only ever tightens requirements.
      auto current = fixture.snapshot();
      if (current.value().mode() != OperatingMode::degraded) {
        auto decision = fixture.transition_to(OperatingMode::degraded);
        if (!decision.has_value()) {
          return "transition_to(degraded) returned an error at step " + std::to_string(step);
        }
        if (!decision_committed(decision.value().outcome)) {
          return "a deterioration record was refused at step " + std::to_string(step);
        }
      }
    } else if (choice == 1) {
      // Recovery needs a permission; grant one first so the transition can succeed
      // when everything else lines up, and accept either outcome.
      (void)fixture.grant({ActionKind::restore_normal}, {}, 1);
      (void)fixture.transition_to(OperatingMode::normal);
    } else if (choice == 2) {
      Interlock interlock;
      const std::string id = "interlock-" + std::to_string(random.below(5));
      interlock.id = InterlockId::parse(id).value();
      interlock.source = EvidenceSourceId::parse("safety-system").value();
      interlock.severity = random.below(3) == 0 ? InterlockSeverity::critical
                                                : InterlockSeverity::blocking;
      const std::uint64_t state_choice = random.below(3);
      interlock.state = state_choice == 0   ? InterlockState::engaged
                        : state_choice == 1 ? InterlockState::cleared
                                            : InterlockState::unknown;
      interlock.explanation = "generated interlock";
      interlock.declared_generation = fixture.snapshot().value().generation();
      auto request = fixture.request(tag);
      if (!request.has_value()) {
        return "request construction failed at step " + std::to_string(step);
      }
      (void)fixture.plane().record_interlock(fixture.lease(), interlock, request.value());
    } else if (choice == 3) {
      ProtectedObligation obligation;
      const std::string id = "obligation-" + std::to_string(random.below(3));
      obligation.id = ObligationId::parse(id).value();
      obligation.authority_source = EvidenceSourceId::parse("facility-capacity").value();
      obligation.authority_reference = AuthorityReference::parse("generated-charter").value();
      obligation.continuity_required = random.below(2) == 0;
      obligation.description = "generated obligation";
      auto request = fixture.request(tag);
      if (!request.has_value()) {
        return "request construction failed at step " + std::to_string(step);
      }
      auto decision = fixture.plane().record_obligation(fixture.lease(), obligation,
                                                        request.value());
      if (!decision.has_value()) {
        return "record_obligation returned an error at step " + std::to_string(step);
      }
      if (decision_committed(decision.value().outcome)) {
        obligation_ids.push_back(id);
      }
    } else if (choice == 4) {
      if (!obligation_ids.empty()) {
        const std::string id = obligation_ids[random.below(obligation_ids.size())];
        auto request = fixture.request(tag);
        (void)fixture.plane().remove_obligation(fixture.lease(),
                                                ObligationId::parse(id).value(),
                                                request.value());
      }
    } else if (choice == 5) {
      CapacityCommitment commitment;
      commitment.id = CapacityCommitmentId::parse("commitment-" + std::to_string(random.below(3)))
                          .value();
      commitment.source = EvidenceSourceId::parse("power-capacity").value();
      commitment.authority_reference = AuthorityReference::parse("generated-grant").value();
      commitment.committed_kw = random.below(2000);
      commitment.evidence.source = commitment.source;
      commitment.evidence.kind = EvidenceKind::power_capacity;
      commitment.evidence.content_digest = sha256_domain("pcp/property/v1", tag);
      auto request = fixture.request(tag);
      (void)fixture.plane().record_commitment(fixture.lease(), commitment, request.value());
    } else if (choice == 6) {
      const std::uint64_t uses = static_cast<std::uint32_t>(1 + random.below(3));
      (void)fixture.grant({kinds[random.below(kinds.size())]}, {"bus-a"}, static_cast<std::uint32_t>(uses));
    } else if (choice == 7) {
      (void)fixture.revalidate();
    } else {
      const ActionKind kind = kinds[random.below(kinds.size())];
      auto intent = fixture.intent("action-" + std::to_string(step), kind, "bus-a",
                                   random.below(2) == 0 ? 0 : random.below(3000));
      auto request = fixture.request(tag);
      if (!intent.has_value() || !request.has_value()) {
        return "intent construction failed at step " + std::to_string(step);
      }
      auto decision = fixture.plane().authorize_action(fixture.lease(), intent.value(),
                                                       request.value());
      if (!decision.has_value()) {
        return "authorize_action returned an error at step " + std::to_string(step) + ": " +
               decision.error().describe();
      }
      // An accepted decision must name an attempt; a refused one must not.
      if (decision_committed(decision.value().outcome) && !decision.value().attempt.has_value()) {
        return "an accepted decision carried no attempt at step " + std::to_string(step);
      }
      if (!decision_committed(decision.value().outcome) && decision.value().attempt.has_value()) {
        return "a refused decision carried an attempt at step " + std::to_string(step);
      }
      if (decision_is_refusal(decision.value()) && decision.value().steps.empty()) {
        return "a refusal carried no explanation at step " + std::to_string(step);
      }
    }

    const Observation current = observe(fixture);
    if (!current.authoritative) {
      return "the authoritative state disappeared at step " + std::to_string(step);
    }
    if (current.revision < previous.revision) {
      return "the publication revision went backwards at step " + std::to_string(step);
    }
    if (current.generation < previous.generation) {
      return "the control generation went backwards at step " + std::to_string(step);
    }
    if (current.generation.value() > current.revision.value()) {
      return "the control generation exceeded the publication revision at step " +
             std::to_string(step);
    }
    if (current.permission_count < previous.permission_count) {
      return "a permission record disappeared at step " + std::to_string(step);
    }
    previous = current;

    // Invariants that hold on the whole state, checked every step.
    auto snapshot = fixture.snapshot();
    for (const PermissionGrant& grant : snapshot.value().permissions()) {
      if (grant.uses > grant.max_uses) {
        return "a permission was used more than it allowed at step " + std::to_string(step);
      }
      if (grant.state == PermissionState::active && grant.uses >= grant.max_uses) {
        return "an exhausted permission is still active at step " + std::to_string(step);
      }
      if (!(grant.expiry_revision > grant.issued_revision)) {
        return "a permission has an empty revision lifetime at step " + std::to_string(step);
      }
    }
    for (const ProtectedObligation& obligation : snapshot.value().obligations()) {
      if (obligation.state == ObligationState::suspended &&
          (!obligation.suspension.has_value() ||
           obligation.suspension->authority.empty())) {
        return "an obligation is suspended without an authority at step " + std::to_string(step);
      }
    }
    for (const AttemptRecord& attempt : snapshot.value().attempts()) {
      if (attempt.id.is_zero()) {
        return "an attempt carries a zero identity at step " + std::to_string(step);
      }
      if (attempt.verification.has_value() && attempt.acknowledgement.has_value() &&
          attempt.verification->verifier == attempt.acknowledgement->adapter) {
        return "a verification came from the acknowledging adapter at step " +
               std::to_string(step);
      }
    }
  }
  return std::string();
}

}  // namespace

PCP_TEST(seeded_state_machine_invariants_hold) {
  const std::uint64_t seeds[] = {1, 0xC0FFEEull, 20260101ull, 0xDEADBEEFull};
  for (const std::uint64_t seed : seeds) {
    auto fixture = Fixture::create("property-" + std::to_string(seed));
    PCP_CHECK(fixture.has_value());
    const std::string failure = run_sequence(fixture.value(), seed, 160);
    if (!failure.empty()) {
      context.note("seed " + std::to_string(seed) + " failed: " + failure);
      PCP_CHECK_MSG(false, "seed " + std::to_string(seed) + ": " + failure);
    }
    auto integrity = fixture.value().plane().verify_store();
    auto replay = fixture.value().plane().verify_replay();
    PCP_CHECK(integrity.has_value() && integrity.value().ok);
    PCP_CHECK(replay.has_value() && replay.value().ok);
  }
}

PCP_TEST(seeded_sequences_are_reproducible) {
  // Two independent fixtures driven by the same seed must reach the same final
  // publication revision, which is what makes a reported seed actionable.
  for (const std::uint64_t seed : {7ull, 4242ull}) {
    auto first = Fixture::create("property-repro-a-" + std::to_string(seed));
    auto second = Fixture::create("property-repro-b-" + std::to_string(seed));
    PCP_CHECK(first.has_value() && second.has_value());
    const std::string failure_a = run_sequence(first.value(), seed, 60);
    const std::string failure_b = run_sequence(second.value(), seed, 60);
    PCP_CHECK_MSG(failure_a.empty(), failure_a);
    PCP_CHECK_MSG(failure_b.empty(), failure_b);
    PCP_CHECK_EQ(first.value().snapshot().value().revision().value(),
                 second.value().snapshot().value().revision().value());
    PCP_CHECK_EQ(first.value().snapshot().value().generation().value(),
                 second.value().snapshot().value().generation().value());
    // The store incarnation is generated per store and is intentional state, so two
    // independently created stores never share a canonical digest. Everything that
    // the seeded sequence itself decides must match exactly.
    const auto& a = first.value().snapshot().value();
    const auto& b = second.value().snapshot().value();
    PCP_CHECK_EQ(a.mode(), b.mode());
    PCP_CHECK_EQ(a.interlocks().size(), b.interlocks().size());
    PCP_CHECK_EQ(a.obligations().size(), b.obligations().size());
    PCP_CHECK_EQ(a.commitments().size(), b.commitments().size());
    PCP_CHECK_EQ(a.permissions().size(), b.permissions().size());
    PCP_CHECK_EQ(a.attempts().size(), b.attempts().size());
    PCP_CHECK_EQ(a.mode_history().size(), b.mode_history().size());
    PCP_CHECK_EQ(a.transition_log().size(), b.transition_log().size());
  }
}

PCP_TEST_MAIN("test_property")
