#pragma once

// Attempt lifecycle: authorization, issued command, acknowledgement, observed
// effect, and verified effect are five separate states.
//
//   authorized       the control plane permitted the action and recorded an attempt
//   issued           a command object was handed to an actuation adapter
//   acknowledged     the adapter reported receipt of the command
//   effect_observed  the adapter or an independent observer reported an outcome
//   verified         an independent verification matched the observed effect to
//                    the intent
//
// Acknowledgement is not effect. Effect is not verified-safe completion. A refusal
// or an indeterminate outcome never creates an attempt and never changes
// authoritative state.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/action.hpp"
#include "power_control_plane/canonical.hpp"
#include "power_control_plane/digest.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/limits.hpp"

namespace power_control_plane {

enum class AttemptState : std::uint8_t {
  authorized = 1,
  issued = 2,
  acknowledged = 3,
  effect_observed = 4,
  verified = 5,
  refused = 6,
  cancelled = 7,
  superseded = 8,
  effect_failed = 9,
  verification_failed = 10,
};

[[nodiscard]] std::string_view to_string(AttemptState state) noexcept;
[[nodiscard]] Result<AttemptState> parse_attempt_state(std::string_view text);

// True when the attempt reached a state from which no further progress is
// possible.
[[nodiscard]] bool attempt_is_terminal(AttemptState state) noexcept;

enum class AttemptEventKind : std::uint8_t {
  authorized = 1,
  issued = 2,
  acknowledged = 3,
  effect_observed = 4,
  effect_failed = 5,
  verification_passed = 6,
  verification_failed = 7,
  cancelled = 8,
  superseded = 9,
  refused = 10,
};

[[nodiscard]] std::string_view to_string(AttemptEventKind kind) noexcept;

struct AttemptEvent {
  AttemptEventKind kind = AttemptEventKind::authorized;
  ControlGeneration generation;
  StateRevision revision;
  LogicalTick tick;
  Digest payload_digest;
  std::string detail;
};

struct Acknowledgement {
  AdapterId adapter;
  // Digest of the exact command object the adapter acknowledged. Two commands
  // with different bytes are different commands even when they target the same
  // equipment.
  Digest command_digest;
  std::string detail;
};

struct ObservedEffect {
  AdapterId adapter;
  // Digest of the observation payload. It is evidence, not proof: an observation
  // reported by the same adapter that issued the command is not independent
  // verification.
  Digest observation_digest;
  std::string detail;
};

struct VerificationReport {
  AdapterId verifier;
  // True only when the verifier independently confirms the facility reached the
  // intended state.
  bool matches_intent = false;
  Digest evidence_digest;
  std::string detail;
};

struct AttemptRecord {
  AttemptId id;
  IdempotencyKey key;
  ActionIntent intent;
  AttemptState state = AttemptState::authorized;
  ControlGeneration authorized_generation;
  StateRevision authorized_revision;
  ControlGeneration updated_generation;
  StateRevision updated_revision;
  std::vector<AttemptEvent> events;
  std::optional<Acknowledgement> acknowledgement;
  std::optional<ObservedEffect> effect;
  std::optional<VerificationReport> verification;
  // False once the idempotency record has been retired by bounded retention.
  bool replay_retained = true;
};

[[nodiscard]] Status encode_acknowledgement(CanonicalWriter& writer,
                                           const Acknowledgement& value,
                                           const Limits& limits);
[[nodiscard]] Result<Acknowledgement> decode_acknowledgement(CanonicalReader& reader,
                                                             const Limits& limits);
[[nodiscard]] Status encode_observed_effect(CanonicalWriter& writer,
                                            const ObservedEffect& value,
                                            const Limits& limits);
[[nodiscard]] Result<ObservedEffect> decode_observed_effect(CanonicalReader& reader,
                                                            const Limits& limits);
[[nodiscard]] Status encode_verification_report(CanonicalWriter& writer,
                                                const VerificationReport& value,
                                                const Limits& limits);
[[nodiscard]] Result<VerificationReport> decode_verification_report(
    CanonicalReader& reader, const Limits& limits);

[[nodiscard]] Status encode_attempt(CanonicalWriter& writer, const AttemptRecord& value,
                                    const Limits& limits);
[[nodiscard]] Result<AttemptRecord> decode_attempt(CanonicalReader& reader,
                                                   const Limits& limits);

}  // namespace power_control_plane
