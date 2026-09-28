#pragma once

// Authoritative transitions and the transition log.
//
// apply_transition is the only function in the library that mutates
// authoritative facility state. Every engine verb builds a TransitionRecord,
// hands it to apply_transition, and publishes the result through the durable
// store. Nothing else writes to FacilityState.
//
// The transition log is part of the state. Each entry records the resulting
// generation, the kind, the digest of the state the transition started from, and
// the canonical payload. Deterministic replay verification reads two consecutive
// persisted generations, applies the logged payload to the older one, and
// requires the result to be byte-identical to the newer one.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/action.hpp"
#include "power_control_plane/attempt.hpp"
#include "power_control_plane/canonical.hpp"
#include "power_control_plane/digest.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/interlock.hpp"
#include "power_control_plane/limits.hpp"
#include "power_control_plane/mode.hpp"
#include "power_control_plane/obligation.hpp"
#include "power_control_plane/permission.hpp"
#include "power_control_plane/policy.hpp"

namespace power_control_plane {

enum class TransitionKind : std::uint8_t {
  facility_bootstrap = 1,
  mode_transition = 2,
  evidence_rebound = 3,
  interlock_recorded = 4,
  interlock_removed = 5,
  obligation_recorded = 6,
  obligation_removed = 7,
  commitment_recorded = 8,
  commitment_removed = 9,
  permission_granted = 10,
  permission_retired = 11,
  policy_rebound = 12,
  attempt_authorized = 13,
  attempt_issued = 14,
  attempt_acknowledged = 15,
  attempt_effect_observed = 16,
  attempt_effect_failed = 17,
  attempt_verified = 18,
  attempt_verification_failed = 19,
  attempt_cancelled = 20,
  attempt_superseded = 21,
};

[[nodiscard]] std::string_view to_string(TransitionKind kind) noexcept;
[[nodiscard]] Result<TransitionKind> parse_transition_kind(std::string_view text);

// True when committing this transition advances the authoritative
// facility electrical control generation. Metadata-only transitions advance the
// state revision instead, which keeps "which electrical generation is
// authoritative" distinct from "how many metadata updates have happened".
[[nodiscard]] bool transition_changes_control_generation(TransitionKind kind) noexcept;

struct TransitionRecord {
  TransitionKind kind = TransitionKind::facility_bootstrap;
  // The idempotency key this transition is committed under, or zero. The applier
  // records a committed-operation entry for a non-zero key, which is what makes a
  // retry of any mutation, not only an action, answerable from the committed result.
  IdempotencyKey key;
  // Canonical payload for the kind. Bounded on decode by
  // transition_payload_bound(). Byte content is validated by the per-kind decoder
  // before any mutation happens.
  Bytes payload;
};

struct TransitionLogEntry {
  // The generation this transition produced. Two publications can share a
  // generation when the transition only changed metadata; the revision below is
  // the unique publication identity.
  ControlGeneration generation;
  // The publication revision this transition produced. Unique and consecutive
  // across every commit, which makes it the correct key for durable-store file
  // naming and for deterministic replay stepping.
  StateRevision revision;
  TransitionKind kind = TransitionKind::facility_bootstrap;
  // The idempotency key the transition was committed under, so that deterministic
  // replay reproduces the committed-operation index as well as the rest of the state.
  IdempotencyKey key;
  // Domain-separated canonical digest of the state the transition started from.
  // Zero for the bootstrap transition, which has no predecessor.
  Digest previous_state_digest;
  LogicalTick tick;
  Bytes payload;
};

struct ModeHistoryEntry {
  ControlGeneration generation;
  // The publication revision at which the facility entered this mode. Generations do
  // not advance for metadata-only publications, so post-event ordering is expressed
  // in revisions.
  StateRevision revision;
  OperatingMode from = OperatingMode::normal;
  OperatingMode to = OperatingMode::normal;
  LogicalTick tick;
  AuthorityReference authority;
};

class FacilityState;

// The single mutation path. On refusal the state is left exactly as it was: the
// implementation decodes and validates the whole payload first and only then
// mutates.
[[nodiscard]] Status apply_transition(FacilityState& state,
                                      const TransitionRecord& record,
                                      const Limits& limits);

// ---------------------------------------------------------------------------
// Transition payloads
// ---------------------------------------------------------------------------

struct BootstrapPayload {
  FacilityId facility;
  StoreIncarnation incarnation;
  OperatingMode mode = OperatingMode::normal;
  // The evidence binding the facility starts with. A facility with no bound
  // evidence can still be bootstrapped, but every action against it is then
  // refused with an explicit indeterminate outcome rather than allowed by default.
  EvidenceBinding evidence;
};

struct ModeTransitionPayload {
  OperatingMode from = OperatingMode::normal;
  OperatingMode to = OperatingMode::normal;
  std::vector<ObligationSuspension> suspensions;
  AuthorityReference authority;
};

struct EvidenceBindingPayload {
  EvidenceBinding evidence;
};

struct InterlockPayload {
  Interlock interlock;
};

struct ObligationPayload {
  ProtectedObligation obligation;
};

struct CommitmentPayload {
  CapacityCommitment commitment;
};

struct PermissionGrantPayload {
  PermissionGrant grant;
};

struct PermissionRetirePayload {
  PermissionId id;
  PermissionState state = PermissionState::revoked;
};

struct PolicyPayload {
  PowerPolicy policy;
};

struct AttemptAuthorizedPayload {
  AttemptRecord attempt;
  // The permission consumed by this attempt, or zero when the authorization path
  // did not consume one. Consumption is part of the same publication as the
  // attempt, so a permission can never be spent without the attempt existing and
  // an attempt can never exist without its permission being spent.
  PermissionId permission;
};

struct AttemptTransitionPayload {
  AttemptId attempt;
  AttemptEventKind event = AttemptEventKind::issued;
  Digest payload_digest;
  std::string detail;
  AttemptState resulting_state = AttemptState::issued;
  // Exactly one of these is set, matching the event kind. The applier refuses a
  // payload whose populated field does not match its event.
  std::optional<Acknowledgement> acknowledgement;
  std::optional<ObservedEffect> effect;
  std::optional<VerificationReport> verification;
};

[[nodiscard]] Status encode_bootstrap_payload(CanonicalWriter& writer,
                                              const BootstrapPayload& value,
                                              const Limits& limits);
[[nodiscard]] Result<BootstrapPayload> decode_bootstrap_payload(CanonicalReader& reader,
                                                                const Limits& limits);

[[nodiscard]] Status encode_mode_transition_payload(CanonicalWriter& writer,
                                                    const ModeTransitionPayload& value,
                                                    const Limits& limits);
[[nodiscard]] Result<ModeTransitionPayload> decode_mode_transition_payload(
    CanonicalReader& reader, const Limits& limits);

[[nodiscard]] Status encode_attempt_authorized_payload(
    CanonicalWriter& writer, const AttemptAuthorizedPayload& value, const Limits& limits);
[[nodiscard]] Result<AttemptAuthorizedPayload> decode_attempt_authorized_payload(
    CanonicalReader& reader, const Limits& limits);

[[nodiscard]] Status encode_attempt_transition_payload(CanonicalWriter& writer,
                                                       const AttemptTransitionPayload& value,
                                                       const Limits& limits);
[[nodiscard]] Result<AttemptTransitionPayload> decode_attempt_transition_payload(
    CanonicalReader& reader, const Limits& limits);

// Identity-only payload used by the removal transitions.
[[nodiscard]] Status encode_identity_payload(CanonicalWriter& writer, std::string_view id,
                                            std::size_t max_bytes);
[[nodiscard]] Result<std::string> decode_identity_payload(CanonicalReader& reader,
                                                          std::size_t max_bytes);

[[nodiscard]] Status encode_permission_retire_payload(
    CanonicalWriter& writer, const PermissionRetirePayload& value, const Limits& limits);
[[nodiscard]] Result<PermissionRetirePayload> decode_permission_retire_payload(
    CanonicalReader& reader, const Limits& limits);

// Canonical payload bound used by every transition decoder.
[[nodiscard]] std::size_t transition_payload_bound(const Limits& limits) noexcept;

}  // namespace power_control_plane
