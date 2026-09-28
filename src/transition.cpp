#include "power_control_plane/transition.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "detail/codec_util.hpp"
#include "detail/state_editor.hpp"
#include "power_control_plane/state.hpp"

// The single mutation path for authoritative facility state.
//
// apply_transition is atomic: it works on a private copy and assigns back only
// after the whole transition has been validated and applied, so a refusal leaves
// the caller's state byte-identical. Every handler validates before it mutates so
// the copy is never half-written in a way that could be observed.
//
// The authoritative counters (tick, revision, and generation) are stamped by the
// applier, not by the payload. A payload therefore cannot lie about which
// generation it produced.

namespace power_control_plane {
namespace {

using detail::check_count;
using detail::read_enum;
using detail::read_list;
using detail::read_text;
using detail::write_enum;
using detail::write_list;
using detail::write_text;

constexpr std::uint8_t kModeMax = 6;
constexpr std::uint8_t kTransitionKindMax = 21;
constexpr std::uint8_t kAttemptEventKindMax = 10;
constexpr std::uint8_t kAttemptStateMax = 10;
constexpr std::uint8_t kPermissionStateMax = 4;

bool mode_preserves_continuity(OperatingMode mode) noexcept {
  return mode != OperatingMode::emergency && mode != OperatingMode::isolated;
}

bool permission_scopes_overlap(const PermissionGrant& a, const PermissionGrant& b) noexcept {
  bool kind_overlap = false;
  for (const ActionKind kind : a.kinds) {
    if (std::find(b.kinds.begin(), b.kinds.end(), kind) != b.kinds.end()) {
      kind_overlap = true;
      break;
    }
  }
  if (!kind_overlap) {
    return false;
  }
  if (a.targets.empty() || b.targets.empty()) {
    return true;
  }
  for (const ActionTargetId& target : a.targets) {
    if (std::find(b.targets.begin(), b.targets.end(), target) != b.targets.end()) {
      return true;
    }
  }
  return false;
}

// Legal attempt state machine. The applier additionally requires that the payload
// field matching the event is populated, and that no other field is.
bool attempt_successor(AttemptState from, AttemptEventKind event, AttemptState& out) noexcept {
  switch (from) {
    case AttemptState::authorized:
      if (event == AttemptEventKind::issued) {
        out = AttemptState::issued;
        return true;
      }
      break;
    case AttemptState::issued:
      if (event == AttemptEventKind::acknowledged) {
        out = AttemptState::acknowledged;
        return true;
      }
      if (event == AttemptEventKind::effect_failed) {
        out = AttemptState::effect_failed;
        return true;
      }
      if (event == AttemptEventKind::refused) {
        out = AttemptState::refused;
        return true;
      }
      break;
    case AttemptState::acknowledged:
      if (event == AttemptEventKind::effect_observed) {
        out = AttemptState::effect_observed;
        return true;
      }
      if (event == AttemptEventKind::effect_failed) {
        out = AttemptState::effect_failed;
        return true;
      }
      if (event == AttemptEventKind::verification_failed) {
        out = AttemptState::verification_failed;
        return true;
      }
      break;
    case AttemptState::effect_observed:
      if (event == AttemptEventKind::verification_passed) {
        out = AttemptState::verified;
        return true;
      }
      if (event == AttemptEventKind::verification_failed) {
        out = AttemptState::verification_failed;
        return true;
      }
      break;
    case AttemptState::verified:
    case AttemptState::refused:
    case AttemptState::cancelled:
    case AttemptState::superseded:
    case AttemptState::effect_failed:
    case AttemptState::verification_failed:
      break;
  }
  if (event == AttemptEventKind::cancelled) {
    if (!attempt_is_terminal(from)) {
      out = AttemptState::cancelled;
      return true;
    }
    return false;
  }
  if (event == AttemptEventKind::superseded) {
    if (!attempt_is_terminal(from)) {
      out = AttemptState::superseded;
      return true;
    }
    return false;
  }
  return false;
}

Status normalize_kinds(std::vector<ActionKind>& kinds, std::size_t bound) {
  PCP_TRY_STATUS(check_count(kinds.size(), bound, "action kind scope"));
  std::sort(kinds.begin(), kinds.end());
  kinds.erase(std::unique(kinds.begin(), kinds.end()), kinds.end());
  if (kinds.empty()) {
    return Status::failure(ErrorCode::invalid_argument,
                           "permission scope must name at least one action kind");
  }
  return Status::success();
}

Status normalize_targets(std::vector<ActionTargetId>& targets, std::size_t bound) {
  PCP_TRY_STATUS(check_count(targets.size(), bound, "action target scope"));
  std::sort(targets.begin(), targets.end());
  targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
  return Status::success();
}

}  // namespace

std::size_t transition_payload_bound(const Limits& limits) noexcept {
  return limits.max_text_field_bytes * 16;
}

bool transition_changes_control_generation(TransitionKind kind) noexcept {
  return kind == TransitionKind::facility_bootstrap ||
         kind == TransitionKind::mode_transition;
}

Status encode_identity_payload(CanonicalWriter& writer, std::string_view id,
                               std::size_t max_bytes) {
  return write_text(writer, id, max_bytes);
}

Result<std::string> decode_identity_payload(CanonicalReader& reader, std::size_t max_bytes) {
  return read_text(reader, max_bytes);
}

Status encode_bootstrap_payload(CanonicalWriter& writer, const BootstrapPayload& value,
                                const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.facility.view(), FacilityId::kMaxLength));
  writer.u64(value.incarnation.high());
  writer.u64(value.incarnation.low());
  PCP_TRY_STATUS(write_enum(writer, value.mode));
  PCP_TRY_STATUS(value.evidence.encode(writer, limits));
  return Status::success();
}

Result<BootstrapPayload> decode_bootstrap_payload(CanonicalReader& reader,
                                                  const Limits& limits) {
  auto facility_text = read_text(reader, FacilityId::kMaxLength);
  if (!facility_text.has_value()) {
    return facility_text.error();
  }
  auto facility = FacilityId::parse(facility_text.value());
  if (!facility.has_value()) {
    return facility.error();
  }
  auto high = reader.u64();
  if (!high.has_value()) {
    return high.error();
  }
  auto low = reader.u64();
  if (!low.has_value()) {
    return low.error();
  }
  auto mode = read_enum<OperatingMode>(reader, kModeMax, "operating mode");
  if (!mode.has_value()) {
    return mode.error();
  }
  auto evidence = EvidenceBinding::decode(reader, limits);
  if (!evidence.has_value()) {
    return evidence.error();
  }
  BootstrapPayload out;
  out.facility = facility.value();
  out.incarnation = StoreIncarnation::from_parts(high.value(), low.value());
  out.mode = mode.value();
  out.evidence = std::move(evidence).value();
  return out;
}

Status encode_mode_transition_payload(CanonicalWriter& writer,
                                      const ModeTransitionPayload& value,
                                      const Limits& limits) {
  PCP_TRY_STATUS(write_enum(writer, value.from));
  PCP_TRY_STATUS(write_enum(writer, value.to));
  PCP_TRY_STATUS(write_text(writer, value.authority.view(), AuthorityReference::kMaxLength));
  PCP_TRY_STATUS(write_list(
      writer, value.suspensions, limits.max_obligations,
      [&limits](CanonicalWriter& out, const ObligationSuspension& suspension) {
        return encode_obligation_suspension(out, suspension, limits);
      }));
  return Status::success();
}

Result<ModeTransitionPayload> decode_mode_transition_payload(CanonicalReader& reader,
                                                             const Limits& limits) {
  auto from = read_enum<OperatingMode>(reader, kModeMax, "operating mode");
  if (!from.has_value()) {
    return from.error();
  }
  auto to = read_enum<OperatingMode>(reader, kModeMax, "operating mode");
  if (!to.has_value()) {
    return to.error();
  }
  auto authority_text = read_text(reader, AuthorityReference::kMaxLength);
  if (!authority_text.has_value()) {
    return authority_text.error();
  }
  auto authority = AuthorityReference::parse(authority_text.value());
  if (!authority.has_value()) {
    return authority.error();
  }
  auto suspensions = read_list<ObligationSuspension>(
      reader, limits.max_obligations, "obligation suspension",
      [&limits](CanonicalReader& in) { return decode_obligation_suspension(in, limits); });
  if (!suspensions.has_value()) {
    return suspensions.error();
  }
  ModeTransitionPayload out;
  out.from = from.value();
  out.to = to.value();
  out.authority = authority.value();
  out.suspensions = std::move(suspensions).value();
  return out;
}

Status encode_permission_retire_payload(CanonicalWriter& writer,
                                        const PermissionRetirePayload& value,
                                        const Limits& limits) {
  writer.u64(value.id.value());
  PCP_TRY_STATUS(write_enum(writer, value.state));
  static_cast<void>(limits);
  return Status::success();
}

Result<PermissionRetirePayload> decode_permission_retire_payload(CanonicalReader& reader,
                                                                 const Limits& limits) {
  auto id = reader.u64();
  if (!id.has_value()) {
    return id.error();
  }
  auto state = read_enum<PermissionState>(reader, kPermissionStateMax, "permission state");
  if (!state.has_value()) {
    return state.error();
  }
  static_cast<void>(limits);
  PermissionRetirePayload out;
  out.id = PermissionId(id.value());
  out.state = state.value();
  return out;
}

Status encode_attempt_authorized_payload(CanonicalWriter& writer,
                                          const AttemptAuthorizedPayload& value,
                                          const Limits& limits) {
  PCP_TRY_STATUS(encode_attempt(writer, value.attempt, limits));
  writer.u64(value.permission.value());
  return Status::success();
}

Result<AttemptAuthorizedPayload> decode_attempt_authorized_payload(CanonicalReader& reader,
                                                                   const Limits& limits) {
  auto attempt = decode_attempt(reader, limits);
  if (!attempt.has_value()) {
    return attempt.error();
  }
  auto permission = reader.u64();
  if (!permission.has_value()) {
    return permission.error();
  }
  AttemptAuthorizedPayload out;
  out.attempt = std::move(attempt).value();
  out.permission = PermissionId(permission.value());
  return out;
}

Status encode_attempt_transition_payload(CanonicalWriter& writer,
                                         const AttemptTransitionPayload& value,
                                         const Limits& limits) {
  writer.u64(value.attempt.value());
  PCP_TRY_STATUS(write_enum(writer, value.event));
  writer.digest(value.payload_digest);
  PCP_TRY_STATUS(write_text(writer, value.detail, limits.max_text_field_bytes));
  PCP_TRY_STATUS(write_enum(writer, value.resulting_state));
  writer.boolean(value.acknowledgement.has_value());
  if (value.acknowledgement.has_value()) {
    PCP_TRY_STATUS(encode_acknowledgement(writer, *value.acknowledgement, limits));
  }
  writer.boolean(value.effect.has_value());
  if (value.effect.has_value()) {
    PCP_TRY_STATUS(encode_observed_effect(writer, *value.effect, limits));
  }
  writer.boolean(value.verification.has_value());
  if (value.verification.has_value()) {
    PCP_TRY_STATUS(encode_verification_report(writer, *value.verification, limits));
  }
  return Status::success();
}

Result<AttemptTransitionPayload> decode_attempt_transition_payload(CanonicalReader& reader,
                                                                   const Limits& limits) {
  auto attempt = reader.u64();
  if (!attempt.has_value()) {
    return attempt.error();
  }
  auto event = read_enum<AttemptEventKind>(reader, kAttemptEventKindMax, "attempt event kind");
  if (!event.has_value()) {
    return event.error();
  }
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.error();
  }
  auto detail = read_text(reader, limits.max_text_field_bytes);
  if (!detail.has_value()) {
    return detail.error();
  }
  auto state = read_enum<AttemptState>(reader, kAttemptStateMax, "attempt state");
  if (!state.has_value()) {
    return state.error();
  }
  AttemptTransitionPayload out;
  out.attempt = AttemptId(attempt.value());
  out.event = event.value();
  out.payload_digest = digest.value();
  out.detail = std::move(detail).value();
  out.resulting_state = state.value();
  auto has_ack = reader.boolean();
  if (!has_ack.has_value()) {
    return has_ack.error();
  }
  if (has_ack.value()) {
    auto ack = decode_acknowledgement(reader, limits);
    if (!ack.has_value()) {
      return ack.error();
    }
    out.acknowledgement = std::move(ack).value();
  }
  auto has_effect = reader.boolean();
  if (!has_effect.has_value()) {
    return has_effect.error();
  }
  if (has_effect.value()) {
    auto effect = decode_observed_effect(reader, limits);
    if (!effect.has_value()) {
      return effect.error();
    }
    out.effect = std::move(effect).value();
  }
  auto has_verification = reader.boolean();
  if (!has_verification.has_value()) {
    return has_verification.error();
  }
  if (has_verification.value()) {
    auto report = decode_verification_report(reader, limits);
    if (!report.has_value()) {
      return report.error();
    }
    out.verification = std::move(report).value();
  }
  return out;
}

namespace {

// ---------------------------------------------------------------------------
// Per-kind application. Each handler validates completely, then mutates.
// ---------------------------------------------------------------------------

Status apply_facility_bootstrap(detail::StateEditor& editor, CanonicalReader& reader,
                                const Limits& limits,
                                const BootstrapPayload& payload) {
  static_cast<void>(limits);
  if (editor.state().has_authoritative_generation()) {
    return Status::failure(ErrorCode::invalid_transition,
                           "a facility bootstrap is only valid when no authoritative "
                           "generation exists");
  }
  if (!(payload.facility == editor.state().facility())) {
    return Status::failure(ErrorCode::conflict,
                           "bootstrap payload names a different facility than the store");
  }
  if (!(payload.incarnation == editor.state().incarnation())) {
    return Status::failure(ErrorCode::conflict,
                           "bootstrap payload names a different store incarnation");
  }
  switch (payload.mode) {
    case OperatingMode::normal:
    case OperatingMode::maintenance:
    case OperatingMode::degraded:
      break;
    case OperatingMode::failover:
    case OperatingMode::emergency:
    case OperatingMode::isolated:
      return Status::failure(ErrorCode::invalid_transition,
                             "a facility cannot be bootstrapped directly into failover, "
                             "emergency, or isolated");
  }
  editor.mode() = payload.mode;
  editor.evidence() = payload.evidence;
  PCP_TRY_STATUS(reader.expect_end());
  return Status::success();
}

Status apply_mode_transition(detail::StateEditor& editor, CanonicalReader& reader,
                             const Limits& limits, std::uint64_t next_generation,
                             StateRevision next_revision, LogicalTick next_tick,
                             const ModeTransitionPayload& payload) {
  static_cast<void>(limits);
  PCP_TRY_STATUS(reader.expect_end());
  if (!(payload.from == editor.state().mode())) {
    return Status::failure(ErrorCode::stale_generation,
                           "mode transition was planned against a different operating mode");
  }
  const ModeTransitionRule* rule = find_mode_transition(payload.from, payload.to);
  if (rule == nullptr) {
    return Status::failure(ErrorCode::invalid_transition,
                           "the requested operating mode transition is not permitted");
  }
  // The mode transition table is a fact about the electrical model. The engine
  // enforces its evidence and permission requirements before it builds a
  // transition; the structural obligation rule below is re-checked here so that a
  // payload which skipped the engine still cannot drop an obligation or mark one
  // suspended without an authority reference.
  if (rule->requires_permission && rule->required_kind == 0) {
    return Status::failure(ErrorCode::internal_failure,
                           "mode transition table entry requires a permission but names "
                           "no permission kind");
  }

  // Validation pass. Nothing is mutated until every suspension has been checked.
  std::vector<const ObligationSuspension*> accepted;
  accepted.reserve(payload.suspensions.size());
  for (const ObligationSuspension& suspension : payload.suspensions) {
    if (suspension.record.authority.empty()) {
      return Status::failure(ErrorCode::blocked_by_obligation,
                             "an obligation suspension must name the external authority "
                             "that permitted it");
    }
    if (suspension.record.generation.value() > next_generation) {
      return Status::failure(ErrorCode::invalid_argument,
                             "suspension names a generation that does not exist yet");
    }
    const ProtectedObligation* existing =
        editor.state().find_obligation(suspension.obligation);
    if (existing == nullptr) {
      return Status::failure(ErrorCode::not_found,
                             "a suspension names an obligation the facility does not have");
    }
    if (existing->state != ObligationState::active) {
      return Status::failure(ErrorCode::conflict,
                             "a suspension names an obligation that is not active");
    }
    for (const ObligationSuspension* earlier : accepted) {
      if (earlier->obligation == suspension.obligation) {
        return Status::failure(ErrorCode::duplicate_identity,
                               "the same obligation is suspended twice in one transition");
      }
    }
    accepted.push_back(&suspension);
  }

  // Every continuity-required obligation that is still active must be covered when
  // the target mode does not preserve continuity. This is the rule that makes
  // "obligations cannot be silently dropped" structural rather than aspirational.
  if (!mode_preserves_continuity(payload.to)) {
    for (const ProtectedObligation& obligation : editor.state().obligations()) {
      if (!obligation.continuity_required || obligation.state != ObligationState::active) {
        continue;
      }
      bool covered = false;
      for (const ObligationSuspension* suspension : accepted) {
        if (suspension->obligation == obligation.id) {
          covered = true;
          break;
        }
      }
      if (!covered) {
        return Status::failure(
            ErrorCode::blocked_by_obligation,
            "the target operating mode does not preserve continuity and a "
            "continuity-required obligation has no authority-bound suspension");
      }
    }
  }

  // Apply: mode, history, and suspensions. No obligation is ever removed here and
  // no obligation outside the suspension list changes state.
  editor.mode() = payload.to;
  ModeHistoryEntry entry;
  entry.generation = ControlGeneration(next_generation);
  entry.revision = next_revision;
  entry.from = payload.from;
  entry.to = payload.to;
  entry.tick = next_tick;
  entry.authority = payload.authority;
  PCP_TRY_STATUS(editor.upsert_mode_history(std::move(entry), limits));

  for (const ObligationSuspension* suspension : accepted) {
    ProtectedObligation* obligation = editor.mutable_obligation(suspension->obligation);
    if (obligation == nullptr) {
      return Status::failure(ErrorCode::internal_failure,
                             "obligation disappeared during transition application");
    }
    obligation->state = ObligationState::suspended;
    obligation->suspension = suspension->record;
  }
  return Status::success();
}

Status apply_evidence_rebound(detail::StateEditor& editor, CanonicalReader& reader,
                              const Limits& limits) {
  auto binding = EvidenceBinding::decode(reader, limits);
  if (!binding.has_value()) {
    return binding.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  editor.evidence() = std::move(binding).value();
  return Status::success();
}

Status apply_policy_rebound(detail::StateEditor& editor, CanonicalReader& reader,
                            const Limits& limits) {
  auto policy = PowerPolicy::decode(reader, limits);
  if (!policy.has_value()) {
    return policy.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  if (!(policy.value().revision() > editor.state().policy_revision())) {
    return Status::failure(ErrorCode::invalid_transition,
                           "a policy rebind must advance the policy revision; otherwise a "
                           "permission issued under the old rules would silently remain valid");
  }
  editor.policy() = std::move(policy).value();
  editor.policy_revision() = editor.policy().revision();
  return Status::success();
}

Status apply_interlock_recorded(detail::StateEditor& editor, CanonicalReader& reader,
                                const Limits& limits, std::uint64_t next_generation) {
  auto decoded = decode_interlock(reader, limits);
  if (!decoded.has_value()) {
    return decoded.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  Interlock interlock = std::move(decoded).value();
  if (interlock.declared_generation.value() > next_generation) {
    return Status::failure(ErrorCode::invalid_argument,
                           "interlock declares a generation that does not exist yet");
  }
  if (interlock.source.empty()) {
    return Status::failure(ErrorCode::invalid_argument,
                           "interlock must name the runtime that published it");
  }
  interlock.updated_generation = ControlGeneration(next_generation);
  return editor.upsert_interlock(std::move(interlock), limits);
}

Status apply_interlock_removed(detail::StateEditor& editor, CanonicalReader& reader,
                               const Limits& limits) {
  auto text = decode_identity_payload(reader, InterlockId::kMaxLength);
  if (!text.has_value()) {
    return text.error();
  }
  auto id = InterlockId::parse(text.value());
  if (!id.has_value()) {
    return id.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  static_cast<void>(limits);
  if (!editor.erase_interlock(id.value())) {
    return Status::failure(ErrorCode::not_found, "no interlock has that identity");
  }
  return Status::success();
}

Status apply_obligation_recorded(detail::StateEditor& editor, CanonicalReader& reader,
                                 const Limits& limits) {
  auto decoded = decode_obligation(reader, limits);
  if (!decoded.has_value()) {
    return decoded.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  ProtectedObligation obligation = std::move(decoded).value();
  if (obligation.authority_source.empty() || obligation.authority_reference.empty()) {
    return Status::failure(ErrorCode::invalid_argument,
                           "a protected obligation must name the external authority that "
                           "owns it");
  }
  if (obligation.state == ObligationState::suspended && !obligation.suspension.has_value()) {
    return Status::failure(ErrorCode::blocked_by_obligation,
                           "an obligation cannot be recorded as suspended without the "
                           "authority-bound suspension that released it");
  }
  return editor.upsert_obligation(std::move(obligation), limits);
}

Status apply_obligation_removed(detail::StateEditor& editor, CanonicalReader& reader,
                                const Limits& limits) {
  auto text = decode_identity_payload(reader, ObligationId::kMaxLength);
  if (!text.has_value()) {
    return text.error();
  }
  auto id = ObligationId::parse(text.value());
  if (!id.has_value()) {
    return id.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  static_cast<void>(limits);
  const ProtectedObligation* existing = editor.state().find_obligation(id.value());
  if (existing == nullptr) {
    return Status::failure(ErrorCode::not_found, "no protected obligation has that identity");
  }
  if (existing->continuity_required && existing->state == ObligationState::active) {
    return Status::failure(ErrorCode::blocked_by_obligation,
                           "a continuity-required obligation cannot be removed while it is "
                           "active; it must be suspended by an external authority first");
  }
  if (!editor.erase_obligation(id.value())) {
    return Status::failure(ErrorCode::not_found, "no protected obligation has that identity");
  }
  return Status::success();
}

Status apply_commitment_recorded(detail::StateEditor& editor, CanonicalReader& reader,
                                 const Limits& limits) {
  auto decoded = decode_commitment(reader, limits);
  if (!decoded.has_value()) {
    return decoded.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  CapacityCommitment commitment = std::move(decoded).value();
  if (commitment.source.empty() || commitment.authority_reference.empty()) {
    return Status::failure(ErrorCode::invalid_argument,
                           "a capacity commitment must name the external authority that "
                           "published it");
  }
  return editor.upsert_commitment(std::move(commitment), limits);
}

Status apply_commitment_removed(detail::StateEditor& editor, CanonicalReader& reader,
                                const Limits& limits) {
  auto text = decode_identity_payload(reader, CapacityCommitmentId::kMaxLength);
  if (!text.has_value()) {
    return text.error();
  }
  auto id = CapacityCommitmentId::parse(text.value());
  if (!id.has_value()) {
    return id.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  static_cast<void>(limits);
  if (!editor.erase_commitment(id.value())) {
    return Status::failure(ErrorCode::not_found, "no capacity commitment has that identity");
  }
  return Status::success();
}

Status apply_permission_granted(detail::StateEditor& editor, CanonicalReader& reader,
                                const Limits& limits, std::uint64_t next_generation,
                                StateRevision next_revision) {
  auto decoded = decode_permission(reader, limits);
  if (!decoded.has_value()) {
    return decoded.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  PermissionGrant grant = std::move(decoded).value();
  if (!(grant.id == editor.state().next_permission_id())) {
    return Status::failure(ErrorCode::conflict,
                           "permission identity does not match the store allocator");
  }
  PCP_TRY_STATUS(normalize_kinds(grant.kinds, limits.max_permission_scope_kinds));
  PCP_TRY_STATUS(normalize_targets(grant.targets, limits.max_permission_scope_targets));
  if (grant.granted_by.empty()) {
    return Status::failure(ErrorCode::invalid_argument,
                           "a permission must name the authority that granted it");
  }
  if (grant.max_uses == 0) {
    return Status::failure(ErrorCode::invalid_argument,
                           "a permission must allow at least one use");
  }
  if (!(grant.expiry_generation > grant.issued_generation)) {
    return Status::failure(ErrorCode::invalid_argument,
                           "permission lifetime must advance the control generation");
  }
  if (!(grant.expiry_revision > grant.issued_revision)) {
    return Status::failure(ErrorCode::invalid_argument,
                           "permission lifetime must advance the publication revision");
  }
  if (grant.issued_generation.value() > next_generation ||
      grant.issued_revision.value() > next_revision.value()) {
    return Status::failure(ErrorCode::invalid_argument,
                           "permission names an authority that does not exist yet");
  }
  for (PermissionGrant& existing : editor.permissions()) {
    if (existing.state == PermissionState::active &&
        permission_scopes_overlap(existing, grant)) {
      existing.state = PermissionState::superseded;
      existing.updated_revision = next_revision;
    }
  }
  PCP_TRY_STATUS(editor.upsert_permission(std::move(grant), limits));
  auto advanced = editor.next_permission_id().next();
  if (!advanced.has_value()) {
    return advanced.error();
  }
  editor.next_permission_id() = advanced.value();
  return Status::success();
}

Status apply_permission_retired(detail::StateEditor& editor, CanonicalReader& reader,
                                const Limits& limits, StateRevision next_revision) {
  auto decoded = decode_permission_retire_payload(reader, limits);
  if (!decoded.has_value()) {
    return decoded.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  static_cast<void>(limits);
  const PermissionRetirePayload& payload = decoded.value();
  PermissionGrant* grant = editor.mutable_permission(payload.id);
  if (grant == nullptr) {
    return Status::failure(ErrorCode::not_found, "no permission has that identity");
  }
  if (grant->state != PermissionState::active) {
    return Status::failure(ErrorCode::conflict,
                           "only an active permission can be retired");
  }
  if (payload.state == PermissionState::active) {
    return Status::failure(ErrorCode::invalid_argument,
                           "retiring a permission cannot set it back to active");
  }
  grant->state = payload.state;
  grant->updated_revision = next_revision;
  return Status::success();
}

Status apply_attempt_authorized(detail::StateEditor& editor, CanonicalReader& reader,
                                const Limits& limits, std::uint64_t next_generation,
                                StateRevision next_revision, LogicalTick next_tick) {
  auto decoded = decode_attempt_authorized_payload(reader, limits);
  if (!decoded.has_value()) {
    return decoded.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  AttemptRecord attempt = std::move(decoded.value().attempt);
  const PermissionId consumed = decoded.value().permission;
  if (!(attempt.id == editor.state().next_attempt_id())) {
    return Status::failure(ErrorCode::conflict,
                           "attempt identity does not match the store allocator");
  }
  if (attempt.key.is_zero()) {
    return Status::failure(ErrorCode::invalid_argument,
                           "an attempt must carry a non-zero idempotency key");
  }
  if (editor.operation_index().find(attempt.key) != editor.operation_index().end()) {
    return Status::failure(ErrorCode::duplicate_identity,
                           "an operation with this idempotency key is already committed");
  }
  attempt.state = AttemptState::authorized;
  attempt.authorized_generation = ControlGeneration(next_generation);
  attempt.authorized_revision = next_revision;
  attempt.updated_generation = ControlGeneration(next_generation);
  attempt.updated_revision = next_revision;
  attempt.replay_retained = true;
  AttemptEvent event;
  event.kind = AttemptEventKind::authorized;
  event.generation = ControlGeneration(next_generation);
  event.revision = next_revision;
  event.tick = next_tick;
  event.payload_digest = attempt.key.digest();
  event.detail = "authorized";
  attempt.events.clear();
  attempt.events.push_back(std::move(event));

  // The permission is spent in the same publication that creates the attempt.
  if (!consumed.is_zero()) {
    PermissionGrant* grant = editor.mutable_permission(consumed);
    if (grant == nullptr) {
      return Status::failure(ErrorCode::not_found,
                             "the consumed permission does not exist in the state");
    }
    if (grant->state != PermissionState::active) {
      return Status::failure(ErrorCode::conflict,
                             "the consumed permission is not active");
    }
    if (grant->uses >= grant->max_uses) {
      return Status::failure(ErrorCode::conflict,
                             "the consumed permission has no uses left");
    }
    grant->uses += 1;
    grant->updated_revision = next_revision;
    if (grant->uses >= grant->max_uses) {
      grant->state = PermissionState::exhausted;
    }
  }

  PCP_TRY_STATUS(editor.upsert_attempt(std::move(attempt), limits));
  auto advanced = editor.next_attempt_id().next();
  if (!advanced.has_value()) {
    return advanced.error();
  }
  editor.next_attempt_id() = advanced.value();
  return Status::success();
}

Status apply_attempt_transition(detail::StateEditor& editor, CanonicalReader& reader,
                                const Limits& limits, std::uint64_t next_generation,
                                StateRevision next_revision, LogicalTick next_tick) {
  auto decoded = decode_attempt_transition_payload(reader, limits);
  if (!decoded.has_value()) {
    return decoded.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  const AttemptTransitionPayload& payload = decoded.value();
  AttemptRecord* attempt = editor.mutable_attempt(payload.attempt);
  if (attempt == nullptr) {
    return Status::failure(ErrorCode::not_found, "no attempt has that identity");
  }
  AttemptState successor = attempt->state;
  if (!attempt_successor(attempt->state, payload.event, successor)) {
    return Status::failure(ErrorCode::invalid_transition,
                           "the attempt is not in a state that permits this event");
  }
  if (successor != payload.resulting_state) {
    return Status::failure(ErrorCode::conflict,
                           "the payload declares a different resulting attempt state");
  }
  // Exactly the field matching the event must be populated.
  const bool needs_ack = payload.event == AttemptEventKind::acknowledged;
  const bool needs_effect = payload.event == AttemptEventKind::effect_observed ||
                            payload.event == AttemptEventKind::effect_failed;
  const bool needs_verification =
      payload.event == AttemptEventKind::verification_passed ||
      payload.event == AttemptEventKind::verification_failed;
  if (payload.acknowledgement.has_value() != needs_ack ||
      payload.effect.has_value() != needs_effect ||
      payload.verification.has_value() != needs_verification) {
    return Status::failure(ErrorCode::invalid_argument,
                           "the attempt payload does not carry exactly the evidence its "
                           "event requires");
  }
  if (needs_ack && payload.acknowledgement->adapter.empty()) {
    return Status::failure(ErrorCode::invalid_argument,
                           "an acknowledgement must name the adapter that produced it");
  }
  if (needs_effect && payload.effect->adapter.empty()) {
    return Status::failure(ErrorCode::invalid_argument,
                           "an observation must name the adapter that produced it");
  }
  if (needs_verification && payload.verification->verifier.empty()) {
    return Status::failure(ErrorCode::invalid_argument,
                           "a verification must name the adapter that produced it");
  }
  // Acknowledgement is not effect and effect is not verified completion: a
  // verification produced by the same adapter that acknowledged the command is
  // refused, because it is not independent evidence.
  if (needs_verification && attempt->acknowledgement.has_value() &&
      attempt->acknowledgement->adapter == payload.verification->verifier) {
    return Status::failure(
        ErrorCode::conflict,
        "a verification report must come from a different adapter than the one that "
        "acknowledged the command");
  }
  if (payload.event == AttemptEventKind::acknowledged &&
      attempt->acknowledgement.has_value()) {
    return Status::failure(ErrorCode::conflict,
                           "the attempt already carries an acknowledgement");
  }
  if (needs_effect && attempt->effect.has_value()) {
    return Status::failure(ErrorCode::conflict,
                           "the attempt already carries an observed effect");
  }
  if (needs_verification && attempt->verification.has_value()) {
    return Status::failure(ErrorCode::conflict,
                           "the attempt already carries a verification report");
  }

  if (needs_ack) {
    attempt->acknowledgement = payload.acknowledgement;
  }
  if (needs_effect) {
    attempt->effect = payload.effect;
  }
  if (needs_verification) {
    attempt->verification = payload.verification;
  }
  attempt->state = successor;
  attempt->updated_generation = ControlGeneration(next_generation);
  attempt->updated_revision = next_revision;
  AttemptEvent event;
  event.kind = payload.event;
  event.generation = ControlGeneration(next_generation);
  event.revision = next_revision;
  event.tick = next_tick;
  event.payload_digest = payload.payload_digest;
  event.detail = payload.detail;
  PCP_TRY_STATUS(check_count(attempt->events.size() + 1, limits.max_attempt_events,
                             "attempt event"));
  attempt->events.push_back(std::move(event));
  return Status::success();
}

Status apply_in_place(FacilityState& state, const TransitionRecord& record,
                      const Limits& limits) {
  PCP_TRY_STATUS(check_count(record.payload.size(), transition_payload_bound(limits),
                             "transition payload"));
  detail::StateEditor editor(state);
  CanonicalReader reader(record.payload);

  auto next_tick = checked_increment(state.tick().value());
  if (!next_tick.has_value()) {
    return next_tick.error();
  }
  auto next_revision = checked_increment(state.revision().value());
  if (!next_revision.has_value()) {
    return next_revision.error();
  }
  std::uint64_t next_generation = state.generation().value();
  if (transition_changes_control_generation(record.kind)) {
    auto advanced = checked_increment(next_generation);
    if (!advanced.has_value()) {
      return advanced.error();
    }
    next_generation = advanced.value();
  }

  const Digest previous_digest =
      record.kind == TransitionKind::facility_bootstrap ? Digest::zero()
                                                        : state.canonical_digest();

  Status applied = Status::success();
  switch (record.kind) {
    case TransitionKind::facility_bootstrap: {
      auto payload = decode_bootstrap_payload(reader, limits);
      if (!payload.has_value()) {
        return payload.error();
      }
      applied = apply_facility_bootstrap(editor, reader, limits, payload.value());
      break;
    }
    case TransitionKind::mode_transition: {
      auto payload = decode_mode_transition_payload(reader, limits);
      if (!payload.has_value()) {
        return payload.error();
      }
      applied = apply_mode_transition(editor, reader, limits, next_generation,
                                      StateRevision(next_revision.value()),
                                      LogicalTick(next_tick.value()), payload.value());
      break;
    }
    case TransitionKind::evidence_rebound:
      applied = apply_evidence_rebound(editor, reader, limits);
      break;
    case TransitionKind::policy_rebound:
      applied = apply_policy_rebound(editor, reader, limits);
      break;
    case TransitionKind::interlock_recorded:
      applied = apply_interlock_recorded(editor, reader, limits, next_generation);
      break;
    case TransitionKind::interlock_removed:
      applied = apply_interlock_removed(editor, reader, limits);
      break;
    case TransitionKind::obligation_recorded:
      applied = apply_obligation_recorded(editor, reader, limits);
      break;
    case TransitionKind::obligation_removed:
      applied = apply_obligation_removed(editor, reader, limits);
      break;
    case TransitionKind::commitment_recorded:
      applied = apply_commitment_recorded(editor, reader, limits);
      break;
    case TransitionKind::commitment_removed:
      applied = apply_commitment_removed(editor, reader, limits);
      break;
    case TransitionKind::permission_granted:
      applied = apply_permission_granted(editor, reader, limits, next_generation,
                                         StateRevision(next_revision.value()));
      break;
    case TransitionKind::permission_retired:
      applied = apply_permission_retired(editor, reader, limits,
                                         StateRevision(next_revision.value()));
      break;
    case TransitionKind::attempt_authorized:
      applied = apply_attempt_authorized(editor, reader, limits, next_generation,
                                         StateRevision(next_revision.value()),
                                         LogicalTick(next_tick.value()));
      break;
    case TransitionKind::attempt_issued:
    case TransitionKind::attempt_acknowledged:
    case TransitionKind::attempt_effect_observed:
    case TransitionKind::attempt_effect_failed:
    case TransitionKind::attempt_verified:
    case TransitionKind::attempt_verification_failed:
    case TransitionKind::attempt_cancelled:
    case TransitionKind::attempt_superseded:
      applied = apply_attempt_transition(editor, reader, limits, next_generation,
                                         StateRevision(next_revision.value()),
                                         LogicalTick(next_tick.value()));
      break;
  }
  PCP_TRY_STATUS(applied);

  editor.tick() = LogicalTick(next_tick.value());
  editor.revision() = StateRevision(next_revision.value());
  editor.generation() = ControlGeneration(next_generation);

  TransitionLogEntry entry;
  entry.generation = ControlGeneration(next_generation);
  entry.revision = StateRevision(next_revision.value());
  entry.kind = record.kind;
  entry.key = record.key;
  entry.previous_state_digest = previous_digest;
  entry.tick = LogicalTick(next_tick.value());
  entry.payload = record.payload;
  PCP_TRY_STATUS(editor.append_transition_log(std::move(entry), limits));

  // Every published transition that was committed under an idempotency key is
  // recorded in the committed-operation index, so a retry of any verb - not only an
  // action - is answered from the result that was actually published.
  if (!record.key.is_zero()) {
    CommittedOperation operation;
    operation.key = record.key;
    operation.kind = record.kind;
    operation.generation = ControlGeneration(next_generation);
    operation.revision = StateRevision(next_revision.value());
    operation.outcome = DecisionOutcome::accepted;
    operation.tick = LogicalTick(next_tick.value());
    if (record.kind == TransitionKind::attempt_authorized && !editor.attempts().empty()) {
      operation.attempt = editor.attempts().back().id;
      operation.attempt_state = editor.attempts().back().state;
    }
    editor.operation_index().insert_or_assign(record.key, std::move(operation));
  }

  std::uint64_t attempts_removed = 0;
  std::uint64_t replay_removed = 0;
  PCP_TRY_STATUS(detail::enforce_retention(editor, limits, attempts_removed,
                                          replay_removed));
  return Status::success();
}

}  // namespace

Status apply_transition(FacilityState& state, const TransitionRecord& record,
                        const Limits& limits) {
  FacilityState candidate = state;
  PCP_TRY_STATUS(apply_in_place(candidate, record, limits));
  state = std::move(candidate);
  return Status::success();
}

}  // namespace power_control_plane
