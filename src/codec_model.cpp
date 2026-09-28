#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "detail/codec_util.hpp"
#include "power_control_plane/attempt.hpp"
#include "power_control_plane/evidence.hpp"
#include "power_control_plane/interlock.hpp"
#include "power_control_plane/obligation.hpp"
#include "power_control_plane/permission.hpp"
#include "power_control_plane/policy.hpp"

// Canonical encoders and decoders for the model value types. Every decoder is
// bounded, rejects unknown ordinals, and requires the payload to end exactly where
// the decoder stopped.

namespace power_control_plane {
namespace {

using detail::check_count;
using detail::read_enum;
using detail::read_list;
using detail::read_text;
using detail::write_enum;
using detail::write_list;
using detail::write_text;

constexpr std::uint8_t kEvidenceKindMax = 11;
constexpr std::uint8_t kInterlockSeverityMax = 3;
constexpr std::uint8_t kInterlockStateMax = 3;
constexpr std::uint8_t kObligationStateMax = 2;
constexpr std::uint8_t kPolicyEffectMax = 4;
constexpr std::uint8_t kPolicyConditionKindMax = 8;
constexpr std::uint8_t kPermissionStateMax = 4;
constexpr std::uint8_t kAttemptStateMax = 10;
constexpr std::uint8_t kAttemptEventKindMax = 10;

Status encode_evidence_ref(CanonicalWriter& writer, const EvidenceRef& value,
                           const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.source.view(), EvidenceSourceId::kMaxLength));
  PCP_TRY_STATUS(write_enum(writer, value.kind));
  writer.u64(value.generation.value());
  writer.u64(value.revision.value());
  writer.u64(value.epoch.value());
  writer.u64(value.incarnation.high());
  writer.u64(value.incarnation.low());
  writer.digest(value.content_digest);
  static_cast<void>(limits);
  return Status::success();
}

Result<EvidenceRef> decode_evidence_ref(CanonicalReader& reader, const Limits& limits) {
  auto source = read_text(reader, EvidenceSourceId::kMaxLength);
  if (!source.has_value()) {
    return source.error();
  }
  auto parsed_source = EvidenceSourceId::parse(source.value());
  if (!parsed_source.has_value()) {
    return parsed_source.error();
  }
  auto kind = read_enum<EvidenceKind>(reader, kEvidenceKindMax, "evidence kind");
  if (!kind.has_value()) {
    return kind.error();
  }
  auto generation = reader.u64();
  if (!generation.has_value()) {
    return generation.error();
  }
  auto revision = reader.u64();
  if (!revision.has_value()) {
    return revision.error();
  }
  auto epoch = reader.u64();
  if (!epoch.has_value()) {
    return epoch.error();
  }
  auto incarnation_high = reader.u64();
  if (!incarnation_high.has_value()) {
    return incarnation_high.error();
  }
  auto incarnation_low = reader.u64();
  if (!incarnation_low.has_value()) {
    return incarnation_low.error();
  }
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.error();
  }
  static_cast<void>(limits);
  EvidenceRef ref;
  ref.source = parsed_source.value();
  ref.kind = kind.value();
  ref.generation = EvidenceGeneration(generation.value());
  ref.revision = EvidenceRevision(revision.value());
  ref.epoch = ControllerEpoch(epoch.value());
  ref.incarnation = ControllerIncarnation::from_parts(incarnation_high.value(),
                                                     incarnation_low.value());
  ref.content_digest = digest.value();
  return ref;
}

Status encode_scope_kinds(CanonicalWriter& writer, const std::vector<ActionKind>& kinds,
                          const Limits& limits) {
  return write_list(writer, kinds, limits.max_permission_scope_kinds,
                    [](CanonicalWriter& out, ActionKind kind) { return write_enum(out, kind); });
}

Result<std::vector<ActionKind>> decode_scope_kinds(CanonicalReader& reader,
                                                   const Limits& limits) {
  return read_list<ActionKind>(
      reader, limits.max_permission_scope_kinds, "action kind scope",
      [](CanonicalReader& in) { return read_enum<ActionKind>(in, 14, "action kind"); });
}

Status encode_target_list(CanonicalWriter& writer, const std::vector<ActionTargetId>& targets,
                          const Limits& limits, std::size_t bound) {
  return write_list(writer, targets, bound, [&limits](CanonicalWriter& out,
                                                     const ActionTargetId& target) {
    static_cast<void>(limits);
    return write_text(out, target.view(), ActionTargetId::kMaxLength);
  });
}

Result<std::vector<ActionTargetId>> decode_target_list(CanonicalReader& reader,
                                                       std::size_t bound) {
  return read_list<ActionTargetId>(reader, bound, "action target scope",
                                   [](CanonicalReader& in) {
                                     auto text = read_text(in, ActionTargetId::kMaxLength);
                                     if (!text.has_value()) {
                                       return Result<ActionTargetId>(text.error());
                                     }
                                     return ActionTargetId::parse(text.value());
                                   });
}

}  // namespace

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

bool operator==(const EvidenceRef& a, const EvidenceRef& b) noexcept {
  return a.source == b.source && a.kind == b.kind && a.generation == b.generation &&
         a.revision == b.revision && a.epoch == b.epoch &&
         a.incarnation == b.incarnation && a.content_digest == b.content_digest;
}

bool operator!=(const EvidenceRef& a, const EvidenceRef& b) noexcept { return !(a == b); }

bool operator<(const EvidenceRef& a, const EvidenceRef& b) noexcept {
  return a.source < b.source;
}

Result<EvidenceBinding> EvidenceBinding::create(std::vector<EvidenceRef> refs,
                                                const Limits& limits) {
  PCP_TRY_STATUS(detail::check_count(refs.size(), limits.max_evidence_bindings, "evidence"));
  std::sort(refs.begin(), refs.end());
  for (std::size_t index = 0; index < refs.size(); ++index) {
    if (refs[index].source.empty()) {
      return Error(ErrorCode::invalid_argument,
                   "evidence reference has no source identity");
    }
    if (index > 0 && refs[index].source == refs[index - 1].source) {
      return Error(ErrorCode::duplicate_identity,
                   "evidence binding names the same source twice");
    }
  }
  EvidenceBinding binding;
  binding.refs_ = std::move(refs);
  return binding;
}

const EvidenceRef* EvidenceBinding::find(const EvidenceSourceId& source) const noexcept {
  EvidenceRef probe;
  probe.source = source;
  const auto position = std::lower_bound(refs_.begin(), refs_.end(), probe);
  if (position == refs_.end() || !(position->source == source)) {
    return nullptr;
  }
  return &(*position);
}

bool EvidenceBinding::matches(const EvidenceBinding& other) const noexcept {
  if (refs_.size() != other.refs_.size()) {
    return false;
  }
  for (std::size_t index = 0; index < refs_.size(); ++index) {
    if (!(refs_[index] == other.refs_[index])) {
      return false;
    }
  }
  return true;
}

Status EvidenceBinding::encode(CanonicalWriter& writer, const Limits& limits) const {
  return write_list(writer, refs_, limits.max_evidence_bindings,
                    [&limits](CanonicalWriter& out, const EvidenceRef& ref) {
                      return encode_evidence_ref(out, ref, limits);
                    });
}

Result<EvidenceBinding> EvidenceBinding::decode(CanonicalReader& reader,
                                                const Limits& limits) {
  auto refs = read_list<EvidenceRef>(
      reader, limits.max_evidence_bindings, "evidence reference",
      [&limits](CanonicalReader& in) { return decode_evidence_ref(in, limits); });
  if (!refs.has_value()) {
    return refs.error();
  }
  return EvidenceBinding::create(std::move(refs).value(), limits);
}

Digest EvidenceBinding::digest() const {
  CanonicalWriter writer;
  const Limits& limits = Limits::defaults();
  if (!encode(writer, limits).ok()) {
    return Digest::zero();
  }
  const Bytes bytes = writer.buffer();
  return sha256_domain("pcp/evidence-binding/v1", bytes.data(), bytes.size());
}

// ---------------------------------------------------------------------------
// Interlocks
// ---------------------------------------------------------------------------

Status encode_interlock(CanonicalWriter& writer, const Interlock& value,
                        const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.id.view(), InterlockId::kMaxLength));
  PCP_TRY_STATUS(write_text(writer, value.source.view(), EvidenceSourceId::kMaxLength));
  PCP_TRY_STATUS(write_enum(writer, value.severity));
  PCP_TRY_STATUS(write_enum(writer, value.state));
  writer.u64(value.declared_generation.value());
  writer.u64(value.updated_generation.value());
  PCP_TRY_STATUS(encode_scope_kinds(writer, value.scope_kinds, limits));
  PCP_TRY_STATUS(encode_target_list(writer, value.scope_targets, limits,
                                    limits.max_scope_targets));
  PCP_TRY_STATUS(write_text(writer, value.explanation, limits.max_text_field_bytes));
  return Status::success();
}

Result<Interlock> decode_interlock(CanonicalReader& reader, const Limits& limits) {
  auto id_text = read_text(reader, InterlockId::kMaxLength);
  if (!id_text.has_value()) {
    return id_text.error();
  }
  auto id = InterlockId::parse(id_text.value());
  if (!id.has_value()) {
    return id.error();
  }
  auto source_text = read_text(reader, EvidenceSourceId::kMaxLength);
  if (!source_text.has_value()) {
    return source_text.error();
  }
  auto source = EvidenceSourceId::parse(source_text.value());
  if (!source.has_value()) {
    return source.error();
  }
  auto severity = read_enum<InterlockSeverity>(reader, kInterlockSeverityMax, "interlock severity");
  if (!severity.has_value()) {
    return severity.error();
  }
  auto state = read_enum<InterlockState>(reader, kInterlockStateMax, "interlock state");
  if (!state.has_value()) {
    return state.error();
  }
  auto declared = reader.u64();
  if (!declared.has_value()) {
    return declared.error();
  }
  auto updated = reader.u64();
  if (!updated.has_value()) {
    return updated.error();
  }
  auto kinds = decode_scope_kinds(reader, limits);
  if (!kinds.has_value()) {
    return kinds.error();
  }
  auto targets = decode_target_list(reader, limits.max_scope_targets);
  if (!targets.has_value()) {
    return targets.error();
  }
  auto explanation = read_text(reader, limits.max_text_field_bytes);
  if (!explanation.has_value()) {
    return explanation.error();
  }
  Interlock out;
  out.id = id.value();
  out.source = source.value();
  out.severity = severity.value();
  out.state = state.value();
  out.declared_generation = ControlGeneration(declared.value());
  out.updated_generation = ControlGeneration(updated.value());
  out.scope_kinds = std::move(kinds).value();
  out.scope_targets = std::move(targets).value();
  out.explanation = std::move(explanation).value();
  return out;
}

// ---------------------------------------------------------------------------
// Obligations and commitments
// ---------------------------------------------------------------------------

Status encode_suspension(CanonicalWriter& writer, const SuspensionRecord& value,
                         const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.authority.view(), AuthorityReference::kMaxLength));
  writer.u64(value.generation.value());
  writer.u64(value.tick.value());
  PCP_TRY_STATUS(write_text(writer, value.reason, limits.max_text_field_bytes));
  return Status::success();
}

Result<SuspensionRecord> decode_suspension(CanonicalReader& reader, const Limits& limits) {
  auto authority_text = read_text(reader, AuthorityReference::kMaxLength);
  if (!authority_text.has_value()) {
    return authority_text.error();
  }
  auto authority = AuthorityReference::parse(authority_text.value());
  if (!authority.has_value()) {
    return authority.error();
  }
  auto generation = reader.u64();
  if (!generation.has_value()) {
    return generation.error();
  }
  auto tick = reader.u64();
  if (!tick.has_value()) {
    return tick.error();
  }
  auto reason = read_text(reader, limits.max_text_field_bytes);
  if (!reason.has_value()) {
    return reason.error();
  }
  SuspensionRecord out;
  out.authority = authority.value();
  out.generation = ControlGeneration(generation.value());
  out.tick = LogicalTick(tick.value());
  out.reason = std::move(reason).value();
  return out;
}

Status encode_obligation_suspension(CanonicalWriter& writer,
                                   const ObligationSuspension& value,
                                   const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.obligation.view(), ObligationId::kMaxLength));
  PCP_TRY_STATUS(encode_suspension(writer, value.record, limits));
  return Status::success();
}

Result<ObligationSuspension> decode_obligation_suspension(CanonicalReader& reader,
                                                          const Limits& limits) {
  auto id_text = read_text(reader, ObligationId::kMaxLength);
  if (!id_text.has_value()) {
    return id_text.error();
  }
  auto id = ObligationId::parse(id_text.value());
  if (!id.has_value()) {
    return id.error();
  }
  auto record = decode_suspension(reader, limits);
  if (!record.has_value()) {
    return record.error();
  }
  ObligationSuspension out;
  out.obligation = id.value();
  out.record = std::move(record).value();
  return out;
}

Status encode_obligation(CanonicalWriter& writer, const ProtectedObligation& value,
                         const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.id.view(), ObligationId::kMaxLength));
  PCP_TRY_STATUS(write_text(writer, value.authority_source.view(), EvidenceSourceId::kMaxLength));
  PCP_TRY_STATUS(
      write_text(writer, value.authority_reference.view(), AuthorityReference::kMaxLength));
  PCP_TRY_STATUS(encode_scope_kinds(writer, value.scope_kinds, limits));
  PCP_TRY_STATUS(
      encode_target_list(writer, value.scope_targets, limits, limits.max_scope_targets));
  PCP_TRY_STATUS(write_enum(writer, value.state));
  writer.boolean(value.continuity_required);
  writer.boolean(value.suspension.has_value());
  if (value.suspension.has_value()) {
    PCP_TRY_STATUS(encode_suspension(writer, *value.suspension, limits));
  }
  PCP_TRY_STATUS(write_text(writer, value.description, limits.max_text_field_bytes));
  return Status::success();
}

Result<ProtectedObligation> decode_obligation(CanonicalReader& reader, const Limits& limits) {
  auto id_text = read_text(reader, ObligationId::kMaxLength);
  if (!id_text.has_value()) {
    return id_text.error();
  }
  auto id = ObligationId::parse(id_text.value());
  if (!id.has_value()) {
    return id.error();
  }
  auto source_text = read_text(reader, EvidenceSourceId::kMaxLength);
  if (!source_text.has_value()) {
    return source_text.error();
  }
  auto source = EvidenceSourceId::parse(source_text.value());
  if (!source.has_value()) {
    return source.error();
  }
  auto authority_text = read_text(reader, AuthorityReference::kMaxLength);
  if (!authority_text.has_value()) {
    return authority_text.error();
  }
  auto authority = AuthorityReference::parse(authority_text.value());
  if (!authority.has_value()) {
    return authority.error();
  }
  auto kinds = decode_scope_kinds(reader, limits);
  if (!kinds.has_value()) {
    return kinds.error();
  }
  auto targets = decode_target_list(reader, limits.max_scope_targets);
  if (!targets.has_value()) {
    return targets.error();
  }
  auto state = read_enum<ObligationState>(reader, kObligationStateMax, "obligation state");
  if (!state.has_value()) {
    return state.error();
  }
  auto continuity = reader.boolean();
  if (!continuity.has_value()) {
    return continuity.error();
  }
  auto has_suspension = reader.boolean();
  if (!has_suspension.has_value()) {
    return has_suspension.error();
  }
  std::optional<SuspensionRecord> suspension;
  if (has_suspension.value()) {
    auto decoded = decode_suspension(reader, limits);
    if (!decoded.has_value()) {
      return decoded.error();
    }
    suspension = std::move(decoded).value();
  }
  auto description = read_text(reader, limits.max_text_field_bytes);
  if (!description.has_value()) {
    return description.error();
  }
  ProtectedObligation out;
  out.id = id.value();
  out.authority_source = source.value();
  out.authority_reference = authority.value();
  out.scope_kinds = std::move(kinds).value();
  out.scope_targets = std::move(targets).value();
  out.state = state.value();
  out.continuity_required = continuity.value();
  out.suspension = std::move(suspension);
  out.description = std::move(description).value();
  return out;
}

Status encode_commitment(CanonicalWriter& writer, const CapacityCommitment& value,
                         const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.id.view(), CapacityCommitmentId::kMaxLength));
  PCP_TRY_STATUS(write_text(writer, value.source.view(), EvidenceSourceId::kMaxLength));
  PCP_TRY_STATUS(
      write_text(writer, value.authority_reference.view(), AuthorityReference::kMaxLength));
  writer.u64(value.committed_kw);
  writer.boolean(value.active);
  PCP_TRY_STATUS(
      encode_target_list(writer, value.targets, limits, limits.max_scope_targets));
  PCP_TRY_STATUS(encode_evidence_ref(writer, value.evidence, limits));
  return Status::success();
}

Result<CapacityCommitment> decode_commitment(CanonicalReader& reader, const Limits& limits) {
  auto id_text = read_text(reader, CapacityCommitmentId::kMaxLength);
  if (!id_text.has_value()) {
    return id_text.error();
  }
  auto id = CapacityCommitmentId::parse(id_text.value());
  if (!id.has_value()) {
    return id.error();
  }
  auto source_text = read_text(reader, EvidenceSourceId::kMaxLength);
  if (!source_text.has_value()) {
    return source_text.error();
  }
  auto source = EvidenceSourceId::parse(source_text.value());
  if (!source.has_value()) {
    return source.error();
  }
  auto authority_text = read_text(reader, AuthorityReference::kMaxLength);
  if (!authority_text.has_value()) {
    return authority_text.error();
  }
  auto authority = AuthorityReference::parse(authority_text.value());
  if (!authority.has_value()) {
    return authority.error();
  }
  auto committed = reader.u64();
  if (!committed.has_value()) {
    return committed.error();
  }
  auto active = reader.boolean();
  if (!active.has_value()) {
    return active.error();
  }
  auto targets = decode_target_list(reader, limits.max_scope_targets);
  if (!targets.has_value()) {
    return targets.error();
  }
  auto evidence = decode_evidence_ref(reader, limits);
  if (!evidence.has_value()) {
    return evidence.error();
  }
  CapacityCommitment out;
  out.id = id.value();
  out.source = source.value();
  out.authority_reference = authority.value();
  out.committed_kw = committed.value();
  out.active = active.value();
  out.targets = std::move(targets).value();
  out.evidence = evidence.value();
  return out;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

namespace {

Status encode_condition(CanonicalWriter& writer, const PolicyCondition& value,
                        const Limits& limits) {
  PCP_TRY_STATUS(write_enum(writer, value.kind));
  PCP_TRY_STATUS(write_enum(writer, value.mode));
  PCP_TRY_STATUS(write_enum(writer, value.action_kind));
  PCP_TRY_STATUS(write_text(writer, value.target.view(), ActionTargetId::kMaxLength));
  PCP_TRY_STATUS(write_enum(writer, value.interlock_state));
  PCP_TRY_STATUS(write_enum(writer, value.obligation_state));
  PCP_TRY_STATUS(write_text(writer, value.evidence_source.view(), EvidenceSourceId::kMaxLength));
  writer.u64(value.threshold_kw);
  static_cast<void>(limits);
  return Status::success();
}

Result<PolicyCondition> decode_condition(CanonicalReader& reader, const Limits& limits) {
  auto kind = read_enum<PolicyConditionKind>(reader, kPolicyConditionKindMax,
                                             "policy condition kind");
  if (!kind.has_value()) {
    return kind.error();
  }
  auto mode = read_enum<OperatingMode>(reader, 6, "operating mode");
  if (!mode.has_value()) {
    return mode.error();
  }
  auto action = read_enum<ActionKind>(reader, 14, "action kind");
  if (!action.has_value()) {
    return action.error();
  }
  auto target_text = read_text(reader, ActionTargetId::kMaxLength);
  if (!target_text.has_value()) {
    return target_text.error();
  }
  ActionTargetId target;
  if (!target_text.value().empty()) {
    auto parsed = ActionTargetId::parse(target_text.value());
    if (!parsed.has_value()) {
      return parsed.error();
    }
    target = parsed.value();
  }
  auto interlock_state = read_enum<InterlockState>(reader, kInterlockStateMax, "interlock state");
  if (!interlock_state.has_value()) {
    return interlock_state.error();
  }
  auto obligation_state = read_enum<ObligationState>(reader, kObligationStateMax,
                                                     "obligation state");
  if (!obligation_state.has_value()) {
    return obligation_state.error();
  }
  auto source_text = read_text(reader, EvidenceSourceId::kMaxLength);
  if (!source_text.has_value()) {
    return source_text.error();
  }
  EvidenceSourceId source;
  if (!source_text.value().empty()) {
    auto parsed = EvidenceSourceId::parse(source_text.value());
    if (!parsed.has_value()) {
      return parsed.error();
    }
    source = parsed.value();
  }
  auto threshold = reader.u64();
  if (!threshold.has_value()) {
    return threshold.error();
  }
  static_cast<void>(limits);
  PolicyCondition out;
  out.kind = kind.value();
  out.mode = mode.value();
  out.action_kind = action.value();
  out.target = target;
  out.interlock_state = interlock_state.value();
  out.obligation_state = obligation_state.value();
  out.evidence_source = source;
  out.threshold_kw = threshold.value();
  return out;
}

}  // namespace

Status encode_policy_rule(CanonicalWriter& writer, const PolicyRule& rule,
                          const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, rule.id.view(), RuleId::kMaxLength));
  writer.u32(rule.order);
  PCP_TRY_STATUS(encode_condition(writer, rule.condition, limits));
  PCP_TRY_STATUS(write_enum(writer, rule.effect));
  PCP_TRY_STATUS(write_text(writer, rule.explanation, limits.max_text_field_bytes));
  return Status::success();
}

Result<PolicyRule> decode_policy_rule(CanonicalReader& reader, const Limits& limits) {
  auto id_text = read_text(reader, RuleId::kMaxLength);
  if (!id_text.has_value()) {
    return id_text.error();
  }
  auto id = RuleId::parse(id_text.value());
  if (!id.has_value()) {
    return id.error();
  }
  auto order = reader.u32();
  if (!order.has_value()) {
    return order.error();
  }
  auto condition = decode_condition(reader, limits);
  if (!condition.has_value()) {
    return condition.error();
  }
  auto effect = read_enum<PolicyEffect>(reader, kPolicyEffectMax, "policy effect");
  if (!effect.has_value()) {
    return effect.error();
  }
  auto explanation = read_text(reader, limits.max_text_field_bytes);
  if (!explanation.has_value()) {
    return explanation.error();
  }
  PolicyRule out;
  out.id = id.value();
  out.order = order.value();
  out.condition = condition.value();
  out.effect = effect.value();
  out.explanation = std::move(explanation).value();
  return out;
}

Result<PowerPolicy> PowerPolicy::create(PolicyRevision revision,
                                        std::vector<PolicyRule> rules,
                                        const Limits& limits) {
  PCP_TRY_STATUS(detail::check_count(rules.size(), limits.max_policy_rules, "policy rule"));
  std::sort(rules.begin(), rules.end(),
            [](const PolicyRule& a, const PolicyRule& b) {
              if (a.order != b.order) {
                return a.order < b.order;
              }
              return a.id < b.id;
            });
  for (std::size_t index = 1; index < rules.size(); ++index) {
    if (rules[index].id == rules[index - 1].id) {
      return Error(ErrorCode::duplicate_identity, "policy names the same rule twice");
    }
  }
  PowerPolicy policy;
  policy.revision_ = revision;
  policy.rules_ = std::move(rules);
  return policy;
}

Status PowerPolicy::encode(CanonicalWriter& writer, const Limits& limits) const {
  writer.u64(revision_.value());
  return write_list(writer, rules_, limits.max_policy_rules,
                    [&limits](CanonicalWriter& out, const PolicyRule& rule) {
                      return encode_policy_rule(out, rule, limits);
                    });
}

Result<PowerPolicy> PowerPolicy::decode(CanonicalReader& reader, const Limits& limits) {
  auto revision = reader.u64();
  if (!revision.has_value()) {
    return revision.error();
  }
  auto rules = read_list<PolicyRule>(
      reader, limits.max_policy_rules, "policy rule",
      [&limits](CanonicalReader& in) { return decode_policy_rule(in, limits); });
  if (!rules.has_value()) {
    return rules.error();
  }
  return PowerPolicy::create(PolicyRevision(revision.value()), std::move(rules).value(), limits);
}

Digest PowerPolicy::digest() const {
  CanonicalWriter writer;
  const Limits& limits = Limits::defaults();
  if (!encode(writer, limits).ok()) {
    return Digest::zero();
  }
  const Bytes bytes = writer.buffer();
  return sha256_domain("pcp/power-policy/v1", bytes.data(), bytes.size());
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

Status encode_permission(CanonicalWriter& writer, const PermissionGrant& value,
                         const Limits& limits) {
  writer.u64(value.id.value());
  PCP_TRY_STATUS(encode_scope_kinds(writer, value.kinds, limits));
  PCP_TRY_STATUS(encode_target_list(writer, value.targets, limits,
                                    limits.max_permission_scope_targets));
  writer.u64(value.issued_generation.value());
  writer.u64(value.expiry_generation.value());
  writer.u64(value.issued_revision.value());
  writer.u64(value.expiry_revision.value());
  writer.u64(value.policy_revision.value());
  PCP_TRY_STATUS(value.evidence.encode(writer, limits));
  PCP_TRY_STATUS(write_enum(writer, value.state));
  PCP_TRY_STATUS(write_text(writer, value.granted_by.view(), AuthorityReference::kMaxLength));
  writer.u32(value.max_uses);
  writer.u32(value.uses);
  writer.u64(value.updated_revision.value());
  return Status::success();
}

Result<PermissionGrant> decode_permission(CanonicalReader& reader, const Limits& limits) {
  auto id = reader.u64();
  if (!id.has_value()) {
    return id.error();
  }
  auto kinds = decode_scope_kinds(reader, limits);
  if (!kinds.has_value()) {
    return kinds.error();
  }
  auto targets = decode_target_list(reader, limits.max_permission_scope_targets);
  if (!targets.has_value()) {
    return targets.error();
  }
  auto issued_generation = reader.u64();
  if (!issued_generation.has_value()) {
    return issued_generation.error();
  }
  auto expiry_generation = reader.u64();
  if (!expiry_generation.has_value()) {
    return expiry_generation.error();
  }
  auto issued_revision = reader.u64();
  if (!issued_revision.has_value()) {
    return issued_revision.error();
  }
  auto expiry_revision = reader.u64();
  if (!expiry_revision.has_value()) {
    return expiry_revision.error();
  }
  auto policy_revision = reader.u64();
  if (!policy_revision.has_value()) {
    return policy_revision.error();
  }
  auto evidence = EvidenceBinding::decode(reader, limits);
  if (!evidence.has_value()) {
    return evidence.error();
  }
  auto state = read_enum<PermissionState>(reader, kPermissionStateMax, "permission state");
  if (!state.has_value()) {
    return state.error();
  }
  auto authority_text = read_text(reader, AuthorityReference::kMaxLength);
  if (!authority_text.has_value()) {
    return authority_text.error();
  }
  auto authority = AuthorityReference::parse(authority_text.value());
  if (!authority.has_value()) {
    return authority.error();
  }
  auto max_uses = reader.u32();
  if (!max_uses.has_value()) {
    return max_uses.error();
  }
  auto uses = reader.u32();
  if (!uses.has_value()) {
    return uses.error();
  }
  auto updated_revision = reader.u64();
  if (!updated_revision.has_value()) {
    return updated_revision.error();
  }
  PermissionGrant out;
  out.id = PermissionId(id.value());
  out.kinds = std::move(kinds).value();
  out.targets = std::move(targets).value();
  out.issued_generation = ControlGeneration(issued_generation.value());
  out.expiry_generation = ControlGeneration(expiry_generation.value());
  out.issued_revision = StateRevision(issued_revision.value());
  out.expiry_revision = StateRevision(expiry_revision.value());
  out.policy_revision = PolicyRevision(policy_revision.value());
  out.evidence = std::move(evidence).value();
  out.state = state.value();
  out.granted_by = authority.value();
  out.max_uses = max_uses.value();
  out.uses = uses.value();
  out.updated_revision = StateRevision(updated_revision.value());
  return out;
}

// ---------------------------------------------------------------------------
// Attempts
// ---------------------------------------------------------------------------

namespace {

Status encode_attempt_event(CanonicalWriter& writer, const AttemptEvent& value,
                            const Limits& limits) {
  PCP_TRY_STATUS(write_enum(writer, value.kind));
  writer.u64(value.generation.value());
  writer.u64(value.revision.value());
  writer.u64(value.tick.value());
  writer.digest(value.payload_digest);
  PCP_TRY_STATUS(write_text(writer, value.detail, limits.max_text_field_bytes));
  return Status::success();
}

Result<AttemptEvent> decode_attempt_event(CanonicalReader& reader, const Limits& limits) {
  auto kind = read_enum<AttemptEventKind>(reader, kAttemptEventKindMax, "attempt event kind");
  if (!kind.has_value()) {
    return kind.error();
  }
  auto generation = reader.u64();
  if (!generation.has_value()) {
    return generation.error();
  }
  auto revision = reader.u64();
  if (!revision.has_value()) {
    return revision.error();
  }
  auto tick = reader.u64();
  if (!tick.has_value()) {
    return tick.error();
  }
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.error();
  }
  auto detail = read_text(reader, limits.max_text_field_bytes);
  if (!detail.has_value()) {
    return detail.error();
  }
  AttemptEvent out;
  out.kind = kind.value();
  out.generation = ControlGeneration(generation.value());
  out.revision = StateRevision(revision.value());
  out.tick = LogicalTick(tick.value());
  out.payload_digest = digest.value();
  out.detail = std::move(detail).value();
  return out;
}

Status encode_intent(CanonicalWriter& writer, const ActionIntent& value,
                     const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.id.view(), ActionId::kMaxLength));
  PCP_TRY_STATUS(write_enum(writer, value.kind));
  PCP_TRY_STATUS(write_text(writer, value.target.view(), ActionTargetId::kMaxLength));
  writer.u64(value.planned.generation.value());
  writer.u64(value.planned.revision.value());
  writer.u64(value.planned.policy_revision.value());
  writer.digest(value.planned.evidence_digest);
  writer.u64(value.requested_load_kw);
  static_cast<void>(limits);
  return Status::success();
}

Result<ActionIntent> decode_intent(CanonicalReader& reader, const Limits& limits) {
  auto id_text = read_text(reader, ActionId::kMaxLength);
  if (!id_text.has_value()) {
    return id_text.error();
  }
  auto id = ActionId::parse(id_text.value());
  if (!id.has_value()) {
    return id.error();
  }
  auto kind = read_enum<ActionKind>(reader, 14, "action kind");
  if (!kind.has_value()) {
    return kind.error();
  }
  auto target_text = read_text(reader, ActionTargetId::kMaxLength);
  if (!target_text.has_value()) {
    return target_text.error();
  }
  auto target = ActionTargetId::parse(target_text.value());
  if (!target.has_value()) {
    return target.error();
  }
  auto generation = reader.u64();
  if (!generation.has_value()) {
    return generation.error();
  }
  auto revision = reader.u64();
  if (!revision.has_value()) {
    return revision.error();
  }
  auto policy = reader.u64();
  if (!policy.has_value()) {
    return policy.error();
  }
  auto evidence = reader.digest();
  if (!evidence.has_value()) {
    return evidence.error();
  }
  auto load = reader.u64();
  if (!load.has_value()) {
    return load.error();
  }
  static_cast<void>(limits);
  ActionIntent out;
  out.id = id.value();
  out.kind = kind.value();
  out.target = target.value();
  out.planned.generation = ControlGeneration(generation.value());
  out.planned.revision = StateRevision(revision.value());
  out.planned.policy_revision = PolicyRevision(policy.value());
  out.planned.evidence_digest = evidence.value();
  out.requested_load_kw = load.value();
  return out;
}

}  // namespace

Status encode_attempt(CanonicalWriter& writer, const AttemptRecord& value,
                      const Limits& limits) {
  writer.u64(value.id.value());
  writer.digest(value.key.digest());
  PCP_TRY_STATUS(encode_intent(writer, value.intent, limits));
  PCP_TRY_STATUS(write_enum(writer, value.state));
  writer.u64(value.authorized_generation.value());
  writer.u64(value.authorized_revision.value());
  writer.u64(value.updated_generation.value());
  writer.u64(value.updated_revision.value());
  PCP_TRY_STATUS(write_list(writer, value.events, limits.max_attempt_events,
                            [&limits](CanonicalWriter& out, const AttemptEvent& event) {
                              return encode_attempt_event(out, event, limits);
                            }));
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
  writer.boolean(value.replay_retained);
  return Status::success();
}

Result<AttemptRecord> decode_attempt(CanonicalReader& reader, const Limits& limits) {
  auto id = reader.u64();
  if (!id.has_value()) {
    return id.error();
  }
  auto key_digest = reader.digest();
  if (!key_digest.has_value()) {
    return key_digest.error();
  }
  auto key = IdempotencyKey::from_digest(key_digest.value());
  if (!key.has_value()) {
    return key.error();
  }
  auto intent = decode_intent(reader, limits);
  if (!intent.has_value()) {
    return intent.error();
  }
  auto state = read_enum<AttemptState>(reader, kAttemptStateMax, "attempt state");
  if (!state.has_value()) {
    return state.error();
  }
  auto authorized_generation = reader.u64();
  if (!authorized_generation.has_value()) {
    return authorized_generation.error();
  }
  auto authorized_revision = reader.u64();
  if (!authorized_revision.has_value()) {
    return authorized_revision.error();
  }
  auto updated_generation = reader.u64();
  if (!updated_generation.has_value()) {
    return updated_generation.error();
  }
  auto updated_revision = reader.u64();
  if (!updated_revision.has_value()) {
    return updated_revision.error();
  }
  auto events = read_list<AttemptEvent>(
      reader, limits.max_attempt_events, "attempt event",
      [&limits](CanonicalReader& in) { return decode_attempt_event(in, limits); });
  if (!events.has_value()) {
    return events.error();
  }

  AttemptRecord out;
  out.id = AttemptId(id.value());
  out.key = key.value();
  out.intent = std::move(intent).value();
  out.state = state.value();
  out.authorized_generation = ControlGeneration(authorized_generation.value());
  out.authorized_revision = StateRevision(authorized_revision.value());
  out.updated_generation = ControlGeneration(updated_generation.value());
  out.updated_revision = StateRevision(updated_revision.value());
  out.events = std::move(events).value();

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

  auto retained = reader.boolean();
  if (!retained.has_value()) {
    return retained.error();
  }
  out.replay_retained = retained.value();
  return out;
}

Status encode_acknowledgement(CanonicalWriter& writer, const Acknowledgement& value,
                              const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.adapter.view(), AdapterId::kMaxLength));
  writer.digest(value.command_digest);
  PCP_TRY_STATUS(write_text(writer, value.detail, limits.max_text_field_bytes));
  return Status::success();
}

Result<Acknowledgement> decode_acknowledgement(CanonicalReader& reader,
                                               const Limits& limits) {
  auto adapter_text = read_text(reader, AdapterId::kMaxLength);
  if (!adapter_text.has_value()) {
    return adapter_text.error();
  }
  auto adapter = AdapterId::parse(adapter_text.value());
  if (!adapter.has_value()) {
    return adapter.error();
  }
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.error();
  }
  auto detail = read_text(reader, limits.max_text_field_bytes);
  if (!detail.has_value()) {
    return detail.error();
  }
  Acknowledgement out;
  out.adapter = adapter.value();
  out.command_digest = digest.value();
  out.detail = std::move(detail).value();
  return out;
}

Status encode_observed_effect(CanonicalWriter& writer, const ObservedEffect& value,
                              const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.adapter.view(), AdapterId::kMaxLength));
  writer.digest(value.observation_digest);
  PCP_TRY_STATUS(write_text(writer, value.detail, limits.max_text_field_bytes));
  return Status::success();
}

Result<ObservedEffect> decode_observed_effect(CanonicalReader& reader, const Limits& limits) {
  auto adapter_text = read_text(reader, AdapterId::kMaxLength);
  if (!adapter_text.has_value()) {
    return adapter_text.error();
  }
  auto adapter = AdapterId::parse(adapter_text.value());
  if (!adapter.has_value()) {
    return adapter.error();
  }
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.error();
  }
  auto detail = read_text(reader, limits.max_text_field_bytes);
  if (!detail.has_value()) {
    return detail.error();
  }
  ObservedEffect out;
  out.adapter = adapter.value();
  out.observation_digest = digest.value();
  out.detail = std::move(detail).value();
  return out;
}

Status encode_verification_report(CanonicalWriter& writer, const VerificationReport& value,
                                  const Limits& limits) {
  PCP_TRY_STATUS(write_text(writer, value.verifier.view(), AdapterId::kMaxLength));
  writer.boolean(value.matches_intent);
  writer.digest(value.evidence_digest);
  PCP_TRY_STATUS(write_text(writer, value.detail, limits.max_text_field_bytes));
  return Status::success();
}

Result<VerificationReport> decode_verification_report(CanonicalReader& reader,
                                                      const Limits& limits) {
  auto verifier_text = read_text(reader, AdapterId::kMaxLength);
  if (!verifier_text.has_value()) {
    return verifier_text.error();
  }
  auto verifier = AdapterId::parse(verifier_text.value());
  if (!verifier.has_value()) {
    return verifier.error();
  }
  auto matches = reader.boolean();
  if (!matches.has_value()) {
    return matches.error();
  }
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.error();
  }
  auto detail = read_text(reader, limits.max_text_field_bytes);
  if (!detail.has_value()) {
    return detail.error();
  }
  VerificationReport out;
  out.verifier = verifier.value();
  out.matches_intent = matches.value();
  out.evidence_digest = digest.value();
  out.detail = std::move(detail).value();
  return out;
}

}  // namespace power_control_plane
