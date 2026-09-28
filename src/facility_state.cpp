#include <algorithm>
#include <utility>

#include "detail/codec_util.hpp"
#include "power_control_plane/state.hpp"

namespace power_control_plane {
namespace {

using detail::check_count;
using detail::read_list;
using detail::read_text;
using detail::write_list;
using detail::write_text;

Status encode_mode_history(CanonicalWriter& writer, const std::vector<ModeHistoryEntry>& entries,
                           const Limits& limits) {
  return write_list(writer, entries, limits.max_mode_history,
                    [&limits](CanonicalWriter& out, const ModeHistoryEntry& entry) -> Status {
                      out.u64(entry.generation.value());
                      out.u64(entry.revision.value());
                      PCP_TRY_STATUS(detail::write_enum(out, entry.from));
                      PCP_TRY_STATUS(detail::write_enum(out, entry.to));
                      out.u64(entry.tick.value());
                      PCP_TRY_STATUS(write_text(out, entry.authority.view(),
                                                AuthorityReference::kMaxLength));
                      return Status::success();
                    });
}

Result<std::vector<ModeHistoryEntry>> decode_mode_history(CanonicalReader& reader,
                                                          const Limits& limits) {
  return read_list<ModeHistoryEntry>(
      reader, limits.max_mode_history, "mode history",
      [&limits](CanonicalReader& in) -> Result<ModeHistoryEntry> {
        auto generation = in.u64();
        if (!generation.has_value()) {
          return generation.error();
        }
        auto revision = in.u64();
        if (!revision.has_value()) {
          return revision.error();
        }
        auto from = detail::read_enum<OperatingMode>(in, 6, "operating mode");
        if (!from.has_value()) {
          return from.error();
        }
        auto to = detail::read_enum<OperatingMode>(in, 6, "operating mode");
        if (!to.has_value()) {
          return to.error();
        }
        auto tick = in.u64();
        if (!tick.has_value()) {
          return tick.error();
        }
        auto authority_text = read_text(in, AuthorityReference::kMaxLength);
        if (!authority_text.has_value()) {
          return authority_text.error();
        }
        auto authority = AuthorityReference::parse(authority_text.value());
        if (!authority.has_value()) {
          return authority.error();
        }
        ModeHistoryEntry entry;
        entry.generation = ControlGeneration(generation.value());
        entry.revision = StateRevision(revision.value());
        entry.from = from.value();
        entry.to = to.value();
        entry.tick = LogicalTick(tick.value());
        entry.authority = authority.value();
        return entry;
      });
}

Status encode_transition_log(CanonicalWriter& writer,
                             const std::vector<TransitionLogEntry>& entries,
                             const Limits& limits) {
  return write_list(writer, entries, limits.max_transition_log_entries,
                    [&limits](CanonicalWriter& out, const TransitionLogEntry& entry) -> Status {
                      out.u64(entry.generation.value());
                      out.u64(entry.revision.value());
                      PCP_TRY_STATUS(detail::write_enum(out, entry.kind));
                      out.digest(entry.key.digest());
                      out.digest(entry.previous_state_digest);
                      out.u64(entry.tick.value());
                      PCP_TRY_STATUS(out.bytes(entry.payload, limits.max_text_field_bytes * 16));
                      return Status::success();
                    });
}

Result<std::vector<TransitionLogEntry>> decode_transition_log(CanonicalReader& reader,
                                                              const Limits& limits) {
  return read_list<TransitionLogEntry>(
      reader, limits.max_transition_log_entries, "transition log",
      [&limits](CanonicalReader& in) -> Result<TransitionLogEntry> {
        auto generation = in.u64();
        if (!generation.has_value()) {
          return generation.error();
        }
        auto revision = in.u64();
        if (!revision.has_value()) {
          return revision.error();
        }
        auto kind = detail::read_enum<TransitionKind>(in, 21, "transition kind");
        if (!kind.has_value()) {
          return kind.error();
        }
        auto key_digest = in.digest();
        if (!key_digest.has_value()) {
          return key_digest.error();
        }
        auto key = IdempotencyKey::from_digest(key_digest.value());
        if (!key.has_value()) {
          return key.error();
        }
        auto previous = in.digest();
        if (!previous.has_value()) {
          return previous.error();
        }
        auto tick = in.u64();
        if (!tick.has_value()) {
          return tick.error();
        }
        auto payload = in.bytes(limits.max_text_field_bytes * 16);
        if (!payload.has_value()) {
          return payload.error();
        }
        TransitionLogEntry entry;
        entry.generation = ControlGeneration(generation.value());
        entry.revision = StateRevision(revision.value());
        entry.kind = kind.value();
        entry.key = key.value();
        entry.previous_state_digest = previous.value();
        entry.tick = LogicalTick(tick.value());
        entry.payload = std::move(payload).value();
        return entry;
      });
}

}  // namespace

FacilityState FacilityState::vacant(FacilityId facility, StoreIncarnation incarnation) {
  FacilityState state;
  state.facility_ = std::move(facility);
  state.incarnation_ = incarnation;
  return state;
}

const Interlock* FacilityState::find_interlock(const InterlockId& id) const noexcept {
  const auto position = std::lower_bound(
      interlocks_.begin(), interlocks_.end(), id,
      [](const Interlock& interlock, const InterlockId& key) { return interlock.id < key; });
  if (position == interlocks_.end() || !(position->id == id)) {
    return nullptr;
  }
  return &(*position);
}

const ProtectedObligation* FacilityState::find_obligation(const ObligationId& id) const noexcept {
  const auto position = std::lower_bound(
      obligations_.begin(), obligations_.end(), id,
      [](const ProtectedObligation& item, const ObligationId& key) { return item.id < key; });
  if (position == obligations_.end() || !(position->id == id)) {
    return nullptr;
  }
  return &(*position);
}

const CapacityCommitment* FacilityState::find_commitment(
    const CapacityCommitmentId& id) const noexcept {
  const auto position = std::lower_bound(
      commitments_.begin(), commitments_.end(), id,
      [](const CapacityCommitment& item, const CapacityCommitmentId& key) {
        return item.id < key;
      });
  if (position == commitments_.end() || !(position->id == id)) {
    return nullptr;
  }
  return &(*position);
}

const PermissionGrant* FacilityState::find_permission(const PermissionId& id) const noexcept {
  const auto position = std::lower_bound(
      permissions_.begin(), permissions_.end(), id,
      [](const PermissionGrant& item, const PermissionId& key) { return item.id < key; });
  if (position == permissions_.end() || !(position->id == id)) {
    return nullptr;
  }
  return &(*position);
}

const AttemptRecord* FacilityState::find_attempt(AttemptId id) const noexcept {
  const auto position = std::lower_bound(
      attempts_.begin(), attempts_.end(), id,
      [](const AttemptRecord& item, AttemptId key) { return item.id < key; });
  if (position == attempts_.end() || !(position->id == id)) {
    return nullptr;
  }
  return &(*position);
}

const CommittedOperation* FacilityState::find_operation(const IdempotencyKey& key) const noexcept {
  const auto position = operation_index_.find(key);
  if (position == operation_index_.end()) {
    return nullptr;
  }
  return &position->second;
}

const AttemptRecord* FacilityState::find_attempt_by_key(const IdempotencyKey& key) const noexcept {
  const CommittedOperation* operation = find_operation(key);
  if (operation == nullptr || operation->attempt.is_zero()) {
    return nullptr;
  }
  return find_attempt(operation->attempt);
}

ControlGeneration FacilityState::last_entry_generation(OperatingMode mode) const noexcept {
  for (auto entry = mode_history_.rbegin(); entry != mode_history_.rend(); ++entry) {
    if (entry->to == mode) {
      return entry->generation;
    }
  }
  return ControlGeneration{};
}

StateRevision FacilityState::last_entry_revision(OperatingMode mode) const noexcept {
  for (auto entry = mode_history_.rbegin(); entry != mode_history_.rend(); ++entry) {
    if (entry->to == mode) {
      return entry->revision;
    }
  }
  return StateRevision{};
}

Status encode_committed_operation(CanonicalWriter& writer,
                                  const CommittedOperation& value, const Limits& limits) {
  writer.digest(value.key.digest());
  PCP_TRY_STATUS(detail::write_enum(writer, value.kind));
  writer.u64(value.generation.value());
  writer.u64(value.revision.value());
  PCP_TRY_STATUS(detail::write_enum(writer, value.outcome));
  writer.u64(value.attempt.value());
  PCP_TRY_STATUS(detail::write_enum(writer, value.attempt_state));
  writer.u64(value.tick.value());
  static_cast<void>(limits);
  return Status::success();
}

Result<CommittedOperation> decode_committed_operation(CanonicalReader& reader,
                                                      const Limits& limits) {
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.error();
  }
  auto key = IdempotencyKey::from_digest(digest.value());
  if (!key.has_value()) {
    return key.error();
  }
  auto kind = detail::read_enum<TransitionKind>(reader, 21, "transition kind");
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
  auto outcome = detail::read_enum<DecisionOutcome>(reader, 14, "decision outcome");
  if (!outcome.has_value()) {
    return outcome.error();
  }
  auto attempt = reader.u64();
  if (!attempt.has_value()) {
    return attempt.error();
  }
  auto attempt_state = detail::read_enum<AttemptState>(reader, 10, "attempt state");
  if (!attempt_state.has_value()) {
    return attempt_state.error();
  }
  auto tick = reader.u64();
  if (!tick.has_value()) {
    return tick.error();
  }
  static_cast<void>(limits);
  CommittedOperation out;
  out.key = key.value();
  out.kind = kind.value();
  out.generation = ControlGeneration(generation.value());
  out.revision = StateRevision(revision.value());
  out.outcome = outcome.value();
  out.attempt = AttemptId(attempt.value());
  out.attempt_state = attempt_state.value();
  out.tick = LogicalTick(tick.value());
  return out;
}

Status FacilityState::encode(CanonicalWriter& writer, const Limits& limits) const {
  writer.u32(kStateEncodingVersion);
  PCP_TRY_STATUS(write_text(writer, facility_.view(), FacilityId::kMaxLength));
  writer.u64(incarnation_.high());
  writer.u64(incarnation_.low());
  writer.u64(generation_.value());
  writer.u64(revision_.value());
  writer.u64(policy_revision_.value());
  writer.u64(tick_.value());
  PCP_TRY_STATUS(detail::write_enum(writer, mode_));
  PCP_TRY_STATUS(policy_.encode(writer, limits));
  PCP_TRY_STATUS(evidence_.encode(writer, limits));

  PCP_TRY_STATUS(write_list(writer, interlocks_, limits.max_interlocks,
                            [&limits](CanonicalWriter& out, const Interlock& value) {
                              return encode_interlock(out, value, limits);
                            }));
  PCP_TRY_STATUS(write_list(writer, obligations_, limits.max_obligations,
                            [&limits](CanonicalWriter& out, const ProtectedObligation& value) {
                              return encode_obligation(out, value, limits);
                            }));
  PCP_TRY_STATUS(write_list(writer, commitments_, limits.max_capacity_commitments,
                            [&limits](CanonicalWriter& out, const CapacityCommitment& value) {
                              return encode_commitment(out, value, limits);
                            }));
  PCP_TRY_STATUS(write_list(writer, permissions_, limits.max_permissions,
                            [&limits](CanonicalWriter& out, const PermissionGrant& value) {
                              return encode_permission(out, value, limits);
                            }));
  PCP_TRY_STATUS(write_list(writer, attempts_, limits.max_attempts,
                            [&limits](CanonicalWriter& out, const AttemptRecord& value) {
                              return encode_attempt(out, value, limits);
                            }));
  // The operation index is a std::map keyed by idempotency key, so iteration is
  // already in canonical key order and the encoding is insertion-order
  // independent.
  PCP_TRY_STATUS(detail::check_count(operation_index_.size(), limits.max_replay_records,
                                     "committed operation"));
  writer.u32(static_cast<std::uint32_t>(operation_index_.size()));
  for (const auto& entry : operation_index_) {
    PCP_TRY_STATUS(encode_committed_operation(writer, entry.second, limits));
  }
  PCP_TRY_STATUS(encode_mode_history(writer, mode_history_, limits));
  PCP_TRY_STATUS(encode_transition_log(writer, transition_log_, limits));
  writer.u64(next_attempt_id_.value());
  writer.u64(next_permission_id_.value());
  writer.u64(pruned_attempts_);
  writer.u64(pruned_replay_records_);
  return Status::success();
}

Result<FacilityState> FacilityState::decode(CanonicalReader& reader, const Limits& limits) {
  auto version = reader.u32();
  if (!version.has_value()) {
    return version.error();
  }
  if (version.value() != kStateEncodingVersion) {
    return Error(ErrorCode::unsupported_format,
                 "state payload encoding version is not supported");
  }
  auto facility_text = read_text(reader, FacilityId::kMaxLength);
  if (!facility_text.has_value()) {
    return facility_text.error();
  }
  auto facility = FacilityId::parse(facility_text.value());
  if (!facility.has_value()) {
    return facility.error();
  }
  auto incarnation_high = reader.u64();
  if (!incarnation_high.has_value()) {
    return incarnation_high.error();
  }
  auto incarnation_low = reader.u64();
  if (!incarnation_low.has_value()) {
    return incarnation_low.error();
  }
  auto generation = reader.u64();
  if (!generation.has_value()) {
    return generation.error();
  }
  auto revision = reader.u64();
  if (!revision.has_value()) {
    return revision.error();
  }
  auto policy_revision = reader.u64();
  if (!policy_revision.has_value()) {
    return policy_revision.error();
  }
  auto tick = reader.u64();
  if (!tick.has_value()) {
    return tick.error();
  }
  auto mode = detail::read_enum<OperatingMode>(reader, 6, "operating mode");
  if (!mode.has_value()) {
    return mode.error();
  }
  auto policy = PowerPolicy::decode(reader, limits);
  if (!policy.has_value()) {
    return policy.error();
  }
  auto evidence = EvidenceBinding::decode(reader, limits);
  if (!evidence.has_value()) {
    return evidence.error();
  }
  auto interlocks = read_list<Interlock>(
      reader, limits.max_interlocks, "interlock",
      [&limits](CanonicalReader& in) { return decode_interlock(in, limits); });
  if (!interlocks.has_value()) {
    return interlocks.error();
  }
  auto obligations = read_list<ProtectedObligation>(
      reader, limits.max_obligations, "protected obligation",
      [&limits](CanonicalReader& in) { return decode_obligation(in, limits); });
  if (!obligations.has_value()) {
    return obligations.error();
  }
  auto commitments = read_list<CapacityCommitment>(
      reader, limits.max_capacity_commitments, "capacity commitment",
      [&limits](CanonicalReader& in) { return decode_commitment(in, limits); });
  if (!commitments.has_value()) {
    return commitments.error();
  }
  auto permissions = read_list<PermissionGrant>(
      reader, limits.max_permissions, "permission",
      [&limits](CanonicalReader& in) { return decode_permission(in, limits); });
  if (!permissions.has_value()) {
    return permissions.error();
  }
  auto attempts = read_list<AttemptRecord>(
      reader, limits.max_attempts, "attempt",
      [&limits](CanonicalReader& in) { return decode_attempt(in, limits); });
  if (!attempts.has_value()) {
    return attempts.error();
  }
  auto operations = read_list<CommittedOperation>(
      reader, limits.max_replay_records, "committed operation",
      [&limits](CanonicalReader& in) { return decode_committed_operation(in, limits); });
  if (!operations.has_value()) {
    return operations.error();
  }
  auto mode_history = decode_mode_history(reader, limits);
  if (!mode_history.has_value()) {
    return mode_history.error();
  }
  auto transition_log = decode_transition_log(reader, limits);
  if (!transition_log.has_value()) {
    return transition_log.error();
  }
  auto next_attempt_id = reader.u64();
  if (!next_attempt_id.has_value()) {
    return next_attempt_id.error();
  }
  auto next_permission_id = reader.u64();
  if (!next_permission_id.has_value()) {
    return next_permission_id.error();
  }
  auto pruned_attempts = reader.u64();
  if (!pruned_attempts.has_value()) {
    return pruned_attempts.error();
  }
  auto pruned_replay = reader.u64();
  if (!pruned_replay.has_value()) {
    return pruned_replay.error();
  }

  FacilityState state;
  state.facility_ = facility.value();
  state.incarnation_ = StoreIncarnation::from_parts(incarnation_high.value(),
                                                    incarnation_low.value());
  state.generation_ = ControlGeneration(generation.value());
  state.revision_ = StateRevision(revision.value());
  state.policy_revision_ = PolicyRevision(policy_revision.value());
  state.tick_ = LogicalTick(tick.value());
  state.mode_ = mode.value();
  state.policy_ = std::move(policy).value();
  state.evidence_ = std::move(evidence).value();
  state.interlocks_ = std::move(interlocks).value();
  state.obligations_ = std::move(obligations).value();
  state.commitments_ = std::move(commitments).value();
  state.permissions_ = std::move(permissions).value();
  state.attempts_ = std::move(attempts).value();
  state.operation_index_.clear();
  for (CommittedOperation& entry : operations.value()) {
    const auto inserted = state.operation_index_.emplace(entry.key, std::move(entry));
    if (!inserted.second) {
      return Error(ErrorCode::corrupt_store,
                   "state payload repeats an idempotency key");
    }
  }
  state.mode_history_ = std::move(mode_history).value();
  state.transition_log_ = std::move(transition_log).value();
  state.next_attempt_id_ = AttemptId(next_attempt_id.value());
  state.next_permission_id_ = PermissionId(next_permission_id.value());
  state.pruned_attempts_ = pruned_attempts.value();
  state.pruned_replay_records_ = pruned_replay.value();

  // Structural integrity of the decoded value. A persisted payload that violates
  // any of these is refused as corrupt rather than repaired.
  for (std::size_t index = 1; index < state.interlocks_.size(); ++index) {
    if (!(state.interlocks_[index - 1].id < state.interlocks_[index].id)) {
      return Error(ErrorCode::corrupt_store, "interlocks are not in canonical order");
    }
  }
  for (std::size_t index = 1; index < state.obligations_.size(); ++index) {
    if (!(state.obligations_[index - 1].id < state.obligations_[index].id)) {
      return Error(ErrorCode::corrupt_store, "obligations are not in canonical order");
    }
  }
  for (std::size_t index = 1; index < state.commitments_.size(); ++index) {
    if (!(state.commitments_[index - 1].id < state.commitments_[index].id)) {
      return Error(ErrorCode::corrupt_store, "commitments are not in canonical order");
    }
  }
  for (std::size_t index = 1; index < state.permissions_.size(); ++index) {
    if (!(state.permissions_[index - 1].id < state.permissions_[index].id)) {
      return Error(ErrorCode::corrupt_store, "permissions are not in canonical order");
    }
  }
  for (std::size_t index = 1; index < state.attempts_.size(); ++index) {
    if (!(state.attempts_[index - 1].id < state.attempts_[index].id)) {
      return Error(ErrorCode::corrupt_store, "attempts are not in canonical order");
    }
  }
  for (std::size_t index = 1; index < state.transition_log_.size(); ++index) {
    const StateRevision previous = state.transition_log_[index - 1].revision;
    const StateRevision current = state.transition_log_[index].revision;
    auto expected = previous.next();
    if (!expected.has_value() || expected.value() != current) {
      return Error(ErrorCode::corrupt_store,
                   "transition log revisions are not consecutive");
    }
    if (state.transition_log_[index].previous_state_digest.is_zero()) {
      return Error(ErrorCode::corrupt_store,
                   "transition log entry has a zero predecessor digest");
    }
  }
  if (!state.transition_log_.empty()) {
    const TransitionLogEntry& last = state.transition_log_.back();
    if (last.generation > state.generation_ || last.revision != state.revision_) {
      return Error(ErrorCode::corrupt_store,
                   "transition log does not end at the state revision");
    }
  }
  if (state.next_attempt_id_.is_zero() || state.next_permission_id_.is_zero()) {
    return Error(ErrorCode::corrupt_store, "identity allocator is zero");
  }
  for (const AttemptRecord& attempt : state.attempts_) {
    if (attempt.id >= state.next_attempt_id_) {
      return Error(ErrorCode::corrupt_store,
                   "attempt identity is not below the identity allocator");
    }
  }
  for (const PermissionGrant& grant : state.permissions_) {
    if (grant.id >= state.next_permission_id_) {
      return Error(ErrorCode::corrupt_store,
                   "permission identity is not below the identity allocator");
    }
  }
  for (const auto& entry : state.operation_index_) {
    if (!(entry.first == entry.second.key)) {
      return Error(ErrorCode::corrupt_store,
                   "a committed operation record does not match its index key");
    }
    if (entry.second.revision > state.revision_) {
      return Error(ErrorCode::corrupt_store,
                   "a committed operation names a revision that does not exist yet");
    }
  }
  return state;
}

Result<FacilityState> FacilityState::decode(const Bytes& bytes, const Limits& limits) {
  CanonicalReader reader(bytes);
  auto state = FacilityState::decode(reader, limits);
  if (!state.has_value()) {
    return state.error();
  }
  PCP_TRY_STATUS(reader.expect_end());
  return state;
}

Bytes FacilityState::encode(const Limits& limits) const {
  CanonicalWriter writer;
  if (!encode(writer, limits).ok()) {
    return Bytes{};
  }
  return writer.take();
}

Digest FacilityState::canonical_digest() const {
  const Bytes bytes = encode(Limits::defaults());
  return sha256_domain(kStateDigestDomain, bytes.data(), bytes.size());
}

}  // namespace power_control_plane
