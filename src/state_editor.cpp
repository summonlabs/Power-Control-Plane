#include "detail/state_editor.hpp"

#include <algorithm>
#include <utility>

#include "detail/codec_util.hpp"

namespace power_control_plane::detail {
namespace {

template <class T, class KeyFn>
Status bounded_upsert(std::vector<T>& items, T value, std::size_t max_count, KeyFn key,
                      std::string_view what) {
  const auto position = std::lower_bound(items.begin(), items.end(), key(value),
                                         [&key](const T& item, const auto& probe) {
                                           return key(item) < probe;
                                         });
  const bool exists = position != items.end() && key(*position) == key(value);
  if (!exists && items.size() >= max_count) {
    std::string message = "the configured bound on ";
    message.append(what);
    message.append(" entries is exhausted");
    return Status::failure(ErrorCode::limit_exceeded, std::move(message));
  }
  if (exists) {
    *position = std::move(value);
  } else {
    items.insert(position, std::move(value));
  }
  return Status::success();
}

}  // namespace

Status StateEditor::append_transition_log(TransitionLogEntry entry, const Limits& limits) {
  transition_log().push_back(std::move(entry));
  while (transition_log().size() > limits.max_transition_log_entries) {
    transition_log().erase(transition_log().begin());
  }
  return Status::success();
}

Status StateEditor::upsert_interlock(Interlock value, const Limits& limits) {
  return bounded_upsert(interlocks(), std::move(value), limits.max_interlocks,
                        [](const Interlock& item) { return item.id; }, "interlock");
}

Status StateEditor::upsert_obligation(ProtectedObligation value, const Limits& limits) {
  return bounded_upsert(obligations(), std::move(value), limits.max_obligations,
                        [](const ProtectedObligation& item) { return item.id; },
                        "protected obligation");
}

Status StateEditor::upsert_commitment(CapacityCommitment value, const Limits& limits) {
  return bounded_upsert(commitments(), std::move(value), limits.max_capacity_commitments,
                        [](const CapacityCommitment& item) { return item.id; },
                        "capacity commitment");
}

Status StateEditor::upsert_permission(PermissionGrant value, const Limits& limits) {
  return bounded_upsert(permissions(), std::move(value), limits.max_permissions,
                        [](const PermissionGrant& item) { return item.id; }, "permission");
}

Status StateEditor::upsert_attempt(AttemptRecord value, const Limits& limits) {
  // One publication may transiently hold one attempt above the retention bound, so
  // that the oldest attempt can be evicted in the same publication that adds the
  // newest. Refusing the new attempt instead would make the bound a hard cap on
  // facility activity rather than a bound on retained history.
  if (limits.max_attempts == 0) {
    return Status::failure(ErrorCode::limit_exceeded,
                           "the configured bound on retained attempts is zero");
  }
  return bounded_upsert(attempts(), std::move(value), limits.max_attempts + 1,
                        [](const AttemptRecord& item) { return item.id; }, "attempt");
}

Status StateEditor::upsert_mode_history(ModeHistoryEntry value, const Limits& limits) {
  if (mode_history().size() >= limits.max_mode_history) {
    mode_history().erase(mode_history().begin());
  }
  mode_history().push_back(std::move(value));
  return Status::success();
}

bool StateEditor::erase_interlock(const InterlockId& id) noexcept {
  return detail::sorted_erase(interlocks(), id,
                              [](const Interlock& item) { return item.id; },
                              [](const InterlockId& a, const InterlockId& b) { return a < b; });
}

bool StateEditor::erase_obligation(const ObligationId& id) noexcept {
  return detail::sorted_erase(
      obligations(), id, [](const ProtectedObligation& item) { return item.id; },
      [](const ObligationId& a, const ObligationId& b) { return a < b; });
}

bool StateEditor::erase_commitment(const CapacityCommitmentId& id) noexcept {
  return detail::sorted_erase(
      commitments(), id, [](const CapacityCommitment& item) { return item.id; },
      [](const CapacityCommitmentId& a, const CapacityCommitmentId& b) { return a < b; });
}

ProtectedObligation* StateEditor::mutable_obligation(const ObligationId& id) noexcept {
  const auto position = std::lower_bound(
      obligations().begin(), obligations().end(), id,
      [](const ProtectedObligation& item, const ObligationId& key) { return item.id < key; });
  if (position == obligations().end() || !(position->id == id)) {
    return nullptr;
  }
  return &(*position);
}

PermissionGrant* StateEditor::mutable_permission(const PermissionId& id) noexcept {
  const auto position = std::lower_bound(
      permissions().begin(), permissions().end(), id,
      [](const PermissionGrant& item, const PermissionId& key) { return item.id < key; });
  if (position == permissions().end() || !(position->id == id)) {
    return nullptr;
  }
  return &(*position);
}

AttemptRecord* StateEditor::mutable_attempt(AttemptId id) noexcept {
  const auto position = std::lower_bound(
      attempts().begin(), attempts().end(), id,
      [](const AttemptRecord& item, AttemptId key) { return item.id < key; });
  if (position == attempts().end() || !(position->id == id)) {
    return nullptr;
  }
  return &(*position);
}

Status enforce_retention(StateEditor& editor, const Limits& limits,
                         std::uint64_t& attempts_removed,
                         std::uint64_t& replay_records_removed) {
  attempts_removed = 0;
  replay_records_removed = 0;

  // Attempts are removed oldest identity first, and the replay record for a
  // removed attempt is retired in the same publication so a later retry with that
  // key can never be answered from a removal that did not happen.
  while (editor.attempts().size() > limits.max_attempts && !editor.attempts().empty()) {
    const AttemptRecord& oldest = editor.attempts().front();
    if (oldest.replay_retained) {
      editor.operation_index().erase(oldest.key);
      ++replay_records_removed;
      ++editor.pruned_replay_records();
    }
    editor.attempts().erase(editor.attempts().begin());
    ++attempts_removed;
    ++editor.pruned_attempts();
  }

  // Committed-operation records are bounded independently. When the index is over
  // bound, the record with the smallest published revision is retired first, which
  // keeps eviction deterministic and reproducible and always retires the oldest
  // accepted result before a newer one.
  while (editor.operation_index().size() > limits.max_replay_records &&
         !editor.operation_index().empty()) {
    auto victim = editor.operation_index().begin();
    for (auto entry = editor.operation_index().begin();
         entry != editor.operation_index().end(); ++entry) {
      if (entry->second.revision < victim->second.revision) {
        victim = entry;
      }
    }
    AttemptRecord* record = victim->second.attempt.is_zero()
                                ? nullptr
                                : editor.mutable_attempt(victim->second.attempt);
    if (record != nullptr) {
      record->replay_retained = false;
    }
    editor.operation_index().erase(victim);
    ++replay_records_removed;
    ++editor.pruned_replay_records();
  }

  return Status::success();
}

}  // namespace power_control_plane::detail
