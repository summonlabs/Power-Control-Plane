#pragma once

// Immutable reader views.
//
// Readers never observe a partially applied transition. A snapshot is a shared,
// immutable value: the engine publishes a new snapshot when a commit completes and
// readers keep whatever snapshot they already hold. The canonical digest is
// computed once and cached, so a reader can prove what it observed.

#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "power_control_plane/attempt.hpp"
#include "power_control_plane/digest.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/interlock.hpp"
#include "power_control_plane/mode.hpp"
#include "power_control_plane/obligation.hpp"
#include "power_control_plane/permission.hpp"
#include "power_control_plane/policy.hpp"
#include "power_control_plane/state.hpp"

namespace power_control_plane {

// Digest cache shared by every copy of one snapshot. It is a shared_ptr rather
// than a member std::once_flag because a std::once_flag is neither copyable nor
// movable, and snapshots are passed by value.
struct SnapshotDigestCache {
  std::mutex mutex;
  bool computed = false;
  Digest digest{};
};

class FacilitySnapshot {
 public:
  FacilitySnapshot() : cache_(std::make_shared<SnapshotDigestCache>()) {}
  explicit FacilitySnapshot(std::shared_ptr<const FacilityState> state)
      : state_(std::move(state)), cache_(std::make_shared<SnapshotDigestCache>()) {}

  [[nodiscard]] bool valid() const noexcept { return state_ != nullptr; }
  [[nodiscard]] const FacilityState& state() const noexcept { return *state_; }
  [[nodiscard]] const std::shared_ptr<const FacilityState>& shared() const noexcept {
    return state_;
  }

  [[nodiscard]] const FacilityId& facility() const { return state_->facility(); }
  [[nodiscard]] const StoreIncarnation& incarnation() const {
    return state_->incarnation();
  }
  [[nodiscard]] ControlGeneration generation() const { return state_->generation(); }
  [[nodiscard]] StateRevision revision() const { return state_->revision(); }
  [[nodiscard]] PolicyRevision policy_revision() const {
    return state_->policy_revision();
  }
  [[nodiscard]] LogicalTick tick() const { return state_->tick(); }
  [[nodiscard]] OperatingMode mode() const { return state_->mode(); }
  [[nodiscard]] const PowerPolicy& policy() const { return state_->policy(); }
  [[nodiscard]] const EvidenceBinding& evidence() const { return state_->evidence(); }
  [[nodiscard]] const std::vector<Interlock>& interlocks() const {
    return state_->interlocks();
  }
  [[nodiscard]] const std::vector<ProtectedObligation>& obligations() const {
    return state_->obligations();
  }
  [[nodiscard]] const std::vector<CapacityCommitment>& commitments() const {
    return state_->commitments();
  }
  [[nodiscard]] const std::vector<PermissionGrant>& permissions() const {
    return state_->permissions();
  }
  [[nodiscard]] const std::vector<AttemptRecord>& attempts() const {
    return state_->attempts();
  }
  [[nodiscard]] const std::vector<ModeHistoryEntry>& mode_history() const {
    return state_->mode_history();
  }
  [[nodiscard]] const std::vector<TransitionLogEntry>& transition_log() const {
    return state_->transition_log();
  }

  // Canonical digest of the observed state. Stable for the lifetime of the
  // snapshot and independent of when it is first requested.
  [[nodiscard]] Digest digest() const {
    std::lock_guard<std::mutex> guard(cache_->mutex);
    if (!cache_->computed) {
      cache_->digest = state_->canonical_digest();
      cache_->computed = true;
    }
    return cache_->digest;
  }

 private:
  std::shared_ptr<const FacilityState> state_;
  std::shared_ptr<SnapshotDigestCache> cache_;
};

}  // namespace power_control_plane
