#pragma once

// Report value types produced by durable-store inspection, deterministic replay
// verification, and evidence revalidation.

#include <cstdint>
#include <string>
#include <vector>

#include "power_control_plane/digest.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/transition.hpp"

namespace power_control_plane {

// Durable publication stages, in order. A crash between any two stages must leave
// the store adoptable at the last completed stage.
enum class CommitStage : std::uint8_t {
  staging_written = 1,
  staging_flushed = 2,
  staging_read_back_verified = 3,
  generation_published = 4,
  head_committed = 5,
  authority_marked = 6,
  residue_retired = 7,
};

[[nodiscard]] std::string_view to_string(CommitStage stage) noexcept;

// True once the publication is durable and authoritative. The commit point of the
// store is head_committed: a generation file that exists without a head marker
// naming it is residue, never authority.
[[nodiscard]] bool commit_stage_is_authoritative(CommitStage stage) noexcept;

struct CommitReport {
  ControlGeneration generation;
  StateRevision revision;
  LogicalTick tick;
  Digest payload_digest;
  std::uint64_t payload_bytes = 0;
  std::string staging_file;
  std::string published_file;
  bool read_back_verified = false;
  bool head_committed = false;
  std::uint64_t retired_residue = 0;
  CommitStage reached = CommitStage::staging_written;
};

struct StoreIntegrityReport {
  bool ok = false;
  bool head_present = false;
  bool head_checksum_ok = false;
  bool payload_present = false;
  bool payload_checksum_ok = false;
  bool head_matches_payload = false;
  bool authority_present = false;
  bool authority_checksum_ok = false;
  bool rollback_detected = false;
  bool incarnation_matches = false;
  std::vector<StateRevision> retained_generations;
  std::vector<std::string> orphan_generation_files;
  std::vector<std::string> staging_residue;
  std::string detail;
};

struct ReplayStepReport {
  TransitionKind kind = TransitionKind::facility_bootstrap;
  ControlGeneration from_generation;
  ControlGeneration to_generation;
  StateRevision from_revision;
  StateRevision to_revision;
  bool matched = false;
  Digest expected_digest;
  Digest actual_digest;
};

struct ReplayReport {
  bool ok = false;
  std::size_t steps_checked = 0;
  std::vector<ReplayStepReport> steps;
  std::string detail;
};

// Runtime evidence freshness. Persisted evidence references are bindings, never
// freshness claims: after any reopen this reports not-fresh until an explicit
// revalidation binds current evidence.
struct RevalidationReport {
  bool evidence_fresh = false;
  bool revalidated_in_this_incarnation = false;
  Digest bound_digest;
  Digest fresh_digest;
  ControlGeneration revalidated_generation;
  StateRevision revalidated_revision;
  std::size_t bound_sources = 0;
  std::string detail;
};

}  // namespace power_control_plane
