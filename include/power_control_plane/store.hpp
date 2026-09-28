#pragma once

// Durable, integrity-checked persistence for authoritative control state.
//
// Layout of a store root (all names are fixed; an operator never invents one):
//
//   pcp.lock              operating-system advisory lock file held exclusively by
//                         the writer process
//   pcp-authority.bin     authority marker: store incarnation, current controller
//                         epoch and incarnation, and the highest generation ever
//                         published. It is the rollback fence.
//   pcp-head.bin          authoritative head marker. Naming this generation is the
//                         commit point.
//   state-<revision>.bin  one published, checksummed state generation per commit
//   staging/              staging area for the in-flight publication only
//
// Publication protocol (the exact ordered stages are in CommitStage):
//
//   plan -> validate -> reserve generation -> write staging -> flush durable
//   content -> read back and verify -> atomically publish generation -> commit
//   authoritative head marker -> advance the authority marker -> retire residue
//
// The commit point is head_committed. A published generation file that the head
// marker does not name is residue from an interrupted publication and is retired
// on the next open; it is never adopted. Recovery adopts exactly one whole
// verified generation or refuses to open.

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/canonical.hpp"
#include "power_control_plane/digest.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/limits.hpp"
#include "power_control_plane/report.hpp"
#include "power_control_plane/state.hpp"
#include "power_control_plane/transition.hpp"

namespace power_control_plane {

// Format identity. Bumping either constant is a format break.
inline constexpr std::string_view kHeadMagic = "PCPHEAD1";
inline constexpr std::string_view kStateMagic = "PCPGEN01";
inline constexpr std::string_view kAuthorityMagic = "PCPAUTH1";
inline constexpr std::uint32_t kStoreFormatVersion = 1;

// Fixed record sizes. The head and authority markers are fixed-size records, so a
// truncated or oversized file is rejected by length before any field is trusted.
inline constexpr std::size_t kHeadRecordSize = 288;
inline constexpr std::size_t kStateHeaderSize = 96;
inline constexpr std::size_t kAuthorityRecordSize = 256;

enum class StoreOpenMode : std::uint8_t {
  read_only = 1,
  read_write = 2,
};

[[nodiscard]] std::string_view to_string(StoreOpenMode mode) noexcept;
[[nodiscard]] Result<StoreOpenMode> parse_store_open_mode(std::string_view text);

// Diagnostic publication hook.
//
// The hook is invoked synchronously inside the writer critical section at each
// durable stage of a commit. It exists so crash-injection tests and the benchmark
// can observe and stage-cost the real publication path. It must not re-enter the
// store; re-entrant use is a programming error and is rejected by the store.
class CommitObserver {
 public:
  CommitObserver() = default;
  virtual ~CommitObserver() = default;
  CommitObserver(const CommitObserver&) = delete;
  CommitObserver& operator=(const CommitObserver&) = delete;
  virtual void on_commit_stage(CommitStage stage, const CommitReport& report) = 0;
};

struct StoreOptions {
  Limits limits{};
  // Number of published revisions retained on disk. At least two are required so
  // that deterministic replay verification always has a predecessor.
  std::size_t retained_publications = 8;
  // Non-owning. Null disables staging observation.
  CommitObserver* commit_observer = nullptr;
};

struct StoreHead {
  StoreIncarnation incarnation;
  ControlGeneration generation;
  StateRevision revision;
  LogicalTick tick;
  Digest payload_digest;
  std::uint64_t payload_bytes = 0;
  std::string state_file;
  bool present = false;
};

// Proof that this process currently holds writer authority. A lease cannot be
// constructed by callers: only DurableStore::acquire_writer produces a valid one,
// and the store validates the epoch, incarnation, and process-local token on every
// mutation. A lease whose epoch has been superseded is refused.
class WriterLease {
 public:
  WriterLease() = default;

  [[nodiscard]] bool valid() const noexcept { return token_ != 0; }
  [[nodiscard]] ControllerEpoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] ControllerIncarnation incarnation() const noexcept {
    return incarnation_;
  }
  [[nodiscard]] const StoreIncarnation& store_incarnation() const noexcept {
    return store_incarnation_;
  }

 private:
  friend class DurableStore;
  ControllerEpoch epoch_;
  ControllerIncarnation incarnation_;
  StoreIncarnation store_incarnation_;
  std::uint64_t token_ = 0;
};

struct WriterStatus {
  bool held_by_this_store = false;
  bool lock_contended = false;
  ControllerEpoch epoch;
  ControllerIncarnation incarnation;
  std::uint64_t process_id = 0;
  std::string detail;
};

struct StoreOpenReport {
  bool created = false;
  bool recovered = false;
  bool rollback_detected = false;
  std::size_t retired_staging_files = 0;
  std::size_t retired_orphan_states = 0;
  std::size_t retired_old_publications = 0;
  std::string detail;
};

class DurableStore {
 public:
  DurableStore();
  ~DurableStore();
  DurableStore(DurableStore&&) noexcept;
  DurableStore& operator=(DurableStore&&) noexcept;
  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;

  // Opens (creating when necessary) a store rooted at an absolute directory.
  //
  // On open the store performs whole-state recovery: it verifies the authority
  // marker, the head marker, and the referenced state generation, and refuses to
  // open when any of them is missing, malformed, oversized, truncated, or fails
  // its checksum. It never stitches two generations together and never merges.
  static Result<DurableStore> open(const std::string& root, StoreOpenMode mode,
                                   StoreOptions options);

  [[nodiscard]] const std::string& root() const noexcept;
  [[nodiscard]] StoreOpenMode mode() const noexcept;
  [[nodiscard]] StoreHead head() const;
  // Identity of the store incarnation this handle is bound to.
  [[nodiscard]] StoreIncarnation incarnation() const;
  [[nodiscard]] const StoreOpenReport& open_report() const noexcept;
  [[nodiscard]] const Limits& limits() const noexcept;
  [[nodiscard]] WriterStatus writer_status() const;

  // Loads the authoritative state. Returns an error when no authoritative
  // generation exists yet.
  [[nodiscard]] Result<FacilityState> load_state() const;

  // Immutable shared view of the authoritative state as of the last successful
  // publication. Readers hold the returned pointer and never observe a partially
  // applied transition.
  [[nodiscard]] std::shared_ptr<const FacilityState> state_pointer() const;
  [[nodiscard]] Result<FacilityState> load_publication(StateRevision revision) const;

  // Revisions currently retained on disk, ascending. Always consecutive.
  [[nodiscard]] std::vector<StateRevision> retained_publications() const;

  // Acquires cross-process writer authority. Fails with
  // ErrorCode::writer_authority_held when another process holds the lock.
  [[nodiscard]] Result<WriterLease> acquire_writer();
  [[nodiscard]] Status release_writer(const WriterLease& lease);
  [[nodiscard]] Status validate_writer(const WriterLease& lease) const;

  // Publishes one whole state as the next authoritative publication. The lease
  // must be the current writer authority and next.generation()/next.revision()
  // must be exactly the successors of the current head.
  [[nodiscard]] Result<CommitReport> commit(const WriterLease& lease,
                                            const FacilityState& next,
                                            const TransitionRecord& record);

  [[nodiscard]] Result<StoreIntegrityReport> verify_integrity() const;
  [[nodiscard]] Result<ReplayReport> verify_deterministic_replay() const;

  // Releases the writer lock (when held) and the store. Safe to call twice.
  void close();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// File name of the published state for a revision. Deterministic and fixed width
// so that lexical order equals numeric order.
[[nodiscard]] std::string state_file_name(StateRevision revision);
[[nodiscard]] Result<StateRevision> parse_state_file_name(std::string_view name);

}  // namespace power_control_plane
