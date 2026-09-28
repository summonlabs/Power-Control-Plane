#include "power_control_plane/store.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "detail/file_io.hpp"
#include "detail/paths.hpp"
#include "detail/process_lock.hpp"
#include "power_control_plane/version.hpp"

namespace power_control_plane {
namespace {

constexpr std::string_view kLockFileName = "pcp.lock";
constexpr std::string_view kHeadFileName = "pcp-head.bin";
constexpr std::string_view kAuthorityFileName = "pcp-authority.bin";
constexpr std::string_view kStagingDirectoryName = "staging";
constexpr std::string_view kStateFilePrefix = "state-";
constexpr std::string_view kStateFileSuffix = ".bin";

constexpr std::size_t kHeadBodySize = 256;
constexpr std::size_t kAuthorityBodySize = 224;
constexpr std::size_t kStateTrailerSize = 32;

// Offsets inside the fixed-size head record.
constexpr std::size_t kHeadMagicOffset = 0;
constexpr std::size_t kHeadVersionOffset = 8;
constexpr std::size_t kHeadRecordSizeOffset = 12;
constexpr std::size_t kHeadIncarnationOffset = 16;
constexpr std::size_t kHeadGenerationOffset = 32;
constexpr std::size_t kHeadRevisionOffset = 40;
constexpr std::size_t kHeadPayloadBytesOffset = 48;
constexpr std::size_t kHeadPayloadDigestOffset = 56;
constexpr std::size_t kHeadTickOffset = 88;
constexpr std::size_t kHeadNameLengthOffset = 96;
constexpr std::size_t kHeadNameOffset = 100;
constexpr std::size_t kHeadMaxNameBytes = 96;

// Offsets inside the fixed-size authority record.
constexpr std::size_t kAuthorityMagicOffset = 0;
constexpr std::size_t kAuthorityVersionOffset = 8;
constexpr std::size_t kAuthorityRecordSizeOffset = 12;
constexpr std::size_t kAuthorityIncarnationOffset = 16;
constexpr std::size_t kAuthorityEpochOffset = 32;
constexpr std::size_t kAuthorityControllerOffset = 40;
constexpr std::size_t kAuthorityHighRevisionOffset = 56;
constexpr std::size_t kAuthorityHighGenerationOffset = 64;
constexpr std::size_t kAuthorityPidOffset = 72;

// Offsets inside the state-file header.
constexpr std::size_t kStateMagicOffset = 0;
constexpr std::size_t kStateVersionOffset = 8;
constexpr std::size_t kStateRecordSizeOffset = 12;
constexpr std::size_t kStateGenerationOffset = 16;
constexpr std::size_t kStateRevisionOffset = 24;
constexpr std::size_t kStateIncarnationOffset = 32;
constexpr std::size_t kStatePayloadBytesOffset = 48;
constexpr std::size_t kStatePayloadDigestOffset = 56;
constexpr std::size_t kStateTickOffset = 88;

void put_u64(Bytes& buffer, std::size_t offset, std::uint64_t value) {
  for (unsigned index = 0; index < 8; ++index) {
    buffer[offset + index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu);
  }
}

void put_u32(Bytes& buffer, std::size_t offset, std::uint32_t value) {
  for (unsigned index = 0; index < 4; ++index) {
    buffer[offset + index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu);
  }
}

void put_magic(Bytes& buffer, std::size_t offset, std::string_view magic) {
  for (std::size_t index = 0; index < magic.size(); ++index) {
    buffer[offset + index] = static_cast<std::uint8_t>(magic[index]);
  }
}

std::uint64_t get_u64(const Bytes& buffer, std::size_t offset) {
  std::uint64_t value = 0;
  for (unsigned index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(buffer[offset + index]) << (8 * index);
  }
  return value;
}

std::uint32_t get_u32(const Bytes& buffer, std::size_t offset) {
  std::uint32_t value = 0;
  for (unsigned index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(buffer[offset + index]) << (8 * index);
  }
  return value;
}

Digest read_digest_at(const Bytes& buffer, std::size_t offset) {
  std::array<std::uint8_t, Digest::kBytes> bytes{};
  for (std::size_t index = 0; index < Digest::kBytes; ++index) {
    bytes[index] = buffer[offset + index];
  }
  return Digest::from_array(bytes);
}

bool magic_matches(const Bytes& buffer, std::size_t offset, std::string_view magic) {
  if (buffer.size() < offset + magic.size()) {
    return false;
  }
  for (std::size_t index = 0; index < magic.size(); ++index) {
    if (buffer[offset + index] != static_cast<std::uint8_t>(magic[index])) {
      return false;
    }
  }
  return true;
}

void seal_record(Bytes& record, std::size_t body_size, std::string_view domain) {
  const Digest checksum = sha256_domain(domain, record.data(), body_size);
  std::memcpy(record.data() + body_size, checksum.bytes().data(), Digest::kBytes);
}

Status verify_seal(const Bytes& record, std::size_t body_size, std::string_view domain,
                   std::string_view what) {
  const Digest expected =
      sha256_domain(domain, record.data(), body_size);
  for (std::size_t index = 0; index < Digest::kBytes; ++index) {
    if (record[body_size + index] != expected.bytes()[index]) {
      std::string message = "the ";
      message.append(what);
      message.append(" failed its integrity check");
      return Status::failure(ErrorCode::corrupt_store, std::move(message));
    }
  }
  return Status::success();
}

struct AuthorityMarker {
  StoreIncarnation incarnation;
  ControllerEpoch epoch;
  ControllerIncarnation controller;
  StateRevision highest_revision;
  ControlGeneration highest_generation;
  std::uint64_t process_id = 0;
};

Bytes encode_authority(const AuthorityMarker& marker) {
  Bytes record(kAuthorityRecordSize, 0);
  put_magic(record, kAuthorityMagicOffset, kAuthorityMagic);
  put_u32(record, kAuthorityVersionOffset, kStoreFormatVersion);
  put_u32(record, kAuthorityRecordSizeOffset,
          static_cast<std::uint32_t>(kAuthorityRecordSize));
  put_u64(record, kAuthorityIncarnationOffset, marker.incarnation.high());
  put_u64(record, kAuthorityIncarnationOffset + 8, marker.incarnation.low());
  put_u64(record, kAuthorityEpochOffset, marker.epoch.value());
  put_u64(record, kAuthorityControllerOffset, marker.controller.high());
  put_u64(record, kAuthorityControllerOffset + 8, marker.controller.low());
  put_u64(record, kAuthorityHighRevisionOffset, marker.highest_revision.value());
  put_u64(record, kAuthorityHighGenerationOffset, marker.highest_generation.value());
  put_u64(record, kAuthorityPidOffset, marker.process_id);
  seal_record(record, kAuthorityBodySize, "pcp/authority-record/v1");
  return record;
}

Result<AuthorityMarker> decode_authority(const Bytes& record) {
  if (record.size() != kAuthorityRecordSize) {
    return Error(ErrorCode::corrupt_store,
                 "the authority marker has an unexpected length and was refused");
  }
  if (!magic_matches(record, kAuthorityMagicOffset, kAuthorityMagic)) {
    return Error(ErrorCode::unsupported_format, "the authority marker magic is unknown");
  }
  if (get_u32(record, kAuthorityVersionOffset) != kStoreFormatVersion) {
    return Error(ErrorCode::unsupported_format,
                 "the authority marker format version is not supported");
  }
  if (get_u32(record, kAuthorityRecordSizeOffset) != kAuthorityRecordSize) {
    return Error(ErrorCode::corrupt_store, "the authority marker declares a wrong size");
  }
  PCP_TRY_STATUS(verify_seal(record, kAuthorityBodySize, "pcp/authority-record/v1",
                             "authority marker"));
  AuthorityMarker marker;
  marker.incarnation = StoreIncarnation::from_parts(
      get_u64(record, kAuthorityIncarnationOffset),
      get_u64(record, kAuthorityIncarnationOffset + 8));
  marker.epoch = ControllerEpoch(get_u64(record, kAuthorityEpochOffset));
  marker.controller = ControllerIncarnation::from_parts(
      get_u64(record, kAuthorityControllerOffset),
      get_u64(record, kAuthorityControllerOffset + 8));
  marker.highest_revision = StateRevision(get_u64(record, kAuthorityHighRevisionOffset));
  marker.highest_generation = ControlGeneration(get_u64(record, kAuthorityHighGenerationOffset));
  marker.process_id = get_u64(record, kAuthorityPidOffset);
  return marker;
}

struct HeadRecord {
  StoreIncarnation incarnation;
  ControlGeneration generation;
  StateRevision revision;
  LogicalTick tick;
  Digest payload_digest;
  std::uint64_t payload_bytes = 0;
  std::string state_file;
};

Bytes encode_head(const HeadRecord& head) {
  Bytes record(kHeadRecordSize, 0);
  put_magic(record, kHeadMagicOffset, kHeadMagic);
  put_u32(record, kHeadVersionOffset, kStoreFormatVersion);
  put_u32(record, kHeadRecordSizeOffset, static_cast<std::uint32_t>(kHeadRecordSize));
  put_u64(record, kHeadIncarnationOffset, head.incarnation.high());
  put_u64(record, kHeadIncarnationOffset + 8, head.incarnation.low());
  put_u64(record, kHeadGenerationOffset, head.generation.value());
  put_u64(record, kHeadRevisionOffset, head.revision.value());
  put_u64(record, kHeadPayloadBytesOffset, head.payload_bytes);
  std::memcpy(record.data() + kHeadPayloadDigestOffset, head.payload_digest.bytes().data(),
              Digest::kBytes);
  put_u64(record, kHeadTickOffset, head.tick.value());
  put_u32(record, kHeadNameLengthOffset,
          static_cast<std::uint32_t>(head.state_file.size()));
  std::memcpy(record.data() + kHeadNameOffset, head.state_file.data(),
              head.state_file.size());
  seal_record(record, kHeadBodySize, "pcp/head-record/v1");
  return record;
}

Result<HeadRecord> decode_head(const Bytes& record) {
  if (record.size() != kHeadRecordSize) {
    return Error(ErrorCode::corrupt_store,
                 "the head marker has an unexpected length and was refused");
  }
  if (!magic_matches(record, kHeadMagicOffset, kHeadMagic)) {
    return Error(ErrorCode::unsupported_format, "the head marker magic is unknown");
  }
  if (get_u32(record, kHeadVersionOffset) != kStoreFormatVersion) {
    return Error(ErrorCode::unsupported_format,
                 "the head marker format version is not supported");
  }
  if (get_u32(record, kHeadRecordSizeOffset) != kHeadRecordSize) {
    return Error(ErrorCode::corrupt_store, "the head marker declares a wrong size");
  }
  PCP_TRY_STATUS(
      verify_seal(record, kHeadBodySize, "pcp/head-record/v1", "head marker"));
  const std::uint32_t name_length = get_u32(record, kHeadNameLengthOffset);
  if (name_length == 0 || name_length > kHeadMaxNameBytes) {
    return Error(ErrorCode::corrupt_store, "the head marker names an invalid state file");
  }
  HeadRecord head;
  head.incarnation = StoreIncarnation::from_parts(get_u64(record, kHeadIncarnationOffset),
                                                  get_u64(record, kHeadIncarnationOffset + 8));
  head.generation = ControlGeneration(get_u64(record, kHeadGenerationOffset));
  head.revision = StateRevision(get_u64(record, kHeadRevisionOffset));
  head.payload_bytes = get_u64(record, kHeadPayloadBytesOffset);
  head.payload_digest = read_digest_at(record, kHeadPayloadDigestOffset);
  head.tick = LogicalTick(get_u64(record, kHeadTickOffset));
  head.state_file.assign(reinterpret_cast<const char*>(record.data() + kHeadNameOffset),
                         name_length);
  return head;
}

}  // namespace

std::string state_file_name(StateRevision revision) {
  char buffer[40] = {};
  std::snprintf(buffer, sizeof(buffer), "state-%020llu.bin",
                static_cast<unsigned long long>(revision.value()));
  return std::string(buffer);
}

Result<StateRevision> parse_state_file_name(std::string_view name) {
  if (name.size() != kStateFilePrefix.size() + 20 + kStateFileSuffix.size()) {
    return Error(ErrorCode::invalid_argument, "not a store state file name");
  }
  if (name.substr(0, kStateFilePrefix.size()) != kStateFilePrefix ||
      name.substr(name.size() - kStateFileSuffix.size()) != kStateFileSuffix) {
    return Error(ErrorCode::invalid_argument, "not a store state file name");
  }
  std::uint64_t value = 0;
  for (std::size_t index = kStateFilePrefix.size();
       index < kStateFilePrefix.size() + 20; ++index) {
    const char digit = name[index];
    if (digit < '0' || digit > '9') {
      return Error(ErrorCode::invalid_argument, "not a store state file name");
    }
    if (value > (0xFFFFFFFFFFFFFFFFull - static_cast<std::uint64_t>(digit - '0')) / 10ull) {
      return Error(ErrorCode::out_of_range, "store state file revision overflows");
    }
    value = value * 10ull + static_cast<std::uint64_t>(digit - '0');
  }
  return StateRevision(value);
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

struct DurableStore::Impl {
  std::string root;
  StoreOpenMode mode = StoreOpenMode::read_only;
  StoreOptions options{};
  StoreOpenReport open_report;
  StoreHead head;
  std::shared_ptr<const FacilityState> cached_state;
  detail::ProcessLock lock;
  AuthorityMarker authority;
  bool has_authority = false;
  WriterLease lease;
  std::uint64_t next_token = 1;
  bool writer_held = false;
  bool lock_contended = false;
  std::atomic<bool> observing{false};

  // Lock order: authority_mutex_ is the outer lock and guards the writer state
  // and the whole publication sequence. state_mutex_ is a leaf lock guarding the
  // published head and the cached immutable state. authority_mutex_ is
  // deliberately held across store I/O because the epoch advance and the durable
  // marker update must be atomic against other in-process writers; it is never
  // held across adapter callbacks, user code, or waits. No path takes
  // state_mutex_ and then authority_mutex_.
  std::mutex authority_mutex;
  mutable std::shared_mutex state_mutex;

  [[nodiscard]] std::string path_of(std::string_view name) const {
    return detail::join_path(root, name);
  }
  [[nodiscard]] std::string staging_path(std::string_view name) const {
    return detail::join_path(detail::join_path(root, kStagingDirectoryName), name);
  }

  void notify(CommitStage stage, const CommitReport& report) {
    if (options.commit_observer == nullptr) {
      return;
    }
    if (observing.exchange(true)) {
      // Re-entering the store from inside a publication hook would observe a
      // half-published state. The hook is refused rather than served.
      return;
    }
    options.commit_observer->on_commit_stage(stage, report);
    observing.store(false);
  }

  // Lease check that assumes authority_mutex is already held. commit() runs the
  // whole publication under that lock, so it must never call the locking public
  // validator: that would be a self-deadlock on a non-recursive mutex.
  [[nodiscard]] Status check_lease(const WriterLease& candidate) const {
    if (!candidate.valid()) {
      return Status::failure(ErrorCode::not_authoritative,
                             "no writer authority was presented");
    }
    if (!writer_held || candidate.token_ != lease.token_) {
      return Status::failure(ErrorCode::stale_epoch,
                             "this writer authority has been superseded by a successor "
                             "incarnation and can no longer publish");
    }
    if (!(candidate.store_incarnation_ == authority.incarnation)) {
      return Status::failure(ErrorCode::stale_incarnation,
                             "the presented authority belongs to a different store incarnation");
    }
    if (!(candidate.epoch_ == authority.epoch) ||
        !(candidate.incarnation_ == authority.controller)) {
      return Status::failure(ErrorCode::stale_epoch,
                             "the presented controller epoch is not the current authority");
    }
    return Status::success();
  }

  [[nodiscard]] Result<FacilityState> load_state_file(const std::string& file_name,
                                                      const HeadRecord& expected) const;
};

Result<FacilityState> DurableStore::Impl::load_state_file(const std::string& file_name,
                                                         const HeadRecord& expected) const {
  PCP_TRY_STATUS(detail::validate_child_name(file_name));
  const std::string full = path_of(file_name);
  PCP_TRY_STATUS(detail::reject_substitution(full));
  PCP_TRY_STATUS(detail::reject_directory(full));
  auto bytes = detail::read_file_bounded(
      full, options.limits.max_payload_bytes + kStateHeaderSize + kStateTrailerSize);
  if (!bytes.has_value()) {
    return bytes.error();
  }
  const Bytes& file = bytes.value();
  if (file.size() < kStateHeaderSize + kStateTrailerSize) {
    return Error(ErrorCode::corrupt_store, "a state generation is too short to be valid");
  }
  if (!magic_matches(file, kStateMagicOffset, kStateMagic)) {
    return Error(ErrorCode::unsupported_format, "a state generation magic is unknown");
  }
  if (get_u32(file, kStateVersionOffset) != kStoreFormatVersion) {
    return Error(ErrorCode::unsupported_format,
                 "a state generation format version is not supported");
  }
  if (get_u32(file, kStateRecordSizeOffset) != file.size()) {
    return Error(ErrorCode::corrupt_store,
                 "a state generation declares a different length than it has");
  }
  const std::uint64_t payload_bytes = get_u64(file, kStatePayloadBytesOffset);
  if (payload_bytes != file.size() - kStateHeaderSize - kStateTrailerSize) {
    return Error(ErrorCode::corrupt_store,
                 "a state generation declares a different payload length than it has");
  }
  PCP_TRY_STATUS(verify_seal(file, file.size() - kStateTrailerSize, "pcp/state-record/v1",
                             "state generation"));
  const Digest payload_digest =
      sha256_domain(kStateDigestDomain, file.data() + kStateHeaderSize,
                    static_cast<std::size_t>(payload_bytes));
  const Digest declared = read_digest_at(file, kStatePayloadDigestOffset);
  if (!(declared == payload_digest)) {
    return Error(ErrorCode::corrupt_store,
                 "a state generation content does not match its declared digest");
  }
  if (!(declared == expected.payload_digest)) {
    return Error(ErrorCode::corrupt_store,
                 "the head marker and the state generation disagree on the content digest");
  }
  if (get_u64(file, kStateRevisionOffset) != expected.revision.value()) {
    return Error(ErrorCode::corrupt_store,
                 "the head marker and the state generation disagree on the revision");
  }
  if (get_u64(file, kStateGenerationOffset) != expected.generation.value()) {
    return Error(ErrorCode::corrupt_store,
                 "the head marker and the state generation disagree on the generation");
  }
  const StoreIncarnation incarnation = StoreIncarnation::from_parts(
      get_u64(file, kStateIncarnationOffset), get_u64(file, kStateIncarnationOffset + 8));
  if (!(incarnation == expected.incarnation)) {
    return Error(ErrorCode::corrupt_store,
                 "the head marker and the state generation disagree on the store incarnation");
  }
  if (get_u64(file, kStateTickOffset) != expected.tick.value()) {
    return Error(ErrorCode::corrupt_store,
                 "the head marker and the state generation disagree on the logical tick");
  }

  const Bytes payload(file.begin() + static_cast<std::ptrdiff_t>(kStateHeaderSize),
                      file.begin() + static_cast<std::ptrdiff_t>(kStateHeaderSize +
                                                                payload_bytes));
  auto state = FacilityState::decode(payload, options.limits);
  if (!state.has_value()) {
    return state.error();
  }
  if (!(state.value().incarnation() == expected.incarnation)) {
    return Error(ErrorCode::corrupt_store,
                 "the decoded state carries a different store incarnation");
  }
  if (state.value().generation() != expected.generation ||
      state.value().revision() != expected.revision) {
    return Error(ErrorCode::corrupt_store,
                 "the decoded state does not match the revision the head marker names");
  }
  return state;
}

DurableStore::DurableStore() : impl_(std::make_unique<Impl>()) {}
DurableStore::~DurableStore() = default;
DurableStore::DurableStore(DurableStore&&) noexcept = default;
DurableStore& DurableStore::operator=(DurableStore&&) noexcept = default;

Result<DurableStore> DurableStore::open(const std::string& root, StoreOpenMode mode,
                                        StoreOptions options) {
  if (options.retained_publications < 2) {
    return Error(ErrorCode::invalid_argument,
                 "at least two published generations must be retained so that "
                 "deterministic replay verification always has a predecessor");
  }
  DurableStore store;
  Impl& impl = *store.impl_;
  impl.mode = mode;
  impl.options = options;

  auto normalized = detail::normalize_root_path(root, options.limits);
  if (!normalized.has_value()) {
    return normalized.error();
  }
  impl.root = std::move(normalized).value();

  if (mode == StoreOpenMode::read_only) {
    if (!detail::is_directory(impl.root)) {
      return Error(ErrorCode::not_found, "the store root does not exist");
    }
  } else {
    PCP_TRY_STATUS(detail::reject_substitution(impl.root));
    PCP_TRY_STATUS(detail::ensure_directory(impl.root));
  }
  PCP_TRY_STATUS(detail::reject_substitution(impl.root));

  // Store-owned entries must never be substituted.
  for (const std::string_view name : {kHeadFileName, kAuthorityFileName, kLockFileName,
                                      kStagingDirectoryName}) {
    PCP_TRY_STATUS(detail::reject_substitution(impl.path_of(name)));
  }

  const std::string authority_path = impl.path_of(kAuthorityFileName);
  const std::string head_path = impl.path_of(kHeadFileName);
  const bool authority_present = detail::path_exists(authority_path);
  const bool head_present = detail::path_exists(head_path);

  if (authority_present) {
    PCP_TRY_STATUS(detail::reject_directory(authority_path));
    auto bytes = detail::read_file_bounded(authority_path, kAuthorityRecordSize);
    if (!bytes.has_value()) {
      return bytes.error();
    }
    auto marker = decode_authority(bytes.value());
    if (!marker.has_value()) {
      return marker.error();
    }
    impl.authority = marker.value();
    impl.has_authority = true;
  } else {
    if (head_present) {
      return Error(ErrorCode::corrupt_store,
                   "the authority marker is missing while a head marker exists; the "
                   "rollback fence cannot be re-established and the store is refused");
    }
    if (mode == StoreOpenMode::read_only) {
      return Error(ErrorCode::not_found, "the store has no authority marker");
    }
    AuthorityMarker marker;
    marker.incarnation = StoreIncarnation::generate();
    marker.epoch = ControllerEpoch(0);
    marker.controller = ControllerIncarnation{};
    impl.authority = marker;
    impl.has_authority = true;
    const Bytes record = encode_authority(marker);
    PCP_TRY_STATUS(detail::write_file_durable(authority_path, record.data(), record.size()));
    impl.open_report.created = true;
    impl.open_report.detail = "the store was created";
  }

  if (head_present) {
    PCP_TRY_STATUS(detail::reject_directory(head_path));
    auto bytes = detail::read_file_bounded(head_path, kHeadRecordSize);
    if (!bytes.has_value()) {
      return bytes.error();
    }
    auto record = decode_head(bytes.value());
    if (!record.has_value()) {
      return record.error();
    }
    if (!(record.value().incarnation == impl.authority.incarnation)) {
      return Error(ErrorCode::corrupt_store,
                   "the head marker belongs to a different store incarnation");
    }
    if (record.value().revision < impl.authority.highest_revision) {
      impl.open_report.rollback_detected = true;
      return Error(ErrorCode::rollback_detected,
                   "the head marker names an older publication than the authority "
                   "high-water mark; the store is refused rather than silently rewound");
    }
    auto state = impl.load_state_file(record.value().state_file, record.value());
    if (!state.has_value()) {
      return state.error();
    }
    impl.head.present = true;
    impl.head.incarnation = record.value().incarnation;
    impl.head.generation = record.value().generation;
    impl.head.revision = record.value().revision;
    impl.head.tick = record.value().tick;
    impl.head.payload_digest = record.value().payload_digest;
    impl.head.payload_bytes = record.value().payload_bytes;
    impl.head.state_file = record.value().state_file;
    impl.cached_state = std::make_shared<const FacilityState>(std::move(state).value());
    impl.open_report.recovered = true;
    impl.open_report.detail = "the authoritative generation was verified and adopted";
  } else if (impl.authority.highest_revision.value() > 0) {
    return Error(ErrorCode::corrupt_store,
                 "the head marker is missing while the authority high-water mark records "
                 "published state; the store is refused rather than silently emptied");
  } else {
    impl.open_report.detail = "the store holds no authoritative generation yet";
  }

  if (mode == StoreOpenMode::read_write) {
    const std::string staging = impl.path_of(kStagingDirectoryName);
    if (detail::path_exists(staging)) {
      PCP_TRY_STATUS(detail::reject_substitution(staging));
      auto residue = detail::list_directory(staging, options.limits);
      if (!residue.has_value()) {
        return residue.error();
      }
      for (const std::string& name : residue.value()) {
        PCP_TRY_STATUS(detail::validate_child_name(name));
        PCP_TRY_STATUS(detail::remove_file_if_present(detail::join_path(staging, name)));
        ++impl.open_report.retired_staging_files;
      }
    } else {
      PCP_TRY_STATUS(detail::ensure_directory(staging));
    }

    auto entries = detail::list_directory(impl.root, options.limits);
    if (!entries.has_value()) {
      return entries.error();
    }
    std::vector<StateRevision> published;
    for (const std::string& name : entries.value()) {
      auto parsed = parse_state_file_name(name);
      if (!parsed.has_value()) {
        continue;
      }
      const std::string full = impl.path_of(name);
      PCP_TRY_STATUS(detail::reject_substitution(full));
      if (impl.head.present && parsed.value() > impl.head.revision) {
        // Published but never named by the head marker: an interrupted
        // publication. It is residue and is never adopted.
        PCP_TRY_STATUS(detail::remove_file_if_present(full));
        ++impl.open_report.retired_orphan_states;
        continue;
      }
      published.push_back(parsed.value());
    }
    std::sort(published.begin(), published.end());
    const std::size_t keep = options.retained_publications;
    while (published.size() > keep) {
      const StateRevision victim = published.front();
      published.erase(published.begin());
      if (impl.head.present && victim == impl.head.revision) {
        continue;
      }
      PCP_TRY_STATUS(
          detail::remove_file_if_present(impl.path_of(state_file_name(victim))));
      ++impl.open_report.retired_old_publications;
    }
  }

  return store;
}

const std::string& DurableStore::root() const noexcept { return impl_->root; }
StoreOpenMode DurableStore::mode() const noexcept { return impl_->mode; }

StoreHead DurableStore::head() const {
  std::shared_lock<std::shared_mutex> guard(impl_->state_mutex);
  return impl_->head;
}

StoreIncarnation DurableStore::incarnation() const { return impl_->authority.incarnation; }

const StoreOpenReport& DurableStore::open_report() const noexcept {
  return impl_->open_report;
}

const Limits& DurableStore::limits() const noexcept { return impl_->options.limits; }

WriterStatus DurableStore::writer_status() const {
  std::lock_guard<std::mutex> guard(impl_->authority_mutex);
  WriterStatus status;
  status.held_by_this_store = impl_->writer_held;
  status.lock_contended = impl_->lock_contended;
  // When this process holds no authority the durable authority marker is reported,
  // so an operator can see which epoch the last writer published at instead of a
  // meaningless zero.
  status.epoch = impl_->writer_held ? impl_->lease.epoch() : impl_->authority.epoch;
  status.incarnation = impl_->writer_held ? impl_->lease.incarnation()
                                          : impl_->authority.controller;
  status.process_id = impl_->authority.process_id;
  status.detail = impl_->writer_held ? "writer authority is held by this process"
                                     : "no writer authority is held by this process";
  return status;
}

Result<FacilityState> DurableStore::load_state() const {
  std::shared_lock<std::shared_mutex> guard(impl_->state_mutex);
  if (!impl_->cached_state) {
    return Error(ErrorCode::not_found, "the store holds no authoritative generation");
  }
  return *impl_->cached_state;
}

std::shared_ptr<const FacilityState> DurableStore::state_pointer() const {
  std::shared_lock<std::shared_mutex> guard(impl_->state_mutex);
  return impl_->cached_state;
}

std::vector<StateRevision> DurableStore::retained_publications() const {
  std::vector<StateRevision> published;
  auto entries = detail::list_directory(impl_->root, impl_->options.limits);
  if (!entries.has_value()) {
    return published;
  }
  for (const std::string& name : entries.value()) {
    auto parsed = parse_state_file_name(name);
    if (parsed.has_value()) {
      published.push_back(parsed.value());
    }
  }
  std::sort(published.begin(), published.end());
  return published;
}

Result<FacilityState> DurableStore::load_publication(StateRevision revision) const {
  HeadRecord expected;
  expected.incarnation = impl_->authority.incarnation;
  expected.revision = revision;
  const std::string name = state_file_name(revision);
  auto bytes = detail::read_file_bounded(
      impl_->path_of(name),
      impl_->options.limits.max_payload_bytes + kStateHeaderSize + kStateTrailerSize);
  if (!bytes.has_value()) {
    return bytes.error();
  }
  const Bytes& file = bytes.value();
  if (file.size() < kStateHeaderSize + kStateTrailerSize ||
      !magic_matches(file, kStateMagicOffset, kStateMagic)) {
    return Error(ErrorCode::corrupt_store, "a state generation is not readable");
  }
  expected.generation = ControlGeneration(get_u64(file, kStateGenerationOffset));
  expected.tick = LogicalTick(get_u64(file, kStateTickOffset));
  expected.payload_digest = read_digest_at(file, kStatePayloadDigestOffset);
  expected.payload_bytes = get_u64(file, kStatePayloadBytesOffset);
  PCP_TRY_STATUS(verify_seal(file, file.size() - kStateTrailerSize, "pcp/state-record/v1",
                             "state generation"));
  const std::uint64_t payload_bytes = get_u64(file, kStatePayloadBytesOffset);
  if (payload_bytes != file.size() - kStateHeaderSize - kStateTrailerSize) {
    return Error(ErrorCode::corrupt_store,
                 "a state generation declares a different payload length than it has");
  }
  const Bytes payload(file.begin() + static_cast<std::ptrdiff_t>(kStateHeaderSize),
                      file.begin() + static_cast<std::ptrdiff_t>(kStateHeaderSize +
                                                                payload_bytes));
  return FacilityState::decode(payload, impl_->options.limits);
}

Result<WriterLease> DurableStore::acquire_writer() {
  std::lock_guard<std::mutex> guard(impl_->authority_mutex);
  if (impl_->mode != StoreOpenMode::read_write) {
    return Error(ErrorCode::not_authoritative,
                 "the store was opened read-only and cannot take writer authority");
  }
  if (impl_->writer_held) {
    return impl_->lease;
  }
  auto lock = detail::ProcessLock::try_acquire(impl_->path_of(kLockFileName));
  if (!lock.has_value()) {
    impl_->lock_contended = true;
    return lock.error();
  }
  impl_->lock_contended = false;
  impl_->lock = std::move(lock).value();

  // Re-read the authority marker under the operating-system lock so the epoch this
  // writer takes is the epoch the previous writer left behind.
  const std::string authority_path = impl_->path_of(kAuthorityFileName);
  auto bytes = detail::read_file_bounded(authority_path, kAuthorityRecordSize);
  if (!bytes.has_value()) {
    impl_->lock.release();
    return bytes.error();
  }
  auto marker = decode_authority(bytes.value());
  if (!marker.has_value()) {
    impl_->lock.release();
    return marker.error();
  }
  auto next_epoch = marker.value().epoch.next();
  if (!next_epoch.has_value()) {
    impl_->lock.release();
    return next_epoch.error();
  }
  AuthorityMarker updated = marker.value();
  updated.epoch = next_epoch.value();
  updated.controller = ControllerIncarnation::generate();
  updated.process_id = static_cast<std::uint64_t>(
#if defined(_WIN32)
      ::GetCurrentProcessId()
#else
      ::getpid()
#endif
  );
  const Bytes record = encode_authority(updated);
  PCP_TRY_STATUS(detail::write_file_durable(authority_path, record.data(), record.size()));
  impl_->authority = updated;
  impl_->writer_held = true;
  impl_->lease = WriterLease{};
  impl_->lease.epoch_ = updated.epoch;
  impl_->lease.incarnation_ = updated.controller;
  impl_->lease.store_incarnation_ = updated.incarnation;
  impl_->lease.token_ = impl_->next_token++;
  return impl_->lease;
}

Status DurableStore::validate_writer(const WriterLease& lease) const {
  std::lock_guard<std::mutex> guard(impl_->authority_mutex);
  return impl_->check_lease(lease);
}

Status DurableStore::release_writer(const WriterLease& lease) {
  std::lock_guard<std::mutex> guard(impl_->authority_mutex);
  if (!impl_->writer_held) {
    return Status::success();
  }
  if (lease.valid() && lease.token_ != impl_->lease.token_) {
    return Status::failure(ErrorCode::stale_epoch,
                           "a superseded writer authority cannot release the current one");
  }
  impl_->lock.release();
  impl_->writer_held = false;
  impl_->lease = WriterLease{};
  return Status::success();
}

Result<CommitReport> DurableStore::commit(const WriterLease& lease,
                                          const FacilityState& next,
                                          const TransitionRecord& record) {
  std::lock_guard<std::mutex> guard(impl_->authority_mutex);
  PCP_TRY_STATUS(impl_->check_lease(lease));

  FacilityState previous;
  {
    std::shared_lock<std::shared_mutex> state_guard(impl_->state_mutex);
    if (impl_->cached_state) {
      previous = *impl_->cached_state;
    }
  }
  if (!impl_->head.present) {
    previous = FacilityState::vacant(next.facility(), next.incarnation());
  }

  // The publication must be exactly the result of applying the logged transition
  // to the previously published generation. Any disagreement is a programming
  // error and is refused rather than published.
  const bool bootstrap = record.kind == TransitionKind::facility_bootstrap;
  auto expected_revision = checked_increment(previous.revision().value());
  if (!expected_revision.has_value()) {
    return expected_revision.error();
  }
  if (next.revision().value() != expected_revision.value()) {
    return Error(ErrorCode::stale_revision,
                 "the candidate state does not advance the publication revision by one");
  }
  std::uint64_t expected_generation = previous.generation().value();
  if (transition_changes_control_generation(record.kind)) {
    auto advanced = checked_increment(expected_generation);
    if (!advanced.has_value()) {
      return advanced.error();
    }
    expected_generation = advanced.value();
  }
  if (next.generation().value() != expected_generation) {
    return Error(ErrorCode::stale_generation,
                 "the candidate state does not carry the generation this transition produces");
  }
  if (!bootstrap && !impl_->head.present) {
    return Error(ErrorCode::invalid_transition,
                 "the first publication of a store must be the facility bootstrap");
  }
  if (bootstrap && impl_->head.present) {
    return Error(ErrorCode::invalid_transition,
                 "a facility bootstrap is only valid on an empty store");
  }

  FacilityState derived = previous;
  PCP_TRY_STATUS(apply_transition(derived, record, impl_->options.limits));
  if (!(derived.canonical_digest() == next.canonical_digest())) {
    return Error(ErrorCode::internal_failure,
                 "the candidate state is not the result of applying the transition to the "
                 "previous authoritative generation");
  }

  const Bytes payload = next.encode(impl_->options.limits);
  if (payload.empty()) {
    return Error(ErrorCode::limit_exceeded,
                 "the candidate state could not be encoded within the configured bounds");
  }

  CommitReport report;
  report.generation = next.generation();
  report.revision = next.revision();
  report.tick = next.tick();
  report.payload_bytes = payload.size();
  report.payload_digest = sha256_domain(kStateDigestDomain, payload.data(), payload.size());
  report.published_file = state_file_name(next.revision());
  report.staging_file = report.published_file + ".tmp";

  const std::string staging_path = impl_->staging_path(report.staging_file);
  const std::string published_path = impl_->path_of(report.published_file);

  Bytes image(kStateHeaderSize + payload.size() + kStateTrailerSize, 0);
  put_magic(image, kStateMagicOffset, kStateMagic);
  put_u32(image, kStateVersionOffset, kStoreFormatVersion);
  put_u32(image, kStateRecordSizeOffset, static_cast<std::uint32_t>(image.size()));
  put_u64(image, kStateGenerationOffset, next.generation().value());
  put_u64(image, kStateRevisionOffset, next.revision().value());
  put_u64(image, kStateIncarnationOffset, next.incarnation().high());
  put_u64(image, kStateIncarnationOffset + 8, next.incarnation().low());
  put_u64(image, kStatePayloadBytesOffset, payload.size());
  std::memcpy(image.data() + kStatePayloadDigestOffset, report.payload_digest.bytes().data(),
              Digest::kBytes);
  put_u64(image, kStateTickOffset, next.tick().value());
  std::memcpy(image.data() + kStateHeaderSize, payload.data(), payload.size());
  seal_record(image, image.size() - kStateTrailerSize, "pcp/state-record/v1");

  // Stage 1: write staging and flush durable content.
  PCP_TRY_STATUS(
      detail::write_new_file_durable(staging_path, image.data(), image.size()));
  PCP_TRY_STATUS(detail::flush_directory(impl_->path_of(kStagingDirectoryName)));
  report.reached = CommitStage::staging_written;
  impl_->notify(CommitStage::staging_written, report);
  report.reached = CommitStage::staging_flushed;
  impl_->notify(CommitStage::staging_flushed, report);

  // Stage 2: read the staging file back and verify it byte for byte.
  auto read_back = detail::read_file_bounded(staging_path, image.size());
  if (!read_back.has_value()) {
    return read_back.error();
  }
  if (read_back.value() != image) {
    return Error(ErrorCode::io_failure,
                 "the staged generation did not read back identical to what was written");
  }
  report.read_back_verified = true;
  report.reached = CommitStage::staging_read_back_verified;
  impl_->notify(CommitStage::staging_read_back_verified, report);

  // Stage 3: atomically publish the generation file.
  PCP_TRY_STATUS(detail::replace_file_atomic(staging_path, published_path));
  PCP_TRY_STATUS(detail::flush_directory(impl_->root));
  report.reached = CommitStage::generation_published;
  impl_->notify(CommitStage::generation_published, report);

  // Stage 4: commit the authoritative head marker. This is the commit point.
  HeadRecord head_record;
  head_record.incarnation = next.incarnation();
  head_record.generation = next.generation();
  head_record.revision = next.revision();
  head_record.tick = next.tick();
  head_record.payload_digest = report.payload_digest;
  head_record.payload_bytes = payload.size();
  head_record.state_file = report.published_file;
  const Bytes head_image = encode_head(head_record);
  const std::string head_staging = impl_->staging_path("head.tmp");
  PCP_TRY_STATUS(detail::write_new_file_durable(head_staging, head_image.data(),
                                                head_image.size()));
  auto head_read_back = detail::read_file_bounded(head_staging, kHeadRecordSize);
  if (!head_read_back.has_value()) {
    return head_read_back.error();
  }
  if (head_read_back.value() != head_image) {
    return Error(ErrorCode::io_failure, "the staged head marker did not read back identical");
  }
  PCP_TRY_STATUS(detail::replace_file_atomic(head_staging, impl_->path_of(kHeadFileName)));
  PCP_TRY_STATUS(detail::flush_directory(impl_->root));
  report.head_committed = true;
  report.reached = CommitStage::head_committed;
  impl_->notify(CommitStage::head_committed, report);

  // Stage 5: advance the rollback fence.
  AuthorityMarker marker = impl_->authority;
  if (next.revision() > marker.highest_revision) {
    marker.highest_revision = next.revision();
  }
  if (next.generation() > marker.highest_generation) {
    marker.highest_generation = next.generation();
  }
  const Bytes authority_image = encode_authority(marker);
  const std::string authority_staging = impl_->staging_path("authority.tmp");
  PCP_TRY_STATUS(detail::write_new_file_durable(authority_staging, authority_image.data(),
                                                authority_image.size()));
  PCP_TRY_STATUS(detail::replace_file_atomic(authority_staging,
                                             impl_->path_of(kAuthorityFileName)));
  impl_->authority = marker;
  report.reached = CommitStage::authority_marked;
  impl_->notify(CommitStage::authority_marked, report);

  // Stage 6: retire safe residue.
  ++report.retired_residue;
  auto entries = detail::list_directory(impl_->root, impl_->options.limits);
  if (entries.has_value()) {
    std::vector<StateRevision> published;
    for (const std::string& name : entries.value()) {
      auto parsed = parse_state_file_name(name);
      if (parsed.has_value() && parsed.value() <= next.revision()) {
        published.push_back(parsed.value());
      }
    }
    std::sort(published.begin(), published.end());
    while (published.size() > impl_->options.retained_publications) {
      const StateRevision victim = published.front();
      published.erase(published.begin());
      if (victim == next.revision()) {
        continue;
      }
      PCP_TRY_STATUS(detail::remove_file_if_present(impl_->path_of(state_file_name(victim))));
      ++report.retired_residue;
    }
  }
  report.reached = CommitStage::residue_retired;
  impl_->notify(CommitStage::residue_retired, report);

  {
    std::unique_lock<std::shared_mutex> state_guard(impl_->state_mutex);
    impl_->head.present = true;
    impl_->head.incarnation = head_record.incarnation;
    impl_->head.generation = head_record.generation;
    impl_->head.revision = head_record.revision;
    impl_->head.tick = head_record.tick;
    impl_->head.payload_digest = head_record.payload_digest;
    impl_->head.payload_bytes = head_record.payload_bytes;
    impl_->head.state_file = head_record.state_file;
    impl_->cached_state = std::make_shared<const FacilityState>(next);
  }
  return report;
}

Result<StoreIntegrityReport> DurableStore::verify_integrity() const {
  StoreIntegrityReport report;
  std::shared_lock<std::shared_mutex> state_guard(impl_->state_mutex);

  const std::string authority_path = impl_->path_of(kAuthorityFileName);
  report.authority_present = detail::path_exists(authority_path);
  if (report.authority_present) {
    auto bytes = detail::read_file_bounded(authority_path, kAuthorityRecordSize);
    if (bytes.has_value()) {
      auto marker = decode_authority(bytes.value());
      report.authority_checksum_ok = marker.has_value();
    }
  }

  const std::string head_path = impl_->path_of(kHeadFileName);
  report.head_present = detail::path_exists(head_path);
  std::optional<HeadRecord> head_record;
  if (report.head_present) {
    auto bytes = detail::read_file_bounded(head_path, kHeadRecordSize);
    if (bytes.has_value()) {
      auto decoded = decode_head(bytes.value());
      if (decoded.has_value()) {
        report.head_checksum_ok = true;
        head_record = decoded.value();
      }
    }
  }

  if (head_record.has_value()) {
    const std::string full = impl_->path_of(head_record->state_file);
    report.payload_present = detail::path_exists(full);
    if (report.payload_present) {
      auto bytes = detail::read_file_bounded(
          full, impl_->options.limits.max_payload_bytes + kStateHeaderSize + kStateTrailerSize);
      if (bytes.has_value()) {
        const Bytes& file = bytes.value();
        if (file.size() >= kStateHeaderSize + kStateTrailerSize &&
            magic_matches(file, kStateMagicOffset, kStateMagic) &&
            get_u32(file, kStateRecordSizeOffset) == file.size()) {
          const std::uint64_t payload_bytes = get_u64(file, kStatePayloadBytesOffset);
          if (kStateHeaderSize + payload_bytes + kStateTrailerSize == file.size()) {
            const Digest digest = sha256_domain(kStateDigestDomain, file.data() + kStateHeaderSize,
                                                static_cast<std::size_t>(payload_bytes));
            report.payload_checksum_ok =
                verify_seal(file, file.size() - kStateTrailerSize, "pcp/state-record/v1",
                            "state generation")
                    .ok();
            report.head_matches_payload = (digest == head_record->payload_digest);
          }
        }
      }
    }
    report.incarnation_matches = head_record->incarnation == impl_->authority.incarnation;
    report.rollback_detected = head_record->revision < impl_->authority.highest_revision;
  }

  auto entries = detail::list_directory(impl_->root, impl_->options.limits);
  if (entries.has_value()) {
    for (const std::string& name : entries.value()) {
      auto parsed = parse_state_file_name(name);
      if (!parsed.has_value()) {
        continue;
      }
      report.retained_generations.push_back(parsed.value());
      if (head_record.has_value() && parsed.value() > head_record->revision) {
        report.orphan_generation_files.push_back(name);
      }
    }
  }
  std::sort(report.retained_generations.begin(), report.retained_generations.end());
  const std::string staging = impl_->path_of(kStagingDirectoryName);
  if (detail::is_directory(staging)) {
    auto residue = detail::list_directory(staging, impl_->options.limits);
    if (residue.has_value()) {
      report.staging_residue = residue.value();
    }
  }

  report.ok = (!report.head_present || (report.head_checksum_ok && report.payload_present &&
                                        report.payload_checksum_ok &&
                                        report.head_matches_payload)) &&
              report.authority_present && report.authority_checksum_ok &&
              !report.rollback_detected && report.incarnation_matches &&
              report.orphan_generation_files.empty() && report.staging_residue.empty();
  if (!report.head_present) {
    report.detail = "the store holds no authoritative generation";
  } else if (report.ok) {
    report.detail = "the head marker, the state generation, and the authority fence agree";
  } else {
    report.detail = "at least one integrity check failed";
  }
  return report;
}

Result<ReplayReport> DurableStore::verify_deterministic_replay() const {
  ReplayReport report;
  const std::vector<StateRevision> published = retained_publications();
  if (published.size() < 2) {
    report.ok = true;
    report.detail = "fewer than two publications are retained; replay cannot be stepped";
    return report;
  }
  for (std::size_t index = 0; index + 1 < published.size(); ++index) {
    auto older = load_publication(published[index]);
    if (!older.has_value()) {
      return older.error();
    }
    auto newer = load_publication(published[index + 1]);
    if (!newer.has_value()) {
      return newer.error();
    }
    ReplayStepReport step;
    step.from_revision = published[index];
    step.to_revision = published[index + 1];
    step.from_generation = older.value().generation();
    step.to_generation = newer.value().generation();
    step.expected_digest = newer.value().canonical_digest();
    if (!(newer.value().revision() == published[index + 1])) {
      report.ok = false;
      report.detail = "a retained publication does not carry the revision its name declares";
      return report;
    }
    const std::vector<TransitionLogEntry>& log = newer.value().transition_log();
    const TransitionLogEntry* entry = nullptr;
    for (auto candidate = log.rbegin(); candidate != log.rend(); ++candidate) {
      if (candidate->revision == published[index + 1]) {
        entry = &(*candidate);
        break;
      }
    }
    if (entry == nullptr) {
      step.matched = false;
      step.actual_digest = Digest::zero();
      report.steps.push_back(step);
      report.ok = false;
      report.detail =
          "a retained publication has no transition log entry, so replay cannot be verified";
      return report;
    }
    step.kind = entry->kind;
    if (!(older.value().canonical_digest() == entry->previous_state_digest)) {
      step.matched = false;
      step.actual_digest = older.value().canonical_digest();
      report.steps.push_back(step);
      report.ok = false;
      report.detail =
          "a transition log entry names a predecessor digest that does not match the "
          "previous publication";
      return report;
    }
    TransitionRecord record;
    record.kind = entry->kind;
    record.key = entry->key;
    record.payload = entry->payload;
    FacilityState replayed = older.value();
    const Status applied = apply_transition(replayed, record, impl_->options.limits);
    if (!applied.ok()) {
      step.matched = false;
      step.actual_digest = Digest::zero();
      report.steps.push_back(step);
      report.ok = false;
      report.detail = std::string("replay refused: ") + applied.describe();
      return report;
    }
    step.actual_digest = replayed.canonical_digest();
    step.matched = step.actual_digest == step.expected_digest;
    report.steps.push_back(step);
    if (!step.matched) {
      report.ok = false;
      report.detail =
          "deterministic replay produced a different state than the published one";
      return report;
    }
    ++report.steps_checked;
  }
  report.ok = true;
  report.detail = "deterministic replay reproduced every retained publication";
  return report;
}

void DurableStore::close() {
  std::lock_guard<std::mutex> guard(impl_->authority_mutex);
  if (impl_->writer_held) {
    impl_->lock.release();
    impl_->writer_held = false;
    impl_->lease = WriterLease{};
  }
}

}  // namespace power_control_plane
