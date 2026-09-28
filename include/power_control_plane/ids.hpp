#pragma once

// Strongly typed identities.
//
// Power Control Plane separates, and never collapses into a generic integer:
//
//   ControllerEpoch         monotonically increasing writer-authority generation
//   ControllerIncarnation   unique identity of one writer session within an epoch
//   StoreIncarnation        unique identity of one durable store incarnation
//   ControlGeneration       authoritative facility electrical-control generation
//   StateRevision           revision of metadata inside one control generation
//   PolicyRevision          revision of the power policy rule set
//   EvidenceGeneration      generation of one external evidence source
//   EvidenceRevision        revision of one external evidence source
//   LogicalTick             monotonic logical clock (no wall-clock is persisted)
//   AttemptId               identity of one authorized actuation attempt
//   PermissionId            identity of one issued permission grant
//
// All of these are unsigned 64-bit counters except the incarnations, which are
// 128-bit opaque values. They are distinct C++ types so that transposing two of
// them is a compile error rather than a field incident.

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

#include "power_control_plane/checked.hpp"
#include "power_control_plane/digest.hpp"
#include "power_control_plane/error.hpp"

namespace power_control_plane {

namespace detail {
struct Random128 {
  std::uint64_t high;
  std::uint64_t low;
};
// Operating-system entropy. Used only to allocate identity values, never to
// produce canonical content.
[[nodiscard]] Random128 random_128();
}  // namespace detail

template <class Tag>
class Counter {
 public:
  using value_type = std::uint64_t;

  constexpr Counter() = default;
  explicit constexpr Counter(std::uint64_t value) noexcept : value_(value) {}

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept { return value_ == 0; }

  // Checked successor; refuses to wrap.
  [[nodiscard]] Result<Counter> next() const {
    auto advanced = checked_increment(value_);
    if (!advanced.has_value()) {
      return advanced.error();
    }
    return Counter(advanced.value());
  }

  [[nodiscard]] Result<Counter> advance_by(std::uint64_t delta) const {
    auto advanced = checked_add(value_, delta);
    if (!advanced.has_value()) {
      return advanced.error();
    }
    return Counter(advanced.value());
  }

  friend constexpr bool operator==(Counter a, Counter b) noexcept {
    return a.value_ == b.value_;
  }
  friend constexpr bool operator!=(Counter a, Counter b) noexcept {
    return a.value_ != b.value_;
  }
  friend constexpr bool operator<(Counter a, Counter b) noexcept {
    return a.value_ < b.value_;
  }
  friend constexpr bool operator<=(Counter a, Counter b) noexcept {
    return a.value_ <= b.value_;
  }
  friend constexpr bool operator>(Counter a, Counter b) noexcept {
    return a.value_ > b.value_;
  }
  friend constexpr bool operator>=(Counter a, Counter b) noexcept {
    return a.value_ >= b.value_;
  }

 private:
  std::uint64_t value_ = 0;
};

struct ControllerEpochTag;
struct ControlGenerationTag;
struct StateRevisionTag;
struct PolicyRevisionTag;
struct EvidenceGenerationTag;
struct EvidenceRevisionTag;
struct LogicalTickTag;
struct AttemptIdTag;
struct PermissionIdTag;

using ControllerEpoch = Counter<ControllerEpochTag>;
using ControlGeneration = Counter<ControlGenerationTag>;
using StateRevision = Counter<StateRevisionTag>;
using PolicyRevision = Counter<PolicyRevisionTag>;
using EvidenceGeneration = Counter<EvidenceGenerationTag>;
using EvidenceRevision = Counter<EvidenceRevisionTag>;
using LogicalTick = Counter<LogicalTickTag>;
using AttemptId = Counter<AttemptIdTag>;
using PermissionId = Counter<PermissionIdTag>;

// ---------------------------------------------------------------------------
// Opaque 128-bit incarnations
// ---------------------------------------------------------------------------

template <class Tag>
class Opaque128Id {
 public:
  constexpr Opaque128Id() = default;

  static Opaque128Id from_parts(std::uint64_t high, std::uint64_t low) noexcept {
    Opaque128Id id;
    id.high_ = high;
    id.low_ = low;
    return id;
  }

  // Allocates a fresh identity from operating-system entropy.
  static Opaque128Id generate() noexcept {
    const detail::Random128 bits = detail::random_128();
    return from_parts(bits.high, bits.low);
  }

  static Result<Opaque128Id> from_hex(std::string_view hex) {
    if (hex.size() != 32) {
      return Error(ErrorCode::invalid_argument,
                   "128-bit identity hex text must be exactly 32 characters");
    }
    std::uint64_t high = 0;
    std::uint64_t low = 0;
    for (std::size_t index = 0; index < 32; ++index) {
      const char digit = hex[index];
      std::uint64_t value = 0;
      if (digit >= '0' && digit <= '9') {
        value = static_cast<std::uint64_t>(digit - '0');
      } else if (digit >= 'a' && digit <= 'f') {
        value = static_cast<std::uint64_t>(digit - 'a') + 10u;
      } else if (digit >= 'A' && digit <= 'F') {
        value = static_cast<std::uint64_t>(digit - 'A') + 10u;
      } else {
        return Error(ErrorCode::invalid_argument,
                     "128-bit identity hex text contains a non-hex character");
      }
      if (index < 16) {
        high = (high << 4) | value;
      } else {
        low = (low << 4) | value;
      }
    }
    return from_parts(high, low);
  }

  [[nodiscard]] constexpr std::uint64_t high() const noexcept { return high_; }
  [[nodiscard]] constexpr std::uint64_t low() const noexcept { return low_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept {
    return high_ == 0 && low_ == 0;
  }

  [[nodiscard]] std::string to_hex() const {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.resize(32);
    for (std::size_t index = 0; index < 16; ++index) {
      const unsigned shift = static_cast<unsigned>(60 - 4 * index);
      out[index] = kDigits[(high_ >> shift) & 0xFu];
      out[index + 16] = kDigits[(low_ >> shift) & 0xFu];
    }
    return out;
  }

  friend constexpr bool operator==(Opaque128Id a, Opaque128Id b) noexcept {
    return a.high_ == b.high_ && a.low_ == b.low_;
  }
  friend constexpr bool operator!=(Opaque128Id a, Opaque128Id b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(Opaque128Id a, Opaque128Id b) noexcept {
    if (a.high_ != b.high_) {
      return a.high_ < b.high_;
    }
    return a.low_ < b.low_;
  }

 private:
  std::uint64_t high_ = 0;
  std::uint64_t low_ = 0;
};

struct StoreIncarnationTag;
struct ControllerIncarnationTag;

using StoreIncarnation = Opaque128Id<StoreIncarnationTag>;
using ControllerIncarnation = Opaque128Id<ControllerIncarnationTag>;

// ---------------------------------------------------------------------------
// Bounded textual identifiers
// ---------------------------------------------------------------------------

// Identifier text is ASCII, 1..64 bytes, starts with an alphanumeric, and
// continues with [A-Za-z0-9._:-]. The grammar is deliberately narrow: these
// values reach log lines, JSON documents, file names, and CLI arguments. The
// reserved path segments "." and ".." are refused outright so an identifier can
// never be interpreted as a directory traversal.
template <class Tag>
class TextId {
 public:
  static constexpr std::size_t kMaxLength = 64;

  TextId() = default;

  static Result<TextId> parse(std::string_view text) {
    if (text.empty()) {
      return Error(ErrorCode::invalid_argument, "identifier must not be empty");
    }
    if (text.size() > kMaxLength) {
      return Error(ErrorCode::limit_exceeded,
                   "identifier exceeds 64 bytes");
    }
    for (std::size_t index = 0; index < text.size(); ++index) {
      const char character = text[index];
      const bool is_alpha =
          (character >= 'A' && character <= 'Z') ||
          (character >= 'a' && character <= 'z');
      const bool is_digit = character >= '0' && character <= '9';
      if (index == 0) {
        if (!is_alpha && !is_digit) {
          return Error(ErrorCode::invalid_argument,
                       "identifier must start with an ASCII letter or digit");
        }
        continue;
      }
      const bool is_punctuation = character == '.' || character == '_' ||
                                  character == ':' || character == '-';
      if (!is_alpha && !is_digit && !is_punctuation) {
        return Error(ErrorCode::invalid_argument,
                     "identifier contains a character outside [A-Za-z0-9._:-]");
      }
    }
    if (text == "." || text == "..") {
      return Error(ErrorCode::path_rejected,
                   "identifier must not be a reserved path segment");
    }
    TextId id;
    id.value_.assign(text);
    return id;
  }

  [[nodiscard]] const std::string& value() const noexcept { return value_; }
  [[nodiscard]] std::string_view view() const noexcept { return value_; }
  [[nodiscard]] bool empty() const noexcept { return value_.empty(); }

  friend bool operator==(const TextId& a, const TextId& b) noexcept {
    return a.value_ == b.value_;
  }
  friend bool operator!=(const TextId& a, const TextId& b) noexcept {
    return !(a == b);
  }
  friend bool operator<(const TextId& a, const TextId& b) noexcept {
    return a.value_ < b.value_;
  }

 private:
  std::string value_;
};

struct FacilityIdTag;
struct ActionIdTag;
struct ActionTargetIdTag;
struct RuleIdTag;
struct InterlockIdTag;
struct ObligationIdTag;
struct CapacityCommitmentIdTag;
struct EvidenceSourceIdTag;
struct AuthorityReferenceTag;
struct AdapterIdTag;
struct OperationTagTag;

using FacilityId = TextId<FacilityIdTag>;
using ActionId = TextId<ActionIdTag>;
using ActionTargetId = TextId<ActionTargetIdTag>;
using RuleId = TextId<RuleIdTag>;
using InterlockId = TextId<InterlockIdTag>;
using ObligationId = TextId<ObligationIdTag>;
using CapacityCommitmentId = TextId<CapacityCommitmentIdTag>;
using EvidenceSourceId = TextId<EvidenceSourceIdTag>;
using AuthorityReference = TextId<AuthorityReferenceTag>;
using AdapterId = TextId<AdapterIdTag>;
using OperationTag = TextId<OperationTagTag>;

// ---------------------------------------------------------------------------
// Planned-against authority
// ---------------------------------------------------------------------------

// The exact authority a state-dependent request was planned against. Every
// mutation names one of these and is refused when any component has moved on.
// A request that cannot state what it was planned against cannot be evaluated.
struct PlannedAgainst {
  ControlGeneration generation;
  StateRevision revision;
  PolicyRevision policy_revision;
  Digest evidence_digest;
};

// ---------------------------------------------------------------------------
// Idempotency key
// ---------------------------------------------------------------------------

// A caller supplied stable identity for one logical operation. Retries of a lost
// response reuse the key; a genuinely new operation must use a new key.
class IdempotencyKey {
 public:
  IdempotencyKey() = default;

  static Result<IdempotencyKey> from_digest(Digest digest) {
    IdempotencyKey key;
    key.digest_ = digest;
    return key;
  }

  static Result<IdempotencyKey> from_hex(std::string_view hex) {
    auto digest = Digest::from_hex(hex);
    if (!digest.has_value()) {
      return digest.error();
    }
    return from_digest(digest.value());
  }

  // Derives a key from caller supplied text. Callers that already own a stable
  // operation identity should use from_digest instead.
  static Result<IdempotencyKey> derive(std::string_view text) {
    if (text.empty()) {
      return Error(ErrorCode::invalid_argument,
                   "idempotency text must not be empty");
    }
    return from_digest(sha256_domain("pcp/idempotency-key/v1", text));
  }

  [[nodiscard]] const Digest& digest() const noexcept { return digest_; }
  [[nodiscard]] std::string to_hex() const { return digest_.to_hex(); }
  [[nodiscard]] bool is_zero() const noexcept { return digest_.is_zero(); }

  friend bool operator==(const IdempotencyKey& a, const IdempotencyKey& b) noexcept {
    return a.digest_ == b.digest_;
  }
  friend bool operator!=(const IdempotencyKey& a, const IdempotencyKey& b) noexcept {
    return !(a == b);
  }
  friend bool operator<(const IdempotencyKey& a, const IdempotencyKey& b) noexcept {
    return a.digest_ < b.digest_;
  }

 private:
  Digest digest_{};
};

}  // namespace power_control_plane
