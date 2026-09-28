#pragma once

// SHA-256 and the 32-byte Digest value type.
//
// Digest is used for three distinct purposes and each use is documented at its
// call site:
//   * content digest of external evidence (an adapter supplied fingerprint),
//   * canonical state digest (deterministic encoding of authoritative state),
//   * idempotency keys (caller supplied stable retry identity).
//
// SHA-256 is implemented here rather than pulled from a dependency: the
// repository is dependency-free by policy and the algorithm is small, fully
// specified, and verified against the published NIST test vectors in the test
// suite.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "power_control_plane/error.hpp"

namespace power_control_plane {

class Digest {
 public:
  static constexpr std::size_t kBytes = 32;

  constexpr Digest() = default;

  static Digest zero();
  static Digest from_array(const std::array<std::uint8_t, kBytes>& bytes) noexcept;
  static Result<Digest> from_hex(std::string_view hex);
  static Result<Digest> from_bytes(const std::uint8_t* data, std::size_t size);

  [[nodiscard]] const std::array<std::uint8_t, kBytes>& bytes() const noexcept {
    return bytes_;
  }
  [[nodiscard]] std::string to_hex() const;
  [[nodiscard]] bool is_zero() const noexcept;

  friend bool operator==(const Digest& a, const Digest& b) noexcept {
    return a.bytes_ == b.bytes_;
  }
  friend bool operator!=(const Digest& a, const Digest& b) noexcept {
    return !(a == b);
  }
  friend bool operator<(const Digest& a, const Digest& b) noexcept {
    return a.bytes_ < b.bytes_;
  }

 private:
  std::array<std::uint8_t, kBytes> bytes_{};
};

// Incremental SHA-256. Feed arbitrary chunks, then finalize once.
class Sha256 {
 public:
  Sha256() { reset(); }

  void reset() noexcept;
  void update(const std::uint8_t* data, std::size_t size) noexcept;
  void update(std::string_view text) noexcept;
  [[nodiscard]] Digest finalize() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
};

[[nodiscard]] Digest sha256(const std::uint8_t* data, std::size_t size) noexcept;
[[nodiscard]] Digest sha256(std::string_view text) noexcept;

// Domain-separated hashing: mixes a textual domain tag into the digest so that
// digests computed for different purposes over identical bytes cannot collide by
// accident.
[[nodiscard]] Digest sha256_domain(std::string_view domain,
                                   const std::uint8_t* data,
                                   std::size_t size) noexcept;
[[nodiscard]] Digest sha256_domain(std::string_view domain, std::string_view text) noexcept;

}  // namespace power_control_plane
