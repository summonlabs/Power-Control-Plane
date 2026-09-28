#include "power_control_plane/digest.hpp"

// SHA-256 (FIPS 180-4). Implemented here rather than pulled from a dependency:
// the repository is dependency-free by policy and the algorithm is small and
// fully specified. The test suite verifies it against the published NIST vectors
// (empty string, "abc", the multi-block message, and the one-million 'a' message)
// and against a byte-at-a-time feeding schedule that must produce the same digest
// as a single-shot feed.

namespace power_control_plane {
namespace {

constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::uint32_t kInitialState[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned shift) noexcept {
  return (value >> shift) | (value << (32u - shift));
}

}  // namespace

Digest Digest::zero() { return Digest{}; }

Digest Digest::from_array(const std::array<std::uint8_t, kBytes>& bytes) noexcept {
  Digest digest;
  digest.bytes_ = bytes;
  return digest;
}

Result<Digest> Digest::from_bytes(const std::uint8_t* data, std::size_t size) {
  if (size != kBytes) {
    return Error(ErrorCode::invalid_argument,
                 "a digest is exactly 32 bytes");
  }
  if (data == nullptr) {
    return Error(ErrorCode::invalid_argument, "digest source pointer is null");
  }
  Digest digest;
  for (std::size_t index = 0; index < kBytes; ++index) {
    digest.bytes_[index] = data[index];
  }
  return digest;
}

Result<Digest> Digest::from_hex(std::string_view hex) {
  if (hex.size() != kBytes * 2) {
    return Error(ErrorCode::invalid_argument,
                 "digest hex text must be exactly 64 characters");
  }
  Digest digest;
  for (std::size_t index = 0; index < kBytes; ++index) {
    unsigned value = 0;
    for (unsigned half = 0; half < 2; ++half) {
      const char digit = hex[index * 2 + half];
      unsigned nibble = 0;
      if (digit >= '0' && digit <= '9') {
        nibble = static_cast<unsigned>(digit - '0');
      } else if (digit >= 'a' && digit <= 'f') {
        nibble = static_cast<unsigned>(digit - 'a') + 10u;
      } else if (digit >= 'A' && digit <= 'F') {
        nibble = static_cast<unsigned>(digit - 'A') + 10u;
      } else {
        return Error(ErrorCode::invalid_argument,
                     "digest hex text contains a non-hex character");
      }
      value = (value << 4) | nibble;
    }
    digest.bytes_[index] = static_cast<std::uint8_t>(value);
  }
  return digest;
}

std::string Digest::to_hex() const {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(kBytes * 2);
  for (std::size_t index = 0; index < kBytes; ++index) {
    out[index * 2] = kDigits[bytes_[index] >> 4];
    out[index * 2 + 1] = kDigits[bytes_[index] & 0x0Fu];
  }
  return out;
}

bool Digest::is_zero() const noexcept {
  for (const std::uint8_t byte : bytes_) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

void Sha256::reset() noexcept {
  for (std::size_t index = 0; index < state_.size(); ++index) {
    state_[index] = kInitialState[index];
  }
  buffer_.fill(0);
  buffered_ = 0;
  total_bytes_ = 0;
}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::uint32_t schedule[64];
  for (std::size_t index = 0; index < 16; ++index) {
    const std::size_t base = index * 4;
    schedule[index] = (static_cast<std::uint32_t>(block[base]) << 24) |
                      (static_cast<std::uint32_t>(block[base + 1]) << 16) |
                      (static_cast<std::uint32_t>(block[base + 2]) << 8) |
                      static_cast<std::uint32_t>(block[base + 3]);
  }
  for (std::size_t index = 16; index < 64; ++index) {
    const std::uint32_t s0 = rotate_right(schedule[index - 15], 7) ^
                             rotate_right(schedule[index - 15], 18) ^
                             (schedule[index - 15] >> 3);
    const std::uint32_t s1 = rotate_right(schedule[index - 2], 17) ^
                             rotate_right(schedule[index - 2], 19) ^
                             (schedule[index - 2] >> 10);
    schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t index = 0; index < 64; ++index) {
    const std::uint32_t capital_s1 =
        rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    const std::uint32_t choose = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + capital_s1 + choose + kRoundConstants[index] +
                                schedule[index];
    const std::uint32_t capital_s0 =
        rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = capital_s0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const std::uint8_t* data, std::size_t size) noexcept {
  if (data == nullptr || size == 0) {
    return;
  }
  total_bytes_ += size;
  std::size_t offset = 0;

  if (buffered_ > 0) {
    while (buffered_ < buffer_.size() && offset < size) {
      buffer_[buffered_] = data[offset];
      ++buffered_;
      ++offset;
    }
    if (buffered_ == buffer_.size()) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }

  while (size - offset >= buffer_.size()) {
    compress(data + offset);
    offset += buffer_.size();
  }

  while (offset < size) {
    buffer_[buffered_] = data[offset];
    ++buffered_;
    ++offset;
  }
}

void Sha256::update(std::string_view text) noexcept {
  update(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

Digest Sha256::finalize() noexcept {
  const std::uint64_t bit_length = total_bytes_ * 8u;
  buffer_[buffered_] = 0x80u;
  ++buffered_;
  if (buffered_ > 56) {
    while (buffered_ < buffer_.size()) {
      buffer_[buffered_] = 0;
      ++buffered_;
    }
    compress(buffer_.data());
    buffered_ = 0;
  }
  while (buffered_ < 56) {
    buffer_[buffered_] = 0;
    ++buffered_;
  }
  for (std::size_t index = 0; index < 8; ++index) {
    buffer_[56 + index] =
        static_cast<std::uint8_t>((bit_length >> (56u - 8u * index)) & 0xFFu);
  }
  compress(buffer_.data());

  std::array<std::uint8_t, Digest::kBytes> out{};
  for (std::size_t index = 0; index < state_.size(); ++index) {
    out[index * 4] = static_cast<std::uint8_t>((state_[index] >> 24) & 0xFFu);
    out[index * 4 + 1] = static_cast<std::uint8_t>((state_[index] >> 16) & 0xFFu);
    out[index * 4 + 2] = static_cast<std::uint8_t>((state_[index] >> 8) & 0xFFu);
    out[index * 4 + 3] = static_cast<std::uint8_t>(state_[index] & 0xFFu);
  }
  return Digest::from_array(out);
}

Digest sha256(const std::uint8_t* data, std::size_t size) noexcept {
  Sha256 hasher;
  hasher.update(data, size);
  return hasher.finalize();
}

Digest sha256(std::string_view text) noexcept {
  return sha256(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

Digest sha256_domain(std::string_view domain, std::string_view text) noexcept {
  return sha256_domain(domain, reinterpret_cast<const std::uint8_t*>(text.data()),
                       text.size());
}

Digest sha256_domain(std::string_view domain, const std::uint8_t* data,
                     std::size_t size) noexcept {
  Sha256 hasher;
  const std::uint8_t separator = 0x00u;
  hasher.update(reinterpret_cast<const std::uint8_t*>(domain.data()), domain.size());
  hasher.update(&separator, 1);
  hasher.update(data, size);
  return hasher.finalize();
}

}  // namespace power_control_plane
