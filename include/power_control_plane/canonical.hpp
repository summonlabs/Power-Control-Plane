#pragma once

// Deterministic canonical encoding.
//
// The encoding is fixed-width little-endian for integers, length-prefixed for
// text and byte strings, and contains no padding, no alignment, no locale
// dependent formatting, no timestamps, no iteration-order dependent sequences,
// and no process specific values. Two logically identical values therefore
// always produce byte-identical output, and the same bytes always decode back to
// the same value.
//
// Text is length-prefixed with a 32-bit little-endian byte count and every decode
// is bounded by Limits before allocating.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/digest.hpp"
#include "power_control_plane/error.hpp"

namespace power_control_plane {

using Bytes = std::vector<std::uint8_t>;

class CanonicalWriter {
 public:
  CanonicalWriter() = default;

  void u8(std::uint8_t value) { buffer_.push_back(value); }

  void u16(std::uint16_t value) {
    buffer_.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    buffer_.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
  }

  void u32(std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
      buffer_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
  }

  void u64(std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
      buffer_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
  }

  void boolean(bool value) { u8(value ? 1u : 0u); }

  void digest(const Digest& value) {
    buffer_.insert(buffer_.end(), value.bytes().begin(), value.bytes().end());
  }

  // Length-prefixed text. The caller states the bound; the writer refuses to
  // encode text longer than that bound so that oversize state can never be
  // published.
  [[nodiscard]] Status text(std::string_view value, std::size_t max_bytes) {
    if (value.size() > max_bytes) {
      return Status::failure(ErrorCode::limit_exceeded,
                             "text exceeds the configured canonical bound");
    }
    if (value.size() > 0xFFFFFFFFull) {
      return Status::failure(ErrorCode::limit_exceeded,
                             "text length does not fit a 32-bit prefix");
    }
    u32(static_cast<std::uint32_t>(value.size()));
    buffer_.insert(buffer_.end(), value.begin(), value.end());
    return Status::success();
  }

  [[nodiscard]] Status bytes(const Bytes& value, std::size_t max_bytes) {
    if (value.size() > max_bytes) {
      return Status::failure(ErrorCode::limit_exceeded,
                             "byte string exceeds the configured canonical bound");
    }
    if (value.size() > 0xFFFFFFFFull) {
      return Status::failure(ErrorCode::limit_exceeded,
                             "byte string length does not fit a 32-bit prefix");
    }
    u32(static_cast<std::uint32_t>(value.size()));
    buffer_.insert(buffer_.end(), value.begin(), value.end());
    return Status::success();
  }

  [[nodiscard]] Status text(std::string_view value) {
    return text(value, 0xFFFFFFFFull);
  }

  [[nodiscard]] const Bytes& buffer() const noexcept { return buffer_; }
  [[nodiscard]] Bytes take() noexcept { return std::move(buffer_); }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
  void clear() noexcept { buffer_.clear(); }

 private:
  Bytes buffer_;
};

class CanonicalReader {
 public:
  CanonicalReader(const std::uint8_t* data, std::size_t size) noexcept
      : data_(data), size_(size) {}

  explicit CanonicalReader(const Bytes& bytes) noexcept
      : data_(bytes.data()), size_(bytes.size()) {}

  [[nodiscard]] Result<std::uint8_t> u8() {
    if (remaining() < 1) {
      return truncated();
    }
    return data_[offset_++];
  }

  [[nodiscard]] Result<std::uint16_t> u16() {
    if (remaining() < 2) {
      return truncated();
    }
    std::uint16_t value = 0;
    for (unsigned index = 0; index < 2; ++index) {
      value |= static_cast<std::uint16_t>(data_[offset_++]) << (8 * index);
    }
    return value;
  }

  [[nodiscard]] Result<std::uint32_t> u32() {
    if (remaining() < 4) {
      return truncated();
    }
    std::uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index) {
      value |= static_cast<std::uint32_t>(data_[offset_++]) << (8 * index);
    }
    return value;
  }

  [[nodiscard]] Result<std::uint64_t> u64() {
    if (remaining() < 8) {
      return truncated();
    }
    std::uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index) {
      value |= static_cast<std::uint64_t>(data_[offset_++]) << (8 * index);
    }
    return value;
  }

  [[nodiscard]] Result<bool> boolean() {
    auto raw = u8();
    if (!raw.has_value()) {
      return raw.error();
    }
    if (raw.value() > 1) {
      return Error(ErrorCode::corrupt_store,
                   "canonical boolean has a value other than 0 or 1");
    }
    return raw.value() == 1;
  }

  [[nodiscard]] Result<Digest> digest() {
    if (remaining() < Digest::kBytes) {
      return truncated();
    }
    auto value = Digest::from_bytes(data_ + offset_, Digest::kBytes);
    offset_ += Digest::kBytes;
    return value;
  }

  [[nodiscard]] Result<std::string> text(std::size_t max_bytes) {
    auto length = u32();
    if (!length.has_value()) {
      return length.error();
    }
    const std::uint64_t declared = length.value();
    if (declared > max_bytes) {
      return Error(ErrorCode::limit_exceeded,
                   "declared text length exceeds the configured bound");
    }
    if (declared > remaining()) {
      return truncated();
    }
    std::string value(reinterpret_cast<const char*>(data_ + offset_),
                      static_cast<std::size_t>(declared));
    offset_ += static_cast<std::size_t>(declared);
    return value;
  }

  [[nodiscard]] Result<Bytes> bytes(std::size_t max_bytes) {
    auto length = u32();
    if (!length.has_value()) {
      return length.error();
    }
    const std::uint64_t declared = length.value();
    if (declared > max_bytes) {
      return Error(ErrorCode::limit_exceeded,
                   "declared byte string length exceeds the configured bound");
    }
    if (declared > remaining()) {
      return truncated();
    }
    Bytes value(data_ + offset_, data_ + offset_ + static_cast<std::size_t>(declared));
    offset_ += static_cast<std::size_t>(declared);
    return value;
  }

  [[nodiscard]] Status skip(std::size_t count) {
    if (count > remaining()) {
      return Status::failure(ErrorCode::corrupt_store,
                             "canonical skip past end of input");
    }
    offset_ += count;
    return Status::success();
  }

  [[nodiscard]] std::size_t remaining() const noexcept { return size_ - offset_; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }
  [[nodiscard]] bool at_end() const noexcept { return offset_ == size_; }

  // Every decoder ends with this: trailing bytes are a format violation, never
  // silently ignored, because silently ignoring them is how two different byte
  // strings become "the same" state.
  [[nodiscard]] Status expect_end() const {
    if (!at_end()) {
      return Status::failure(ErrorCode::corrupt_store,
                             "canonical payload has trailing bytes");
    }
    return Status::success();
  }

 private:
  [[nodiscard]] Error truncated() const {
    return Error(ErrorCode::corrupt_store,
                 "canonical payload is truncated");
  }

  const std::uint8_t* data_ = nullptr;
  std::size_t size_ = 0;
  std::size_t offset_ = 0;
};

}  // namespace power_control_plane
