#pragma once

// Shared canonical-encoding helpers.
//
// Every decoder validates a declared count or length against an explicit bound
// before allocating, and refuses unknown enumerator ordinals rather than mapping
// them onto a default. A malformed payload therefore produces an error, never a
// partially interpreted value.

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "power_control_plane/canonical.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/limits.hpp"

namespace power_control_plane::detail {

[[nodiscard]] inline Status write_text(CanonicalWriter& writer, std::string_view value,
                                       std::size_t max_bytes) {
  return writer.text(value, max_bytes);
}

[[nodiscard]] inline Result<std::string> read_text(CanonicalReader& reader,
                                                   std::size_t max_bytes) {
  return reader.text(max_bytes);
}

[[nodiscard]] inline Status check_count(std::size_t count, std::size_t max_count,
                                        std::string_view what) {
  if (count > max_count) {
    std::string message = "declared ";
    message.append(what);
    message.append(" count exceeds the configured bound");
    return Status::failure(ErrorCode::limit_exceeded, std::move(message));
  }
  return Status::success();
}

template <class Enum>
[[nodiscard]] inline Status write_enum(CanonicalWriter& writer, Enum value) {
  writer.u8(static_cast<std::uint8_t>(value));
  return Status::success();
}

template <class Enum>
[[nodiscard]] inline Result<Enum> read_enum(CanonicalReader& reader, std::uint8_t max_ordinal,
                                            std::string_view what) {
  auto raw = reader.u8();
  if (!raw.has_value()) {
    return raw.error();
  }
  if (raw.value() == 0 || raw.value() > max_ordinal) {
    std::string message = "canonical payload carries an out-of-range ";
    message.append(what);
    message.append(" ordinal");
    return Error(ErrorCode::corrupt_store, std::move(message));
  }
  return static_cast<Enum>(raw.value());
}

template <class T, class EncodeFn>
[[nodiscard]] inline Status write_list(CanonicalWriter& writer, const std::vector<T>& items,
                                       std::size_t max_count, EncodeFn&& encode) {
  PCP_TRY_STATUS(check_count(items.size(), max_count, "list"));
  if (items.size() > 0xFFFFFFFFull) {
    return Status::failure(ErrorCode::limit_exceeded, "list length does not fit a 32-bit prefix");
  }
  writer.u32(static_cast<std::uint32_t>(items.size()));
  for (const T& item : items) {
    PCP_TRY_STATUS(encode(writer, item));
  }
  return Status::success();
}

template <class T, class DecodeFn>
[[nodiscard]] inline Result<std::vector<T>> read_list(CanonicalReader& reader,
                                                      std::size_t max_count,
                                                      std::string_view what,
                                                      DecodeFn&& decode) {
  auto count = reader.u32();
  if (!count.has_value()) {
    return count.error();
  }
  if (count.value() > max_count) {
    std::string message = "declared ";
    message.append(what);
    message.append(" count exceeds the configured bound");
    return Error(ErrorCode::limit_exceeded, std::move(message));
  }
  std::vector<T> items;
  items.reserve(count.value());
  for (std::uint32_t index = 0; index < count.value(); ++index) {
    auto item = decode(reader);
    if (!item.has_value()) {
      return item.error();
    }
    items.push_back(std::move(item).value());
  }
  return items;
}

// Sorted, duplicate-free insertion used by every collection with a canonical
// order. Returns true when the value replaced an existing entry.
template <class T, class KeyFn, class LessFn>
[[nodiscard]] inline bool sorted_upsert(std::vector<T>& items, T value, KeyFn key,
                                        LessFn less) {
  const auto position = std::lower_bound(items.begin(), items.end(), key(value), less);
  if (position != items.end() && key(*position) == key(value)) {
    *position = std::move(value);
    return true;
  }
  items.insert(position, std::move(value));
  return false;
}

template <class T, class Key, class KeyFn, class LessFn>
[[nodiscard]] inline bool sorted_erase(std::vector<T>& items, const Key& key_value, KeyFn key,
                                       LessFn less) {
  const auto position = std::lower_bound(
      items.begin(), items.end(), key_value,
      [&key, &less](const T& item, const Key& probe) { return less(key(item), probe); });
  if (position == items.end() || less(key_value, key(*position))) {
    return false;
  }
  items.erase(position);
  return true;
}

}  // namespace power_control_plane::detail
