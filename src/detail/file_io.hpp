#pragma once

// Narrow file primitives for the durable store.
//
// Reads are bounded before allocation: the size is checked against an explicit
// maximum and the file is refused when it is larger, so a hostile or truncated
// file can never drive an unbounded allocation. Writes are explicitly flushed to
// durable storage (FlushFileBuffers on Windows, fsync on POSIX) before the call
// returns, because the publication protocol depends on ordered durability.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "power_control_plane/canonical.hpp"
#include "power_control_plane/error.hpp"

namespace power_control_plane::detail {

// Result of a bounded read. The returned byte buffer excludes anything past
// max_bytes; an oversized file is refused rather than truncated.
[[nodiscard]] Result<Bytes> read_file_bounded(const std::string& path,
                                              std::size_t max_bytes);

// Creates or truncates the file and writes the whole buffer durably.
[[nodiscard]] Status write_file_durable(const std::string& path,
                                        const std::uint8_t* data, std::size_t size);

// Same, but refuses when the file already exists (used for staging files so a
// half-written residue is never silently reused).
[[nodiscard]] Status write_new_file_durable(const std::string& path,
                                            const std::uint8_t* data, std::size_t size);

// Atomically replaces destination with source. Both must be on the same volume.
[[nodiscard]] Status replace_file_atomic(const std::string& source,
                                         const std::string& destination);

// Flushes directory metadata so a rename survives a crash.
[[nodiscard]] Status flush_directory(const std::string& path);

[[nodiscard]] Status remove_file(const std::string& path);
[[nodiscard]] Status remove_directory_if_empty(const std::string& path);

}  // namespace power_control_plane::detail
