#pragma once

// Path handling for the durable store.
//
// Trust model: the store root is chosen by the operator and is trusted to be a
// real directory. Everything below it is store-owned and is created and named by
// the library. The checks here exist to make sure a name derived from persisted
// content, from an operator, or from a CLI argument can never escape the store
// root, can never be substituted by a symlink, junction, or other reparse point,
// and can never name a Windows reserved device.
//
// Checks run before normalization where normalization could erase evidence of an
// attack: a name containing a traversal segment is rejected outright rather than
// normalized away.

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/error.hpp"
#include "power_control_plane/limits.hpp"

namespace power_control_plane::detail {

[[nodiscard]] bool is_path_separator(char character) noexcept;

// Validates one path component that the library is about to use as a file or
// directory name inside the store root.
[[nodiscard]] Status validate_child_name(std::string_view name);

// Validates and normalizes an absolute store root path.
[[nodiscard]] Result<std::string> normalize_root_path(std::string_view input,
                                                      const Limits& limits);

[[nodiscard]] std::string join_path(std::string_view parent, std::string_view child);

[[nodiscard]] bool path_exists(const std::string& path);
[[nodiscard]] bool is_directory(const std::string& path);
[[nodiscard]] bool is_reparse_point(const std::string& path);

// Refuses when the path exists and is a symlink, junction, or other reparse
// point, or when it exists as a directory where a file is required.
[[nodiscard]] Status reject_substitution(const std::string& path);
[[nodiscard]] Status reject_directory(const std::string& path);

[[nodiscard]] Status ensure_directory(const std::string& path);
[[nodiscard]] Status remove_file_if_present(const std::string& path);

// Directory entries (names only), sorted for determinism. Never recursive.
[[nodiscard]] Result<std::vector<std::string>> list_directory(const std::string& path,
                                                              const Limits& limits);

}  // namespace power_control_plane::detail
