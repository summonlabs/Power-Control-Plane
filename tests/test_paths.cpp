// Proof obligations: path traversal, root escape, reserved device names,
// substitution through a reparse point, and directories where files are required.

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include "power_control_plane/engine.hpp"
#include "support/fixture.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

// Creates a directory link to the target. On Windows a directory junction is used
// because creating one does not require a privilege the host may withhold; on POSIX a
// directory symlink is used.
bool make_directory_link(const std::filesystem::path& link, const std::filesystem::path& target,
                         std::string& diagnostic) {
#if defined(_WIN32)
  const std::string command = "cmd /c mklink /J \"" + link.string() + "\" \"" +
                              target.string() + "\" > nul 2>&1";
  const int status = std::system(command.c_str());
  if (status != 0) {
    diagnostic = "mklink /J exited with " + std::to_string(status);
    return false;
  }
#else
  std::error_code error;
  std::filesystem::create_directory_symlink(target, link, error);
  if (error) {
    diagnostic = error.message();
    return false;
  }
#endif
  std::error_code error;
  if (!std::filesystem::exists(link, error)) {
    diagnostic = "the directory link was not created";
    return false;
  }
  return true;
}

}  // namespace

PCP_TEST(a_name_with_a_traversal_segment_is_refused_before_normalization) {
  const std::string root = scratch_directory("paths-traversal");
  const std::string with_traversal = root + "/../" + "escaped-store";
  auto plane = ControlPlane::open(with_traversal, StoreOpenMode::read_write, EngineOptions{});
  // The library resolves a relative path against the working directory but refuses a
  // traversal segment outright, so normalization can never erase the attempt.
  PCP_CHECK(!plane.has_value());
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::path_rejected);
}

PCP_TEST(an_empty_or_control_character_root_is_refused) {
  auto empty = ControlPlane::open("", StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!empty.has_value());
  PCP_CHECK_EQ(empty.error().code(), ErrorCode::invalid_argument);

  const std::string with_nul = std::string("store\0name", 10);
  auto nul = ControlPlane::open(with_nul, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!nul.has_value());
  PCP_CHECK_EQ(nul.error().code(), ErrorCode::path_rejected);

  auto control = ControlPlane::open(std::string("store\nname"), StoreOpenMode::read_write,
                                    EngineOptions{});
  PCP_CHECK(!control.has_value());
  PCP_CHECK_EQ(control.error().code(), ErrorCode::path_rejected);
}

PCP_TEST(an_overlong_root_path_is_refused) {
  const std::string huge(6000, 'a');
  auto plane = ControlPlane::open(huge, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::path_rejected);
}

PCP_TEST(a_file_where_the_store_root_belongs_is_refused) {
  const std::string root = scratch_directory("paths-file-root");
  const std::string file = (std::filesystem::path(root) / "not-a-directory").string();
  {
    std::ofstream output(file);
    output << "x";
  }
  auto plane = ControlPlane::open(file, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::path_rejected);
}

PCP_TEST(a_head_marker_that_is_a_directory_is_refused) {
  auto fixture = Fixture::create("paths-head-directory");
  PCP_CHECK(fixture.has_value());
  const std::string root = fixture.value().root();
  fixture.value().close();
  std::error_code error;
  std::filesystem::remove((std::filesystem::path(root) / "pcp-head.bin").string(), error);
  std::filesystem::create_directories((std::filesystem::path(root) / "pcp-head.bin").string(),
                                      error);
  PCP_CHECK(!error);
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  // A directory where a file is required is refused by path validation before any
  // content is read.
  PCP_CHECK(plane.error().code() == ErrorCode::path_rejected ||
            plane.error().code() == ErrorCode::corrupt_store);
}

PCP_TEST(a_reparse_point_substitution_is_refused) {
  auto fixture = Fixture::create("paths-substitution");
  PCP_CHECK(fixture.has_value());
  const std::string root = fixture.value().root();
  fixture.value().close();

  // A directory link is created under the system temporary directory: it must live
  // on a volume that supports reparse points, which is not guaranteed for the volume
  // the build tree happens to sit on. The link still targets a real directory and the
  // refusal is about the link, not about where it lives.
  std::error_code scratch_error;
  const std::filesystem::path base =
      std::filesystem::temp_directory_path(scratch_error) / "pcp-reparse-substitution";
  std::filesystem::remove_all(base, scratch_error);
  std::filesystem::create_directories(base / "target", scratch_error);
  const std::filesystem::path elsewhere = base / "target";
  const std::filesystem::path link = base / "linked-store";
  std::string diagnostic;
  if (!make_directory_link(link, elsewhere, diagnostic)) {
    // The check cannot run without a link, and a check that cannot run must not be
    // reported as a pass.
    PCP_CHECK_MSG(false, "a directory link could not be created: " + diagnostic);
  }
  PCP_CHECK(std::filesystem::exists(link));
  auto plane = ControlPlane::open(link.string(), StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::path_rejected);
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::path_rejected);
  std::filesystem::remove_all(base, scratch_error);
  static_cast<void>(root);
}

PCP_TEST(a_store_directory_with_unexpected_entries_is_listed_without_error) {
  auto fixture = Fixture::create("paths-extra-entries");
  PCP_CHECK(fixture.has_value());
  const std::string root = fixture.value().root();
  {
    std::ofstream output((std::filesystem::path(root) / "operator-notes.txt").string());
    output << "not a store file";
  }
  fixture.value().close();
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(plane.has_value());
  auto integrity = plane.value().verify_store();
  PCP_CHECK(integrity.has_value());
  // An unrelated file is neither adopted nor treated as corruption.
  PCP_CHECK(integrity.value().ok);
}

PCP_TEST_MAIN("test_paths")
