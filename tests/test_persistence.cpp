// Proof obligations: versioned integrity-checked persistence, whole-state recovery,
// and strict rejection of malformed, truncated, oversized, or substituted input.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "power_control_plane/store.hpp"
#include "support/fixture.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

std::string path_of(const std::string& root, std::string_view name) {
  return (std::filesystem::path(root) / std::string(name)).string();
}

Bytes read_all(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  Bytes bytes;
  char buffer[4096];
  while (input.read(buffer, sizeof(buffer)) || input.gcount() > 0) {
    bytes.insert(bytes.end(), buffer, buffer + input.gcount());
  }
  return bytes;
}

void write_all(const std::string& path, const Bytes& bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
}

// Builds a store with several committed publications and returns its root.
std::string build_store(const std::string& name, std::size_t publications) {
  auto fixture = Fixture::create(name);
  if (!fixture.has_value()) {
    return {};
  }
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 64);
  if (!granted.has_value()) {
    return {};
  }
  for (std::size_t index = 0; index < publications; ++index) {
    auto intent = fixture.value().intent("open-" + std::to_string(index),
                                         ActionKind::open_breaker, "bus-a");
    auto decision = fixture.value().authorize(intent.value(),
                                              "persistence/" + std::to_string(index));
    if (!decision.has_value() || !decision_committed(decision.value().outcome)) {
      return {};
    }
  }
  const std::string root = fixture.value().root();
  fixture.value().close();
  return root;
}

}  // namespace

PCP_TEST(a_closed_store_reopens_with_the_same_authoritative_state) {
  const std::string root = build_store("persistence-reopen", 4);
  PCP_CHECK(!root.empty());
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(plane.has_value());
  PCP_CHECK(plane.value().store().open_report().recovered);
  auto status = plane.value().status();
  PCP_CHECK(status.has_value());
  PCP_CHECK(status.value().head.present);
  // bootstrap, policy rebind, revalidation, permission grant, and four authorizations.
  PCP_CHECK_EQ(status.value().revision.value(), std::uint64_t{8});
  auto integrity = plane.value().verify_store();
  PCP_CHECK(integrity.has_value());
  PCP_CHECK(integrity.value().ok);
  PCP_CHECK(integrity.value().orphan_generation_files.empty());
  PCP_CHECK(integrity.value().staging_residue.empty());
  PCP_CHECK(integrity.value().head_matches_payload);
}

PCP_TEST(a_corrupted_head_marker_is_refused) {
  const std::string root = build_store("persistence-corrupt-head", 2);
  PCP_CHECK(!root.empty());
  const std::string head_path = path_of(root, "pcp-head.bin");
  Bytes head = read_all(head_path);
  PCP_CHECK(!head.empty());
  head[40] ^= 0x01;  // flip a bit inside the record body
  write_all(head_path, head);
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::corrupt_store);
}

PCP_TEST(a_truncated_head_marker_is_refused) {
  const std::string root = build_store("persistence-truncated-head", 2);
  PCP_CHECK(!root.empty());
  const std::string head_path = path_of(root, "pcp-head.bin");
  const Bytes head = read_all(head_path);
  write_all(head_path, Bytes(head.begin(), head.begin() + 64));
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::corrupt_store);
}

PCP_TEST(an_oversized_head_marker_is_refused_without_being_read) {
  const std::string root = build_store("persistence-oversized-head", 2);
  PCP_CHECK(!root.empty());
  const std::string head_path = path_of(root, "pcp-head.bin");
  Bytes head = read_all(head_path);
  head.resize(head.size() + 1024, 0);
  write_all(head_path, head);
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  // The fixed-size record is rejected by length before any field is trusted.
  PCP_CHECK(plane.error().code() == ErrorCode::corrupt_store ||
            plane.error().code() == ErrorCode::limit_exceeded);
}

PCP_TEST(an_unknown_head_magic_is_rejected_as_an_unsupported_format) {
  const std::string root = build_store("persistence-magic", 2);
  PCP_CHECK(!root.empty());
  const std::string head_path = path_of(root, "pcp-head.bin");
  Bytes head = read_all(head_path);
  head[0] = 'X';
  write_all(head_path, head);
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::unsupported_format);
}

PCP_TEST(a_corrupted_generation_file_is_refused) {
  const std::string root = build_store("persistence-corrupt-state", 2);
  PCP_CHECK(!root.empty());
  auto plane = ControlPlane::open(root, StoreOpenMode::read_only, EngineOptions{});
  PCP_CHECK(plane.has_value());
  const std::string file = plane.value().store().head().state_file;
  PCP_CHECK(!file.empty());
  const std::string full = path_of(root, file);
  Bytes bytes = read_all(full);
  PCP_CHECK(bytes.size() > 200);
  bytes[bytes.size() / 2] ^= 0xFF;
  write_all(full, bytes);
  auto reopened = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!reopened.has_value());
  PCP_CHECK_EQ(reopened.error().code(), ErrorCode::corrupt_store);
}

PCP_TEST(a_missing_authority_marker_refuses_the_store) {
  const std::string root = build_store("persistence-missing-authority", 2);
  PCP_CHECK(!root.empty());
  std::error_code error;
  std::filesystem::remove(path_of(root, "pcp-authority.bin"), error);
  PCP_CHECK(!error);
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::corrupt_store);
}

PCP_TEST(a_missing_head_with_published_state_refuses_the_store) {
  const std::string root = build_store("persistence-missing-head", 2);
  PCP_CHECK(!root.empty());
  std::error_code error;
  std::filesystem::remove(path_of(root, "pcp-head.bin"), error);
  PCP_CHECK(!error);
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::corrupt_store);
}

PCP_TEST(staging_residue_is_retired_and_never_adopted) {
  const std::string root = build_store("persistence-staging", 2);
  PCP_CHECK(!root.empty());
  const std::string staging = path_of(root, "staging");
  std::error_code error;
  std::filesystem::create_directories(staging, error);
  write_all(path_of(staging, "state-000000000000000099.bin.tmp"), Bytes(64, 0xAB));
  write_all(path_of(staging, "head.tmp"), Bytes(16, 0xCD));
  auto plane = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(plane.has_value());
  PCP_CHECK_EQ(plane.value().store().open_report().retired_staging_files, std::size_t{2});
  auto integrity = plane.value().verify_store();
  PCP_CHECK(integrity.has_value());
  PCP_CHECK(integrity.value().staging_residue.empty());
  PCP_CHECK(integrity.value().ok);
}

PCP_TEST(an_unreferenced_generation_file_is_retired_and_never_adopted) {
  const std::string root = build_store("persistence-orphan", 2);
  PCP_CHECK(!root.empty());
  auto plane = ControlPlane::open(root, StoreOpenMode::read_only, EngineOptions{});
  PCP_CHECK(plane.has_value());
  const StateRevision head_revision = plane.value().store().head().revision;
  const std::string orphan = state_file_name(StateRevision(head_revision.value() + 5));
  write_all(path_of(root, orphan), read_all(path_of(root, plane.value().store().head().state_file)));
  auto reopened = ControlPlane::open(root, StoreOpenMode::read_write, EngineOptions{});
  PCP_CHECK(reopened.has_value());
  PCP_CHECK_EQ(reopened.value().store().open_report().retired_orphan_states, std::size_t{1});
  PCP_CHECK(reopened.value().store().head().revision == head_revision);
  std::error_code error;
  PCP_CHECK(!std::filesystem::exists(path_of(root, orphan), error));
}

PCP_TEST(state_file_names_are_fixed_width_and_parse_back) {
  PCP_CHECK_EQ(state_file_name(StateRevision(7)), std::string("state-00000000000000000007.bin"));
  auto parsed = parse_state_file_name("state-00000000000000000007.bin");
  PCP_CHECK(parsed.has_value());
  PCP_CHECK_EQ(parsed.value().value(), std::uint64_t{7});
  PCP_CHECK(!parse_state_file_name("state-7.bin").has_value());
  PCP_CHECK(!parse_state_file_name("state-0000000000000000000X.bin").has_value());
  PCP_CHECK(!parse_state_file_name("other-00000000000000000007.bin").has_value());
  PCP_CHECK(!parse_state_file_name("").has_value());
}

PCP_TEST(read_only_open_refuses_to_create_a_store) {
  const std::string root = scratch_directory("persistence-read-only-missing");
  auto plane = ControlPlane::open(root, StoreOpenMode::read_only, EngineOptions{});
  PCP_CHECK(!plane.has_value());
  PCP_CHECK_EQ(plane.error().code(), ErrorCode::not_found);
}

PCP_TEST(retention_bounds_the_number_of_retained_generations) {
  EngineOptions options;
  options.retained_publications = 3;
  auto fixture = Fixture::create("persistence-retention", options);
  PCP_CHECK(fixture.has_value());
  auto granted = fixture.value().grant({ActionKind::open_breaker}, {"bus-a"}, 32);
  PCP_CHECK(granted.has_value());
  for (int index = 0; index < 12; ++index) {
    auto intent = fixture.value().intent("open-" + std::to_string(index),
                                         ActionKind::open_breaker, "bus-a");
    auto decision = fixture.value().authorize(intent.value(),
                                              "persistence-retention/" + std::to_string(index));
    PCP_CHECK(decision.has_value());
    PCP_CHECK_EQ(decision.value().outcome, DecisionOutcome::accepted);
  }
  PCP_CHECK(fixture.value().plane().store().retained_publications().size() <= 3);
  auto integrity = fixture.value().plane().verify_store();
  PCP_CHECK(integrity.has_value());
  PCP_CHECK(integrity.value().ok);
}

PCP_TEST_MAIN("test_persistence")
