// Proof obligations: the command line tool exercises real library behaviour rather
// than reimplementing it, and there is no CLI path that bypasses the engine.
//
// Every assertion drives the installed tool as an independent process and checks the
// documented exit codes: 0 accepted or replayed, 2 refused by the control plane,
// 1 usage or input error.

#include <filesystem>
#include <string>
#include <vector>

#include "support/fixture.hpp"
#include "support/proc.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

std::string cli_path() { return pcp_test::cli_executable(); }

std::string evidence_spec() {
  // source:kind:generation:revision:epoch:incarnation:digest
  return "power-topology:power_topology:12:4:3:"
         "0123456789abcdeffedcba9876543210:"
         "1111111111111111111111111111111111111111111111111111111111111111";
}

}  // namespace

PCP_TEST(cli_reports_version_and_usage) {
  PCP_CHECK(!cli_path().empty());
  auto version = run_process(cli_path(), {"version"}, scratch_directory("cli-version"));
  PCP_CHECK(version.has_value());
  PCP_CHECK_EQ(version.value().exit_code, 0);
  context.note("version output: " + version.value().output);
  PCP_CHECK(version.value().output.find("power control plane 1.0.0") != std::string::npos);
  PCP_CHECK(version.value().output.find("store format version: 1") != std::string::npos);

  auto unknown = run_process(cli_path(), {"not-a-verb"}, scratch_directory("cli-unknown"));
  PCP_CHECK(unknown.has_value());
  PCP_CHECK_EQ(unknown.value().exit_code, 1);
}

PCP_TEST(cli_lifecycle_uses_the_same_engine) {
  const std::string working = scratch_directory("cli-lifecycle");
  const std::string store = (std::filesystem::path(working) / "store").string();

  auto init = run_process(cli_path(),
                          {"--store", store, "init", "--facility", "dc1",
                           "--evidence", evidence_spec()},
                          working);
  PCP_CHECK(init.has_value());
  PCP_CHECK_MSG(init.value().exit_code == 0, init.value().output);
  PCP_CHECK(init.value().output.find("outcome=accepted") != std::string::npos);

  auto state = run_process(cli_path(), {"--store", store, "state"}, working);
  PCP_CHECK(state.has_value());
  PCP_CHECK_EQ(state.value().exit_code, 0);
  context.note("state output: " + state.value().output);
  PCP_CHECK(state.value().output.find("facility: dc1") != std::string::npos);
  PCP_CHECK(state.value().output.find("operating mode: normal") != std::string::npos);
  PCP_CHECK(state.value().output.find("evidence fresh in this incarnation: no") !=
            std::string::npos);

  // An action before revalidation is refused with the stale-evidence outcome and the
  // refusal exit code, which is only reachable through the engine.
  auto early = run_process(cli_path(),
                           {"--store", store, "attempt", "--action", "open-a", "--kind",
                            "open_breaker", "--target", "bus-a"},
                           working);
  PCP_CHECK(early.has_value());
  PCP_CHECK_EQ(early.value().exit_code, 2);
  PCP_CHECK(early.value().output.find("outcome=stale_evidence") != std::string::npos);

  auto revalidate = run_process(cli_path(),
                                {"--store", store, "revalidate", "--evidence",
                                 evidence_spec()},
                                working);
  PCP_CHECK(revalidate.has_value());
  PCP_CHECK_EQ(revalidate.value().exit_code, 0);

  auto policy = run_process(
      cli_path(),
      {"--store", store, "policy", "set", "--rule",
       "10|allow|kind|open_breaker|breaker opening is authorized", "--rule",
       "20|allow|kind|close_breaker|breaker closing is authorized"},
      working);
  PCP_CHECK(policy.has_value());
  PCP_CHECK_MSG(policy.value().exit_code == 0, policy.value().output);

  auto evaluation = run_process(
      cli_path(),
      {"--store", store, "evaluate", "--evidence", evidence_spec(), "--action", "open-a",
       "--kind", "open_breaker", "--target", "bus-a"},
      working);
  PCP_CHECK(evaluation.has_value());
  PCP_CHECK_MSG(evaluation.value().exit_code == 2, evaluation.value().output);
  // Without a permission the engine refuses; the CLI cannot bypass that stage.
  PCP_CHECK(evaluation.value().output.find("outcome=unauthorized") != std::string::npos);
  PCP_CHECK(evaluation.value().output.find("permission_missing") != std::string::npos);

  auto grant = run_process(cli_path(),
                           {"--store", store, "permissions", "grant", "--kind",
                            "open_breaker", "--target", "bus-a", "--uses", "2"},
                           working);
  PCP_CHECK(grant.has_value());
  PCP_CHECK_MSG(grant.value().exit_code == 0, grant.value().output);

  auto attempt = run_process(cli_path(),
                             {"--store", store, "attempt", "--evidence", evidence_spec(),
                              "--action", "open-a", "--kind", "open_breaker", "--target",
                              "bus-a"},
                             working);
  PCP_CHECK(attempt.has_value());
  PCP_CHECK_MSG(attempt.value().exit_code == 0, attempt.value().output);
  context.note("attempt output: " + attempt.value().output);
  PCP_CHECK(attempt.value().output.find("outcome=accepted") != std::string::npos);
  PCP_CHECK(attempt.value().output.find("acknowledged=yes") != std::string::npos);
  PCP_CHECK(attempt.value().output.find("verified=yes") != std::string::npos);
  PCP_CHECK(attempt.value().output.find("SYNTHETIC") != std::string::npos);

  // Repeating the exact same command replays the committed result.
  // The retry asserts the same evidence and reuses the derived idempotency key, which
  // is exactly the lost-response retry the library is designed to answer.
  auto replay = run_process(cli_path(),
                            {"--store", store, "attempt", "--evidence", evidence_spec(),
                             "--action", "open-a", "--kind", "open_breaker", "--target",
                             "bus-a"},
                            working);
  PCP_CHECK(replay.has_value());
  PCP_CHECK_EQ(replay.value().exit_code, 0);
  PCP_CHECK(replay.value().output.find("outcome=replayed") != std::string::npos);

  auto verify = run_process(cli_path(), {"--store", store, "verify", "--replay"}, working);
  PCP_CHECK(verify.has_value());
  PCP_CHECK_EQ(verify.value().exit_code, 0);
  context.note("verify output: " + verify.value().output);
  PCP_CHECK(verify.value().output.find("integrity ok: yes") != std::string::npos);
  PCP_CHECK(verify.value().output.find("deterministic replay ok: yes") != std::string::npos);

  auto store_report = run_process(cli_path(), {"--store", store, "store"}, working);
  PCP_CHECK(store_report.has_value());
  PCP_CHECK_EQ(store_report.value().exit_code, 0);
  PCP_CHECK(store_report.value().output.find("head present: yes") != std::string::npos);
}

PCP_TEST(cli_refuses_to_mutate_in_read_only_mode) {
  const std::string working = scratch_directory("cli-read-only");
  const std::string store = (std::filesystem::path(working) / "store").string();
  auto init = run_process(cli_path(),
                          {"--store", store, "init", "--facility", "dc1", "--evidence",
                           evidence_spec()},
                          working);
  PCP_CHECK(init.has_value());
  PCP_CHECK_EQ(init.value().exit_code, 0);

  auto refused = run_process(cli_path(),
                             {"--store", store, "--read-only", "policy", "set", "--rule",
                              "1|allow|always||permissive"},
                             working);
  PCP_CHECK(refused.has_value());
  PCP_CHECK_EQ(refused.value().exit_code, 1);
  context.note("read-only refusal: " + refused.value().output);

  // Reading is still allowed in read-only mode.
  auto state = run_process(cli_path(), {"--store", store, "--read-only", "state"}, working);
  PCP_CHECK(state.has_value());
  PCP_CHECK_EQ(state.value().exit_code, 0);
}

PCP_TEST(cli_interlock_is_visible_and_blocks_the_matching_action) {
  const std::string working = scratch_directory("cli-interlock");
  const std::string store = (std::filesystem::path(working) / "store").string();
  PCP_CHECK(run_process(cli_path(),
                        {"--store", store, "init", "--facility", "dc1", "--evidence",
                         evidence_spec()},
                        working)
                .value()
                .exit_code == 0);
  PCP_CHECK(run_process(cli_path(),
                        {"--store", store, "revalidate", "--evidence", evidence_spec()},
                        working)
                .value()
                .exit_code == 0);
  PCP_CHECK(run_process(cli_path(),
                        {"--store", store, "policy", "set", "--rule",
                         "1|allow|kind|close_breaker|permissive for this test"},
                        working)
                .value()
                .exit_code == 0);
  PCP_CHECK(run_process(cli_path(),
                        {"--store", store, "permissions", "grant", "--kind",
                         "close_breaker", "--target", "bus-b", "--uses", "1"},
                        working)
                .value()
                .exit_code == 0);

  auto interlock = run_process(cli_path(),
                               {"--store", store, "interlocks", "set", "arc-flash",
                                "--source", "safety-system", "--severity", "critical",
                                "--state", "engaged", "--kind", "close_breaker", "--target",
                                "bus-b", "--explain", "arc flash hazard"},
                               working);
  PCP_CHECK(interlock.has_value());
  PCP_CHECK_MSG(interlock.value().exit_code == 0, interlock.value().output);

  auto listing = run_process(cli_path(), {"--store", store, "interlocks"}, working);
  PCP_CHECK(listing.has_value());
  PCP_CHECK_EQ(listing.value().exit_code, 0);
  context.note("interlock listing: " + listing.value().output);
  PCP_CHECK(listing.value().output.find("arc-flash") != std::string::npos);
  PCP_CHECK(listing.value().output.find("state=engaged") != std::string::npos);

  auto blocked = run_process(cli_path(),
                             {"--store", store, "evaluate", "--evidence", evidence_spec(),
                              "--action", "close-b", "--kind", "close_breaker", "--target",
                              "bus-b"},
                             working);
  PCP_CHECK(blocked.has_value());
  PCP_CHECK_EQ(blocked.value().exit_code, 2);
  PCP_CHECK(blocked.value().output.find("outcome=blocked_by_interlock") != std::string::npos);
  PCP_CHECK(blocked.value().output.find("arc-flash") != std::string::npos);
}

PCP_TEST(cli_rejects_malformed_input_with_a_usage_exit) {
  const std::string working = scratch_directory("cli-bad-input");
  const std::string store = (std::filesystem::path(working) / "store").string();
  auto missing_facility = run_process(cli_path(), {"--store", store, "init"}, working);
  PCP_CHECK(missing_facility.has_value());
  PCP_CHECK_EQ(missing_facility.value().exit_code, 1);

  auto bad_evidence = run_process(cli_path(),
                                  {"--store", store, "init", "--facility", "dc1",
                                   "--evidence", "not-a-spec"},
                                  working);
  PCP_CHECK(bad_evidence.has_value());
  PCP_CHECK_EQ(bad_evidence.value().exit_code, 1);

  auto missing_store = run_process(cli_path(), {"state"}, working);
  PCP_CHECK(missing_store.has_value());
  PCP_CHECK_EQ(missing_store.value().exit_code, 1);

  auto bad_mode = run_process(cli_path(),
                              {"--store", store, "init", "--facility", "dc1", "--mode",
                               "sideways"},
                              working);
  PCP_CHECK(bad_mode.has_value());
  PCP_CHECK_EQ(bad_mode.value().exit_code, 1);
}

PCP_TEST_MAIN("test_cli")
