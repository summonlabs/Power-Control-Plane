#pragma once

// Independent-process execution for the multiprocess tests.
//
// A child process is started through the host command interpreter with its output
// redirected to a file. Using the interpreter avoids pipe plumbing entirely, which
// keeps the helper portable and keeps a test from depending on the parent's stdio
// buffering. The exit status is normalised so a test never has to know whether the
// platform reports a raw exit code or a wait status.

#include <cstdint>
#include <string>
#include <vector>

#include "power_control_plane/error.hpp"

namespace pcp_test {

struct ProcessOutcome {
  int exit_code = -1;
  std::string output;
};

[[nodiscard]] power_control_plane::Result<ProcessOutcome> run_process(
    const std::string& executable, const std::vector<std::string>& arguments,
    const std::string& working_directory);

[[nodiscard]] std::string probe_executable();
[[nodiscard]] std::string cli_executable();

}  // namespace pcp_test
