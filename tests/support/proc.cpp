#include "proc.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#ifndef PCP_PROBE_EXECUTABLE
#error "PCP_PROBE_EXECUTABLE must be defined by the build"
#endif

namespace pcp_test {
namespace {

std::string quote(const std::string& text) { return "\"" + text + "\""; }

std::uint64_t next_serial() {
  static std::uint64_t serial = 0;
  return ++serial;
}

}  // namespace

std::string probe_executable() { return std::string(PCP_PROBE_EXECUTABLE); }

std::string cli_executable() {
#if defined(PCP_CLI_EXECUTABLE)
  return std::string(PCP_CLI_EXECUTABLE);
#else
  return std::string();
#endif
}

power_control_plane::Result<ProcessOutcome> run_process(const std::string& executable,
                                   const std::vector<std::string>& arguments,
                                   const std::string& working_directory) {
  std::error_code error;
  std::filesystem::create_directories(working_directory, error);
  const std::filesystem::path capture =
      std::filesystem::path(working_directory) /
      ("proc-" + std::to_string(next_serial()) + ".out");

  // The whole command line is wrapped in an extra pair of quotes. The host command
  // interpreter strips the outermost pair, which is what lets an executable and a
  // working directory containing spaces survive; without the wrapper the interpreter
  // truncates the path at the first space.
  std::string command = "\"";
  command.append(quote(executable));
  for (const std::string& argument : arguments) {
    command.push_back(' ');
    command.append(quote(argument));
  }
  command.append(" > ");
  command.append(quote(capture.string()));
  command.append(" 2>&1\"");

  const int status = std::system(command.c_str());

  ProcessOutcome outcome;
  std::ifstream input(capture, std::ios::binary);
  if (input) {
    std::ostringstream buffer;
    buffer << input.rdbuf();
    outcome.output = buffer.str();
  }
  std::filesystem::remove(capture, error);

#if defined(_WIN32)
  outcome.exit_code = status;
#else
  if (status == -1) {
    outcome.exit_code = -1;
  } else if (WIFEXITED(status)) {
    outcome.exit_code = WEXITSTATUS(status);
  } else {
    outcome.exit_code = 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  }
#endif
  return outcome;
}

}  // namespace pcp_test
