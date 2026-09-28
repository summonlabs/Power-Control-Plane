# Test suite.
#
# The suite is organised by proof obligation, not by source file: each executable
# owns one class of obligation and says so in its header comment.
#
# No test is given a timeout. CTest timeouts, timeout wrappers, and watchdog
# processes are prohibited in this repository: a test that does not finish is a
# defect to diagnose, not to bound.

# The probe is a real program that the multiprocess tests start as an independent
# operating-system process.
add_executable(pcp_probe support/pcp_probe.cpp)
target_link_libraries(pcp_probe PRIVATE power_control_plane)
power_control_plane_apply_strict_options(pcp_probe)

add_library(pcp_test_support STATIC
  support/test_harness.cpp
  support/fixture.cpp
  support/proc.cpp)
target_include_directories(pcp_test_support PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/support")
target_link_libraries(pcp_test_support PUBLIC power_control_plane)
target_compile_definitions(pcp_test_support PUBLIC
  "PCP_PROBE_EXECUTABLE=\"$<TARGET_FILE:pcp_probe>\"")
add_dependencies(pcp_test_support pcp_probe)
power_control_plane_apply_strict_options(pcp_test_support)

if(TARGET pcp_cli)
  target_compile_definitions(pcp_test_support PUBLIC
    "PCP_CLI_EXECUTABLE=\"$<TARGET_FILE:pcp_cli>\"")
  add_dependencies(pcp_test_support pcp_cli)
endif()

function(power_control_plane_add_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE pcp_test_support)
  # Adversarial artifacts are produced with the same encoder and checksum the
  # library uses, so the tests need the internal headers.
  target_include_directories(${name} PRIVATE "${CMAKE_SOURCE_DIR}")
  power_control_plane_apply_strict_options(${name})
  add_test(NAME ${name} COMMAND ${name})
  # Test state is written under the build tree, never into the source tree.
  set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()

# Proof obligations: identity, canonical encoding, and integrity primitives.
power_control_plane_add_test(pcp_test_identity test_identity.cpp)
# Proof obligations: model rules, fail-closed semantics, deterministic precedence.
power_control_plane_add_test(pcp_test_model test_model.cpp)
# Proof obligations: authority fencing, staleness refusal, no effect on refusal.
power_control_plane_add_test(pcp_test_authority test_authority.cpp)
# Proof obligations: idempotent replay and bounded retention metadata.
power_control_plane_add_test(pcp_test_idempotency test_idempotency.cpp)
# Proof obligations: acknowledgement, effect, and verified completion stay distinct.
power_control_plane_add_test(pcp_test_attempts test_attempts.cpp)
# Proof obligations: durable publication, integrity, and malformed-input rejection.
power_control_plane_add_test(pcp_test_persistence test_persistence.cpp)
# Proof obligations: path traversal, substitution, and name-safety rejection.
power_control_plane_add_test(pcp_test_paths test_paths.cpp)
# Proof obligations: whole-state recovery and evidence revalidation.
power_control_plane_add_test(pcp_test_recovery test_recovery.cpp)
# Proof obligations: deterministic replay and rollback fencing.
power_control_plane_add_test(pcp_test_replay test_replay.cpp)
# Proof obligations: concurrency model, snapshot consistency, lock ownership.
power_control_plane_add_test(pcp_test_concurrency test_concurrency.cpp)
# Proof obligations: malformed, contradictory, repeated, and boundary-shaped input.
power_control_plane_add_test(pcp_test_adversarial test_adversarial.cpp)
# Proof obligations: seeded randomized state-machine invariants.
power_control_plane_add_test(pcp_test_property test_property.cpp)
# Proof obligations: real independent processes, writer death, crash injection.
power_control_plane_add_test(pcp_test_multiprocess test_multiprocess.cpp)

if(TARGET pcp_cli)
  power_control_plane_add_test(pcp_test_cli test_cli.cpp)
endif()

# The downstream consumer is configured, built, and run out of tree against an
# installed package. It is enabled by pointing POWER_CONTROL_PLANE_DOWNSTREAM_PREFIX
# at an install prefix produced by this project.
if(POWER_CONTROL_PLANE_DOWNSTREAM_PREFIX)
  add_test(NAME pcp_test_downstream_install
    COMMAND "${CMAKE_COMMAND}"
      -DPCP_SOURCE_DIR=${CMAKE_SOURCE_DIR}
      -DPCP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/downstream
      -DPCP_PREFIX=${POWER_CONTROL_PLANE_DOWNSTREAM_PREFIX}
      -DPCP_GENERATOR=${CMAKE_GENERATOR}
      -DPCP_CONFIG=$$<CONFIG>
      -P "${CMAKE_SOURCE_DIR}/cmake/RunDownstreamCheck.cmake")
  # The check configures a nested CMake project, which needs a usable C++ toolchain.
  # The script locates the MSVC developer environment itself; when none can be
  # reached the check fails with the exact reason rather than passing.
  set_tests_properties(pcp_test_downstream_install PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endif()
