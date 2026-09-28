# Examples.
#
# Each example is an ordinary library client built against the exported target. They
# run as CTest cases so that the documented lifecycle is exercised on every build.

function(power_control_plane_add_example name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE power_control_plane)
  target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  power_control_plane_apply_strict_options(${name})
  add_test(NAME ${name} COMMAND ${name} "${CMAKE_CURRENT_BINARY_DIR}/${name}-store")
  set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()

power_control_plane_add_example(pcp_example_lifecycle example_lifecycle.cpp)
power_control_plane_add_example(pcp_example_stale_authority example_stale_authority.cpp)
power_control_plane_add_example(pcp_example_crash_recovery example_crash_recovery.cpp)
power_control_plane_add_example(pcp_example_adapter_simulation example_adapter_simulation.cpp)

# The crash-recovery example re-executes itself. CTest invokes it with an absolute
# binary path, which is what the example passes on to the child process.
