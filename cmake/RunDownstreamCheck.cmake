# Configures, builds, and runs the out-of-tree downstream consumer against an
# installed Power Control Plane package. Invoked by CTest when
# POWER_CONTROL_PLANE_DOWNSTREAM_PREFIX is set, and by the release verification
# steps.
#
# A nested CMake project needs a usable C++ toolchain in this process environment.
# On Windows with MSVC that environment is produced by vcvars64.bat, so this script
# locates it through vswhere (never through a hard-coded path) and runs the nested
# commands through it. When no toolchain can be reached the check fails with the
# exact reason rather than reporting a pass it did not earn.

foreach(required PCP_SOURCE_DIR PCP_BINARY_DIR PCP_PREFIX)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "RunDownstreamCheck.cmake requires -D${required}=...")
  endif()
endforeach()

set(pcp_vcvars "")
if(WIN32)
  set(pcp_program_files_x86 "$ENV{ProgramFiles\(x86\)}")
  set(pcp_vswhere "${pcp_program_files_x86}/Microsoft Visual Studio/Installer/vswhere.exe")
  if(EXISTS "${pcp_vswhere}")
    execute_process(COMMAND "${pcp_vswhere}" -latest -products * -requires
                            Microsoft.VisualStudio.Component.VC.Tools.x86.x64
                            -property installationPath
                    OUTPUT_VARIABLE pcp_vs_path
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET)
    if(NOT pcp_vs_path STREQUAL "")
      set(pcp_vcvars "${pcp_vs_path}/VC/Auxiliary/Build/vcvars64.bat")
    endif()
  endif()
endif()

# Runs one nested command, entering the MSVC developer environment first when one
# was found. The environment is entered through a generated batch file rather than
# through cmd /c "call ... && ...", because nesting quotes inside an outer quoted
# command line is not reliable.
set(pcp_run_serial 0)
function(pcp_run description)
  math(EXPR pcp_run_serial "${pcp_run_serial} + 1")
  if(WIN32 AND NOT pcp_vcvars STREQUAL "" AND EXISTS "${pcp_vcvars}")
    set(pcp_batch "${PCP_BINARY_DIR}/pcp-run-${pcp_run_serial}.bat")
    set(pcp_script "@echo off\r\ncall \"${pcp_vcvars}\" >nul 2>&1\r\n")
    foreach(argument IN LISTS ARGN)
      set(pcp_script "${pcp_script}\"${argument}\" ")
    endforeach()
    set(pcp_script "${pcp_script}\r\nexit /b %ERRORLEVEL%\r\n")
    file(WRITE "${pcp_batch}" "${pcp_script}")
    execute_process(COMMAND cmd /c "${pcp_batch}"
      RESULT_VARIABLE pcp_result
      OUTPUT_VARIABLE pcp_output
      ERROR_VARIABLE pcp_output)
  else()
    execute_process(COMMAND ${ARGN}
      RESULT_VARIABLE pcp_result
      OUTPUT_VARIABLE pcp_output
      ERROR_VARIABLE pcp_output)
  endif()

  if(NOT pcp_result EQUAL 0)
    if(pcp_output MATCHES "No CMAKE_CXX_COMPILER could be found" OR
       pcp_output MATCHES "CMAKE_CXX_COMPILER not set")
      message(FATAL_ERROR
              "${description} could not run because no C++ compiler is reachable from this "
              "environment. Run the suite from a developer environment (for MSVC, after "
              "vcvars64.bat) to execute the installed-package check for real.\n${pcp_output}")
    endif()
    if(pcp_output MATCHES "Could not find a package configuration file provided by \"PowerControlPlane\"")
      message(FATAL_ERROR
              "${description} failed because no Power Control Plane package was found under "
              "'${PCP_PREFIX}'. Install the project into that prefix first, for example "
              "'cmake --install <build-dir> --prefix ${PCP_PREFIX}'.\n${pcp_output}")
    endif()
    message(FATAL_ERROR "${description} failed with exit ${pcp_result}:\n${pcp_output}")
  endif()
  set(pcp_last_output "${pcp_output}" PARENT_SCOPE)
endfunction()

file(REMOVE_RECURSE "${PCP_BINARY_DIR}")
file(MAKE_DIRECTORY "${PCP_BINARY_DIR}")
file(REMOVE_RECURSE "${PCP_BINARY_DIR}-store")

set(configure_command "${CMAKE_COMMAND}"
  -S "${PCP_SOURCE_DIR}/downstream/consumer"
  -B "${PCP_BINARY_DIR}"
  "-DCMAKE_PREFIX_PATH=${PCP_PREFIX}")
if(DEFINED PCP_GENERATOR AND NOT PCP_GENERATOR STREQUAL "")
  list(APPEND configure_command -G "${PCP_GENERATOR}")
endif()
if(DEFINED PCP_CONFIG AND NOT PCP_CONFIG STREQUAL "")
  list(APPEND configure_command "-DCMAKE_BUILD_TYPE=${PCP_CONFIG}")
endif()

pcp_run("downstream configure" ${configure_command})
pcp_run("downstream build" "${CMAKE_COMMAND}" --build "${PCP_BINARY_DIR}")
pcp_run("downstream run" "${CMAKE_COMMAND}" --build "${PCP_BINARY_DIR}" --target run_consumer)

message(STATUS "downstream consumer output:\n${pcp_last_output}")
