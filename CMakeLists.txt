cmake_minimum_required(VERSION 3.21)

project(PowerControlPlane
  VERSION 1.0.0
  DESCRIPTION "Facility-wide electrical operating state and control authority for the Data Center Control Plane"
  HOMEPAGE_URL "https://github.com/summonlabs/Power-Control-Plane"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(POWER_CONTROL_PLANE_IS_TOP_LEVEL ON)
else()
  set(POWER_CONTROL_PLANE_IS_TOP_LEVEL OFF)
endif()

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(POWER_CONTROL_PLANE_IS_TOP_LEVEL)
  option(POWER_CONTROL_PLANE_BUILD_TESTS "Build the Power Control Plane test suite" ON)
  option(POWER_CONTROL_PLANE_BUILD_EXAMPLES "Build the Power Control Plane examples" ON)
  option(POWER_CONTROL_PLANE_BUILD_BENCHMARKS "Build the Power Control Plane benchmarks" ON)
  option(POWER_CONTROL_PLANE_BUILD_TOOLS "Build the Power Control Plane command line tool" ON)
else()
  option(POWER_CONTROL_PLANE_BUILD_TESTS "Build the Power Control Plane test suite" OFF)
  option(POWER_CONTROL_PLANE_BUILD_EXAMPLES "Build the Power Control Plane examples" OFF)
  option(POWER_CONTROL_PLANE_BUILD_BENCHMARKS "Build the Power Control Plane benchmarks" OFF)
  option(POWER_CONTROL_PLANE_BUILD_TOOLS "Build the Power Control Plane command line tool" OFF)
endif()

option(POWER_CONTROL_PLANE_WARNINGS_AS_ERRORS
  "Treat first-party compiler warnings as errors" ON)
option(POWER_CONTROL_PLANE_ENABLE_ASAN
  "Build with AddressSanitizer where the toolchain supports it" OFF)

set(POWER_CONTROL_PLANE_DOWNSTREAM_PREFIX "" CACHE PATH
  "Install prefix of a previous Power Control Plane installation; enables the downstream consumer test")

# Durable store format version. Independent of the package version: it changes only
# when the persisted byte layout changes.
set(POWER_CONTROL_PLANE_STATE_FORMAT_VERSION 1)

# ---------------------------------------------------------------------------
# First-party compile options
# ---------------------------------------------------------------------------
function(power_control_plane_apply_strict_options target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
    if(POWER_CONTROL_PLANE_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(POWER_CONTROL_PLANE_ENABLE_ASAN)
      target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
      target_link_options(${target} PRIVATE /fsanitize=address /INCREMENTAL:NO)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
      -Wnon-virtual-dtor -Wcast-qual -Wdouble-promotion)
    if(POWER_CONTROL_PLANE_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(POWER_CONTROL_PLANE_ENABLE_ASAN)
      target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Generated version header
# ---------------------------------------------------------------------------
set(POWER_CONTROL_PLANE_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/power_control_plane/version.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/generated/power_control_plane/version.hpp"
  @ONLY)

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
add_library(power_control_plane
  src/error.cpp
  src/digest.cpp
  src/ids.cpp
  src/enums.cpp
  src/model_rules.cpp
  src/codec_model.cpp
  src/facility_state.cpp
  src/state_editor.cpp
  src/transition.cpp
  src/store.cpp
  src/engine.cpp
  src/adapter.cpp
  src/detail/paths.cpp
  src/detail/file_io.cpp
  src/detail/process_lock.cpp)
add_library(PowerControlPlane::power_control_plane ALIAS power_control_plane)

set(POWER_CONTROL_PLANE_PUBLIC_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(POWER_CONTROL_PLANE_BUILD_INCLUDE "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(POWER_CONTROL_PLANE_PRIVATE_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_include_directories(power_control_plane
  PUBLIC
    "$<BUILD_INTERFACE:${POWER_CONTROL_PLANE_PUBLIC_INCLUDE}>"
    "$<BUILD_INTERFACE:${POWER_CONTROL_PLANE_BUILD_INCLUDE}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${POWER_CONTROL_PLANE_PRIVATE_INCLUDE}")

target_compile_features(power_control_plane PUBLIC cxx_std_20)
power_control_plane_apply_strict_options(power_control_plane)

set_target_properties(power_control_plane PROPERTIES
  OUTPUT_NAME "power_control_plane"
  VERSION "${PROJECT_VERSION}"
  SOVERSION "${PROJECT_VERSION_MAJOR}"
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON)

if(BUILD_SHARED_LIBS AND WIN32)
  set_target_properties(power_control_plane PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# ---------------------------------------------------------------------------
# CLI tool
# ---------------------------------------------------------------------------
if(POWER_CONTROL_PLANE_BUILD_TOOLS)
  add_executable(pcp_cli tools/pcp_cli.cpp)
  set_target_properties(pcp_cli PROPERTIES OUTPUT_NAME "pcp")
  target_link_libraries(pcp_cli PRIVATE power_control_plane)
  power_control_plane_apply_strict_options(pcp_cli)
endif()

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------
install(TARGETS power_control_plane
  EXPORT PowerControlPlaneTargets
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

if(POWER_CONTROL_PLANE_BUILD_TOOLS)
  install(TARGETS pcp_cli RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/power_control_plane"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.hpp")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/generated/power_control_plane/version.hpp"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/power_control_plane")

set(POWER_CONTROL_PLANE_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/PowerControlPlane")

install(EXPORT PowerControlPlaneTargets
  NAMESPACE PowerControlPlane::
  FILE PowerControlPlaneTargets.cmake
  DESTINATION "${POWER_CONTROL_PLANE_INSTALL_CMAKEDIR}")

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PowerControlPlaneConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/PowerControlPlaneConfig.cmake"
  INSTALL_DESTINATION "${POWER_CONTROL_PLANE_INSTALL_CMAKEDIR}")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/PowerControlPlaneConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/PowerControlPlaneConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/PowerControlPlaneConfigVersion.cmake"
  DESTINATION "${POWER_CONTROL_PLANE_INSTALL_CMAKEDIR}")

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" "${CMAKE_CURRENT_SOURCE_DIR}/NOTICE"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/PowerControlPlane")

# ---------------------------------------------------------------------------
# Subprojects
# ---------------------------------------------------------------------------
if(POWER_CONTROL_PLANE_IS_TOP_LEVEL AND (POWER_CONTROL_PLANE_BUILD_TESTS OR POWER_CONTROL_PLANE_BUILD_EXAMPLES))
  enable_testing()
endif()

if(POWER_CONTROL_PLANE_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(POWER_CONTROL_PLANE_BUILD_BENCHMARKS)
  add_subdirectory(bench)
endif()

if(POWER_CONTROL_PLANE_BUILD_TESTS)
  add_subdirectory(tests)
endif()
