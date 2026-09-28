# Benchmark.
#
# Measures completed operations only: every timing includes validation, canonical
# encoding, staging, the required durable flush, read-back verification, atomic
# publication, head-marker commit, authority advancement, and residue retirement.
# Submission latency is never timed and reported as completion.

add_executable(pcp_bench bench_control.cpp)
target_link_libraries(pcp_bench PRIVATE power_control_plane)
power_control_plane_apply_strict_options(pcp_bench)
