#pragma once

// Externally influenced sizes are bounded before allocation. Every collection
// that an operator, adapter, or persisted payload can grow has an explicit cap in
// Limits. Constructs that would exceed a cap are refused with
// ErrorCode::limit_exceeded before any allocation proportional to the input.

#include <cstddef>

namespace power_control_plane {

struct Limits {
  // Identifier and text bounds.
  std::size_t max_identifier_length = 64;
  std::size_t max_text_field_bytes = 512;
  std::size_t max_explanation_detail_bytes = 256;
  std::size_t max_explanation_steps = 64;
  std::size_t max_path_bytes = 4096;

  // Model collection bounds.
  std::size_t max_evidence_sources = 256;
  std::size_t max_evidence_bindings = 64;
  std::size_t max_interlocks = 1024;
  std::size_t max_obligations = 1024;
  std::size_t max_capacity_commitments = 1024;
  std::size_t max_permissions = 4096;
  std::size_t max_policy_rules = 256;
  std::size_t max_permission_scope_kinds = 32;
  std::size_t max_permission_scope_targets = 64;
  std::size_t max_scope_targets = 256;

  // Attempt, replay, and history bounds.
  std::size_t max_attempts = 4096;
  std::size_t max_replay_records = 4096;
  std::size_t max_transition_log_entries = 1024;
  std::size_t max_attempt_events = 16;
  std::size_t max_mode_history = 2048;

  // Durable store bounds.
  std::size_t max_payload_bytes = 64u * 1024u * 1024u;
  std::size_t max_retained_generations = 16;
  std::size_t max_staging_files = 8;

  [[nodiscard]] static const Limits& defaults() noexcept;
};

}  // namespace power_control_plane
