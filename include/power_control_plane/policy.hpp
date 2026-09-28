#pragma once

// Deterministic power policy.
//
// A policy is an ordered list of rules. Evaluation walks the rules in a total
// order (ascending order index, then ascending rule identity) and produces a
// complete trace: every rule is recorded with whether it matched and what it
// would do. The outcome is derived from the trace, never from the first match:
//
//   * any matching deny rule            -> deny
//   * else any matching require rule    -> that requirement
//   * else any matching allow rule      -> allow
//   * else                              -> no_match, which the engine treats as
//                                          deny (fail closed)
//
// A policy cannot grant an action that an interlock blocks. The engine evaluates
// interlocks first and no policy effect can clear, weaken, or outrank an
// interlock.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/action.hpp"
#include "power_control_plane/canonical.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/interlock.hpp"
#include "power_control_plane/limits.hpp"
#include "power_control_plane/mode.hpp"
#include "power_control_plane/obligation.hpp"

namespace power_control_plane {

enum class PolicyEffect : std::uint8_t {
  allow = 1,
  deny = 2,
  require_permission = 3,
  require_revalidation = 4,
};

enum class PolicyConditionKind : std::uint8_t {
  always = 1,
  mode_is = 2,
  action_kind_is = 3,
  target_is = 4,
  interlock_state_is = 5,
  obligation_state_is = 6,
  evidence_source_present = 7,
  requested_load_at_least = 8,
};

[[nodiscard]] std::string_view to_string(PolicyEffect effect) noexcept;
[[nodiscard]] std::string_view to_string(PolicyConditionKind kind) noexcept;
[[nodiscard]] Result<PolicyEffect> parse_policy_effect(std::string_view text);
[[nodiscard]] Result<PolicyConditionKind> parse_condition_kind(std::string_view text);

struct PolicyCondition {
  PolicyConditionKind kind = PolicyConditionKind::always;
  OperatingMode mode = OperatingMode::normal;
  ActionKind action_kind = ActionKind::open_breaker;
  ActionTargetId target;
  InterlockState interlock_state = InterlockState::engaged;
  ObligationState obligation_state = ObligationState::active;
  EvidenceSourceId evidence_source;
  std::uint64_t threshold_kw = 0;
};

struct PolicyRule {
  RuleId id;
  std::uint32_t order = 0;
  PolicyCondition condition;
  PolicyEffect effect = PolicyEffect::deny;
  std::string explanation;
};

enum class PolicyOutcome : std::uint8_t {
  allow = 1,
  deny = 2,
  require_permission = 3,
  require_revalidation = 4,
  no_match = 5,
};

[[nodiscard]] std::string_view to_string(PolicyOutcome outcome) noexcept;

struct PolicyRuleTrace {
  RuleId rule;
  std::uint32_t order = 0;
  PolicyEffect effect = PolicyEffect::deny;
  bool matched = false;
  std::string explanation;
};

struct PolicyEvaluation {
  PolicyRevision revision;
  PolicyOutcome outcome = PolicyOutcome::no_match;
  std::vector<PolicyRuleTrace> trace;
};

class PowerPolicy {
 public:
  PowerPolicy() = default;

  // Rules are stored sorted by (order, id); duplicates by identity are refused.
  static Result<PowerPolicy> create(PolicyRevision revision,
                                    std::vector<PolicyRule> rules,
                                    const Limits& limits);

  [[nodiscard]] PolicyRevision revision() const noexcept { return revision_; }
  [[nodiscard]] const std::vector<PolicyRule>& rules() const noexcept { return rules_; }
  [[nodiscard]] bool empty() const noexcept { return rules_.empty(); }

  // Domain-separated canonical digest of the rule set and revision.
  [[nodiscard]] Digest digest() const;

  [[nodiscard]] Status encode(CanonicalWriter& writer, const Limits& limits) const;
  [[nodiscard]] static Result<PowerPolicy> decode(CanonicalReader& reader,
                                                  const Limits& limits);

 private:
  PolicyRevision revision_;
  std::vector<PolicyRule> rules_;
};

[[nodiscard]] Status encode_policy_rule(CanonicalWriter& writer, const PolicyRule& rule,
                                        const Limits& limits);
[[nodiscard]] Result<PolicyRule> decode_policy_rule(CanonicalReader& reader,
                                                    const Limits& limits);

}  // namespace power_control_plane
