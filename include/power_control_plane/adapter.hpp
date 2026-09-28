#pragma once

// The actuation adapter boundary.
//
// This runtime never talks to electrical equipment directly and never embeds an
// endpoint, credential, or protocol. Every physical consequence leaves through an
// ActuationAdapter supplied by the embedding process. The adapter contract
// separates three facts that are commonly conflated:
//
//   issue()   -> Acknowledgement   the command was received
//   observe() -> ObservedEffect    something was observed afterwards
//   verify()  -> VerificationReport an independent check matched intent to effect
//
// The engine refuses to promote an acknowledgement into an effect, or an effect
// into verified completion. A verification report is only accepted when it comes
// from a different adapter than the one that acknowledged the command.
//
// Synthetic adapters (SimulationAdapter) exist so the control semantics can be
// validated deterministically with no hardware present. Evidence produced through
// them is SYNTHETIC and is labelled as such by the CLI, the examples, and the
// validation documentation. No hardware validation is claimed anywhere in this
// repository.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/action.hpp"
#include "power_control_plane/attempt.hpp"
#include "power_control_plane/digest.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/limits.hpp"

namespace power_control_plane {

// The exact command object handed to an adapter. Its digest covers every field,
// so an acknowledgement can only refer to one specific command.
struct IssuedCommand {
  AttemptId attempt;
  ActionId action;
  ActionKind kind = ActionKind::open_breaker;
  ActionTargetId target;
  ControlGeneration generation;
  StateRevision revision;
  Digest command_digest;
};

[[nodiscard]] Digest command_digest(const IssuedCommand& command);

class ActuationAdapter {
 public:
  ActuationAdapter() = default;
  virtual ~ActuationAdapter() = default;

  ActuationAdapter(const ActuationAdapter&) = delete;
  ActuationAdapter& operator=(const ActuationAdapter&) = delete;

  [[nodiscard]] virtual AdapterId id() const = 0;

  // Hands the command to the equipment boundary and reports receipt. Returning
  // an error means the command was not handed over; it is not an acknowledgement.
  [[nodiscard]] virtual Result<Acknowledgement> issue(const IssuedCommand& command) = 0;

  // Reports what was observed after the command. An adapter that cannot observe
  // returns an error and the attempt stays acknowledged-but-unobserved.
  [[nodiscard]] virtual Result<ObservedEffect> observe(const IssuedCommand& command) = 0;

  // Independently checks whether the facility reached the intended state.
  [[nodiscard]] virtual Result<VerificationReport> verify(
      const IssuedCommand& command, const ObservedEffect& effect) = 0;

  // True when this adapter produces simulated rather than measured evidence.
  [[nodiscard]] virtual bool synthetic() const noexcept = 0;
};

// Deterministic scripted adapter used by the examples, the CLI, the benchmarks,
// and the test suite. Every behaviour is selected explicitly; nothing here
// consults the clock, the filesystem, or the network.
enum class SimulationBehaviour : std::uint8_t {
  // Acknowledges, observes the intended effect, and reports a match.
  full_success = 1,
  // Acknowledges the command but never observes any effect. Demonstrates
  // acknowledgement without effect.
  acknowledge_only = 2,
  // Refuses at the issue stage: no command was handed over.
  refuse_command = 3,
  // Acknowledges and observes an effect that contradicts the intent.
  effect_contradicts_intent = 4,
  // Acknowledges and observes the intended effect but reports no verification.
  effect_unverified = 5,
  // Reports an internal failure during observation.
  observation_failure = 6,
};

[[nodiscard]] std::string_view to_string(SimulationBehaviour behaviour) noexcept;
[[nodiscard]] Result<SimulationBehaviour> parse_simulation_behaviour(std::string_view text);

class SimulationAdapter final : public ActuationAdapter {
 public:
  SimulationAdapter(AdapterId id, SimulationBehaviour behaviour);

  [[nodiscard]] AdapterId id() const override { return id_; }
  [[nodiscard]] Result<Acknowledgement> issue(const IssuedCommand& command) override;
  [[nodiscard]] Result<ObservedEffect> observe(const IssuedCommand& command) override;
  [[nodiscard]] Result<VerificationReport> verify(const IssuedCommand& command,
                                                  const ObservedEffect& effect) override;
  [[nodiscard]] bool synthetic() const noexcept override { return true; }

  [[nodiscard]] SimulationBehaviour behaviour() const noexcept { return behaviour_; }
  [[nodiscard]] std::size_t issues() const noexcept { return issues_; }
  [[nodiscard]] std::size_t observations() const noexcept { return observations_; }
  [[nodiscard]] std::size_t verifications() const noexcept { return verifications_; }

 private:
  AdapterId id_;
  SimulationBehaviour behaviour_;
  std::size_t issues_ = 0;
  std::size_t observations_ = 0;
  std::size_t verifications_ = 0;
};

}  // namespace power_control_plane
