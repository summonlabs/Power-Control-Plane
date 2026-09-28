#include "power_control_plane/adapter.hpp"

#include <string>
#include <utility>

namespace power_control_plane {

SimulationAdapter::SimulationAdapter(AdapterId id, SimulationBehaviour behaviour)
    : id_(std::move(id)), behaviour_(behaviour) {}

Result<Acknowledgement> SimulationAdapter::issue(const IssuedCommand& command) {
  ++issues_;
  if (behaviour_ == SimulationBehaviour::refuse_command) {
    return Error(ErrorCode::indeterminate,
                 "the simulated adapter refused to hand the command to the equipment "
                 "boundary; nothing was issued");
  }
  Acknowledgement acknowledgement;
  acknowledgement.adapter = id_;
  acknowledgement.command_digest = command.command_digest;
  acknowledgement.detail = "simulated command receipt";
  return acknowledgement;
}

Result<ObservedEffect> SimulationAdapter::observe(const IssuedCommand& command) {
  ++observations_;
  switch (behaviour_) {
    case SimulationBehaviour::refuse_command:
      return Error(ErrorCode::invalid_transition,
                   "no command was issued, so there is nothing to observe");
    case SimulationBehaviour::acknowledge_only:
      return Error(ErrorCode::indeterminate,
                   "the simulated adapter acknowledged the command but has no observation "
                   "to report");
    case SimulationBehaviour::observation_failure:
      return Error(ErrorCode::indeterminate,
                   "the simulated adapter failed while observing the commanded equipment");
    case SimulationBehaviour::full_success:
    case SimulationBehaviour::effect_contradicts_intent:
    case SimulationBehaviour::effect_unverified:
      break;
  }
  ObservedEffect effect;
  effect.adapter = id_;
  CanonicalWriter writer;
  writer.u64(command.attempt.value());
  writer.digest(command.command_digest);
  writer.u8(static_cast<std::uint8_t>(behaviour_));
  const Bytes payload = writer.take();
  effect.observation_digest =
      sha256_domain("pcp/simulated-observation/v1", payload.data(), payload.size());
  effect.detail = "simulated observation";
  return effect;
}

Result<VerificationReport> SimulationAdapter::verify(const IssuedCommand& command,
                                                     const ObservedEffect& effect) {
  ++verifications_;
  VerificationReport report;
  report.verifier = id_;
  CanonicalWriter evidence_writer;
  evidence_writer.digest(command.command_digest);
  evidence_writer.digest(effect.observation_digest);
  const Bytes evidence_bytes = evidence_writer.take();
  report.evidence_digest = sha256_domain("pcp/simulated-verification/v1",
                                         evidence_bytes.data(), evidence_bytes.size());
  switch (behaviour_) {
    case SimulationBehaviour::refuse_command:
      return Error(ErrorCode::invalid_transition,
                   "no command was issued, so there is nothing to verify");
    case SimulationBehaviour::full_success:
      report.matches_intent = true;
      report.detail = "simulated verification matched the commanded state";
      break;
    case SimulationBehaviour::effect_contradicts_intent:
      report.matches_intent = false;
      report.detail = "simulated verification found the equipment in a different state "
                      "than the command intended";
      break;
    case SimulationBehaviour::effect_unverified:
      report.matches_intent = false;
      report.detail = "no independent verification is available for this command";
      break;
    case SimulationBehaviour::acknowledge_only:
    case SimulationBehaviour::observation_failure:
      return Error(ErrorCode::indeterminate,
                   "the simulated adapter has no observation to verify against");
  }
  return report;
}

}  // namespace power_control_plane
