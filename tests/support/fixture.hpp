#pragma once

// Shared test fixture.
//
// A Fixture is an open, bootstrapped, revalidated control plane with writer
// authority, a baseline policy, and a deterministic evidence binding. Tests that
// need a different starting point build it from the same helpers.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/engine.hpp"

namespace pcp_test {

// Removes and recreates a scratch directory under the test working directory.
[[nodiscard]] std::string scratch_directory(std::string_view name);

[[nodiscard]] power_control_plane::Result<power_control_plane::EvidenceBinding>
fixture_evidence(std::uint64_t generation = 5, std::uint64_t revision = 3);

[[nodiscard]] power_control_plane::Result<power_control_plane::PowerPolicy>
fixture_policy(power_control_plane::PolicyRevision revision,
               const power_control_plane::Limits& limits);

// A permissive policy used to demonstrate that a safety interlock cannot be
// outranked by a policy rule.
[[nodiscard]] power_control_plane::Result<power_control_plane::PowerPolicy>
permissive_policy(power_control_plane::PolicyRevision revision,
                  const power_control_plane::Limits& limits);

class Fixture {
 public:
  Fixture() = default;

  static power_control_plane::Result<Fixture> create(
      std::string_view name, power_control_plane::EngineOptions options = {});

  [[nodiscard]] power_control_plane::ControlPlane& plane() {
    return *plane_;
  }
  [[nodiscard]] power_control_plane::WriterLease& lease() { return *lease_; }
  [[nodiscard]] const power_control_plane::Limits& limits() const {
    return plane_->limits();
  }
  [[nodiscard]] const std::string& root() const { return root_; }
  [[nodiscard]] const power_control_plane::EvidenceBinding& evidence() const {
    return evidence_;
  }

  [[nodiscard]] power_control_plane::Result<power_control_plane::FacilitySnapshot> snapshot()
      const {
    return plane_->snapshot();
  }

  [[nodiscard]] power_control_plane::Result<power_control_plane::MutationRequest> request(
      std::string_view seed) const;

  [[nodiscard]] power_control_plane::Result<power_control_plane::ActionIntent> intent(
      std::string_view id, power_control_plane::ActionKind kind, std::string_view target,
      std::uint64_t requested_load_kw = 0) const;

  [[nodiscard]] power_control_plane::Result<power_control_plane::AuthorizationDecision>
  revalidate();

  [[nodiscard]] power_control_plane::Result<power_control_plane::AuthorizationDecision> grant(
      const std::vector<power_control_plane::ActionKind>& kinds,
      const std::vector<std::string>& targets, std::uint32_t max_uses,
      std::uint64_t generation_lifetime = 8, std::uint64_t revision_lifetime = 128);

  [[nodiscard]] power_control_plane::Result<power_control_plane::AuthorizationDecision>
  transition_to(power_control_plane::OperatingMode target,
                std::vector<power_control_plane::ObligationSuspension> suspensions = {});

  [[nodiscard]] power_control_plane::Result<power_control_plane::AuthorizationDecision>
  authorize(const power_control_plane::ActionIntent& intent, std::string_view seed);

  void close();

 private:
  std::unique_ptr<power_control_plane::ControlPlane> plane_;
  std::unique_ptr<power_control_plane::WriterLease> lease_;
  power_control_plane::EvidenceBinding evidence_;
  std::string root_;
};

}  // namespace pcp_test
