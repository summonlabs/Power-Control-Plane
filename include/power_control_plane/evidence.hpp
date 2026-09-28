#pragma once

// References to evidence produced by adjacent DCCP runtimes.
//
// Power Control Plane does not own electrical topology, per-feed eligibility,
// PDU/UPS/generator device lifecycle, load-shedding execution, energy accounting,
// or capacity computation. It consumes their published facts as typed references
// that carry the producing runtime identity, generation, revision, controller
// epoch and incarnation, and a content digest.
//
// An EvidenceRef is a binding, never a freshness claim. Persisting a binding and
// reopening the store does not make the referenced evidence current: freshness is
// runtime state that must be re-established by an explicit revalidation.

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "power_control_plane/canonical.hpp"
#include "power_control_plane/digest.hpp"
#include "power_control_plane/error.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/limits.hpp"

namespace power_control_plane {

enum class EvidenceKind : std::uint8_t {
  power_topology = 1,
  feed_authority = 2,
  power_capacity = 3,
  pdu_device = 4,
  ups_device = 5,
  generator_device = 6,
  load_shedding = 7,
  energy_ledger = 8,
  facility_capacity = 9,
  black_start_status = 10,
  safety_system = 11,
};

[[nodiscard]] std::string_view to_string(EvidenceKind kind) noexcept;
[[nodiscard]] Result<EvidenceKind> parse_evidence_kind(std::string_view text);

struct EvidenceRef {
  EvidenceSourceId source;
  EvidenceKind kind = EvidenceKind::power_topology;
  EvidenceGeneration generation;
  EvidenceRevision revision;
  ControllerEpoch epoch;
  ControllerIncarnation incarnation;
  Digest content_digest;
};

[[nodiscard]] bool operator==(const EvidenceRef& a, const EvidenceRef& b) noexcept;
[[nodiscard]] bool operator!=(const EvidenceRef& a, const EvidenceRef& b) noexcept;
[[nodiscard]] bool operator<(const EvidenceRef& a, const EvidenceRef& b) noexcept;

// An evidence binding is the complete set of external references an authoritative
// decision depends on. It is stored sorted by source identity and compared as an
// exact set: two bindings match only when every field of every reference is
// equal.
class EvidenceBinding {
 public:
  EvidenceBinding() = default;

  static Result<EvidenceBinding> create(std::vector<EvidenceRef> refs,
                                        const Limits& limits);

  [[nodiscard]] const std::vector<EvidenceRef>& refs() const noexcept {
    return refs_;
  }
  [[nodiscard]] bool empty() const noexcept { return refs_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return refs_.size(); }
  [[nodiscard]] const EvidenceRef* find(const EvidenceSourceId& source) const noexcept;
  [[nodiscard]] bool contains(const EvidenceSourceId& source) const noexcept {
    return find(source) != nullptr;
  }
  [[nodiscard]] bool matches(const EvidenceBinding& other) const noexcept;
  [[nodiscard]] Digest digest() const;

  [[nodiscard]] Status encode(CanonicalWriter& writer, const Limits& limits) const;
  [[nodiscard]] static Result<EvidenceBinding> decode(CanonicalReader& reader,
                                                      const Limits& limits);

 private:
  std::vector<EvidenceRef> refs_;
};

}  // namespace power_control_plane
