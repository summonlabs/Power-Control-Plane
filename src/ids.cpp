#include "power_control_plane/ids.hpp"

#include <random>

namespace power_control_plane::detail {

Random128 random_128() {
  // Identity allocation only. Nothing produced here enters canonical content
  // except through an explicitly persisted identity field (the store incarnation)
  // whose value is intentional state.
  std::random_device device;
  Random128 bits{};
  bits.high = (static_cast<std::uint64_t>(device()) << 32) ^
              static_cast<std::uint64_t>(device());
  bits.low = (static_cast<std::uint64_t>(device()) << 32) ^
             static_cast<std::uint64_t>(device());
  return bits;
}

}  // namespace power_control_plane::detail
