#include "test_harness.hpp"

// The harness is header-only so that a test can fail with an accurate file and line
// without a macro indirection layer. This translation unit exists so the support
// library has a stable compilation unit of its own, which keeps the harness honest
// about being ordinary first-party code compiled under the same strict settings as
// everything else.

namespace pcp_test {

std::string_view harness_name() noexcept { return "pcp_test"; }

}  // namespace pcp_test
