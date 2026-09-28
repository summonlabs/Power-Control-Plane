#pragma once

// A very small test harness.
//
// The suite is organised by proof obligation rather than by source file, so the
// harness deliberately stays out of the way: a test is a function, a check records
// the first failure with its file and line, and the runner reports a per-test
// verdict and a non-zero exit status when anything failed.
//
// No test is given a timeout. CTest timeouts, timeout wrappers, and watchdog
// processes are prohibited in this repository: a test that does not finish is a
// defect to diagnose, not to bound.

#include <cstdint>
#include <functional>
#include <type_traits>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace pcp_test {

class Context {
 public:
  void fail(const char* file, int line, const std::string& expression) {
    if (failed_) {
      return;
    }
    failed_ = true;
    std::ostringstream stream;
    stream << file << ':' << line << ": check failed: " << expression;
    message_ = stream.str();
  }

  void note(const std::string& text) { notes_.push_back(text); }

  [[nodiscard]] bool failed() const { return failed_; }
  [[nodiscard]] const std::string& message() const { return message_; }
  [[nodiscard]] const std::vector<std::string>& notes() const { return notes_; }

 private:
  bool failed_ = false;
  std::string message_;
  std::vector<std::string> notes_;
};

using TestFunction = std::function<void(Context&)>;

struct TestCase {
  std::string name;
  TestFunction body;
};

class Registry {
 public:
  static Registry& instance() {
    static Registry registry;
    return registry;
  }

  void add(std::string name, TestFunction body) {
    cases_.push_back(TestCase{std::move(name), std::move(body)});
  }

  [[nodiscard]] const std::vector<TestCase>& cases() const { return cases_; }

 private:
  std::vector<TestCase> cases_;
};

struct Registrar {
  Registrar(std::string name, TestFunction body) {
    Registry::instance().add(std::move(name), std::move(body));
  }
};

// Renders a value for a failure message. Types that have no stream insertion
// operator (model enumerations, for example) are reported by name rather than
// making the check itself fail to compile.
template <class T>
std::string render(const T& value) {
  if constexpr (requires(std::ostream& stream, const T& item) { stream << item; }) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  } else if constexpr (std::is_enum_v<T>) {
    // A scoped enumeration has no text form of its own; the ordinal is what a
    // failure message can show without a per-enum table.
    return "enum#" + std::to_string(static_cast<long long>(value));
  } else {
    return "<unprintable>";
  }
}

// Reports a failing check without stopping the test. Used for checks that should be
// observed together, such as "this refusal changed no state" assertions.
inline void report(bool condition, const char* file, int line, const std::string& expression,
                   Context& context) {
  if (!condition) {
    context.fail(file, line, expression);
  }
}

}  // namespace pcp_test

#define PCP_TEST(name)                                                              \
  static void name##_body(::pcp_test::Context& context);                            \
  static const ::pcp_test::Registrar name##_registrar(#name, name##_body);          \
  static void name##_body(::pcp_test::Context& context)

#define PCP_CHECK(condition)                                                        \
  do {                                                                              \
    if (!(condition)) {                                                             \
      context.fail(__FILE__, __LINE__, #condition);                                 \
      return;                                                                       \
    }                                                                               \
  } while (false)

#define PCP_CHECK_MSG(condition, message)                                           \
  do {                                                                              \
    if (!(condition)) {                                                             \
      context.fail(__FILE__, __LINE__, std::string(#condition) + " | " + (message)); \
      return;                                                                       \
    }                                                                               \
  } while (false)

#define PCP_SOFT_CHECK(condition)                                                   \
  ::pcp_test::report((condition), __FILE__, __LINE__, #condition, context)

// Equality check that renders both sides, so a failure is diagnosable without a
// debugger.
#define PCP_CHECK_EQ(actual, expected)                                              \
  do {                                                                              \
    const auto pcp_actual = (actual);                                               \
    const auto pcp_expected = (expected);                                           \
    if (!(pcp_actual == pcp_expected)) {                                            \
      std::ostringstream pcp_stream;                                                \
      pcp_stream << #actual " == " #expected " (actual "                      \
                 << ::pcp_test::render(pcp_actual) << ", expected "                \
                 << ::pcp_test::render(pcp_expected) << ')';                       \
      context.fail(__FILE__, __LINE__, pcp_stream.str());                           \
      return;                                                                       \
    }                                                                               \
  } while (false)

namespace pcp_test {

// Seed handling for randomized tests: a failing run prints the seed so the exact
// sequence can be replayed.
class SeededRandom {
 public:
  explicit SeededRandom(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}

  [[nodiscard]] std::uint64_t seed() const { return seed_; }

  [[nodiscard]] std::uint64_t next() {
    // splitmix64: deterministic, portable, and adequate for state-machine fuzzing.
    state_ += 0x9E3779B97F4A7C15ull;
    std::uint64_t value = state_;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
  }

  [[nodiscard]] std::uint64_t below(std::uint64_t bound) {
    if (bound == 0) {
      return 0;
    }
    return next() % bound;
  }

 private:
  std::uint64_t seed_ = 0;
  std::uint64_t state_ = 0;
};

namespace detail {
inline int run_all_impl(int argc, char** argv, const char* suite_name) {
  const auto& cases = ::pcp_test::Registry::instance().cases();
  std::string filter;
  if (argc > 1) {
    filter = argv[1];
  }
  std::size_t passed = 0;
  std::size_t failed = 0;
  std::size_t skipped = 0;
  for (const ::pcp_test::TestCase& test : cases) {
    if (!filter.empty() && test.name.find(filter) == std::string::npos) {
      ++skipped;
      continue;
    }
    ::pcp_test::Context context;
    try {
      test.body(context);
    } catch (const std::exception& error) {
      context.fail(__FILE__, __LINE__,
                   std::string("unexpected exception: ") + error.what());
    } catch (...) {
      context.fail(__FILE__, __LINE__, "unexpected non-standard exception");
    }
    for (const std::string& note : context.notes()) {
      std::cout << "  note: " << note << '\n';
    }
    if (context.failed()) {
      ++failed;
      std::cout << "[FAIL] " << test.name << ": " << context.message() << '\n';
    } else {
      ++passed;
      std::cout << "[ ok ] " << test.name << '\n';
    }
  }
  std::cout << suite_name << ": " << passed << " passed, " << failed << " failed";
  if (skipped > 0) {
    std::cout << ", " << skipped << " filtered out";
  }
  std::cout << '\n';
  return failed == 0 ? 0 : 1;
}
}  // namespace detail

}  // namespace pcp_test

#define PCP_TEST_MAIN(suite_name)                                                   \
  int main(int argc, char** argv) {                                                 \
    return ::pcp_test::detail::run_all_impl(argc, argv, suite_name);                \
  }
