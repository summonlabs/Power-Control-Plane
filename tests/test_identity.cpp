// Proof obligations: identity typing, canonical encoding determinism, and the SHA-256
// implementation the store integrity checks depend on.

#include <string>
#include <vector>

#include "power_control_plane/canonical.hpp"
#include "power_control_plane/digest.hpp"
#include "power_control_plane/ids.hpp"
#include "power_control_plane/state.hpp"
#include "support/test_harness.hpp"

namespace {

using namespace power_control_plane;
using namespace pcp_test;

std::string hex_of(std::string_view text) { return sha256(text).to_hex(); }

}  // namespace

PCP_TEST(sha256_matches_published_nist_vectors) {
  PCP_CHECK_EQ(hex_of(""),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  PCP_CHECK_EQ(hex_of("abc"),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  PCP_CHECK_EQ(
      hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  PCP_CHECK_EQ(hex_of("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                      "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
               std::string("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"));
}

PCP_TEST(sha256_one_million_a_matches_nist_vector) {
  Sha256 hasher;
  const std::string block(1000, 'a');
  for (int index = 0; index < 1000; ++index) {
    hasher.update(block);
  }
  PCP_CHECK_EQ(hasher.finalize().to_hex(),
               std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

PCP_TEST(sha256_incremental_feeding_equals_single_shot) {
  std::string message;
  for (int index = 0; index < 500; ++index) {
    message.push_back(static_cast<char>('A' + (index % 26)));
  }
  const Digest single = sha256(message);
  for (std::size_t chunk = 1; chunk <= 8; ++chunk) {
    Sha256 hasher;
    std::size_t offset = 0;
    while (offset < message.size()) {
      const std::size_t size = std::min(chunk, message.size() - offset);
      hasher.update(reinterpret_cast<const std::uint8_t*>(message.data()) + offset, size);
      offset += size;
    }
    PCP_CHECK(hasher.finalize() == single);
  }
}

PCP_TEST(digest_hex_round_trip_and_rejection) {
  const Digest digest = sha256_domain("pcp/test/v1", "payload");
  auto parsed = Digest::from_hex(digest.to_hex());
  PCP_CHECK(parsed.has_value());
  PCP_CHECK(parsed.value() == digest);
  PCP_CHECK(!Digest::from_hex("zz").has_value());
  PCP_CHECK(!Digest::from_hex(std::string(63, 'a')).has_value());
  PCP_CHECK(!Digest::from_hex(std::string(65, 'a')).has_value());
  PCP_CHECK(Digest::zero().is_zero());
  PCP_CHECK(!digest.is_zero());
}

PCP_TEST(counters_refuse_to_wrap) {
  const ControllerEpoch epoch(std::numeric_limits<std::uint64_t>::max());
  const auto advanced = epoch.next();
  PCP_CHECK(!advanced.has_value());
  PCP_CHECK_EQ(advanced.error().code(), ErrorCode::arithmetic_overflow);

  const StateRevision revision(5);
  const auto ok = revision.next();
  PCP_CHECK(ok.has_value());
  PCP_CHECK_EQ(ok.value().value(), std::uint64_t{6});

  const auto huge = ControlGeneration(1).advance_by(std::numeric_limits<std::uint64_t>::max());
  PCP_CHECK(!huge.has_value());
}

PCP_TEST(text_identifier_grammar_is_narrow) {
  PCP_CHECK(FacilityId::parse("dc1").has_value());
  PCP_CHECK(FacilityId::parse("dc-1.a:b_c").has_value());
  PCP_CHECK(!FacilityId::parse("").has_value());
  PCP_CHECK(!FacilityId::parse("-leading").has_value());
  PCP_CHECK(!FacilityId::parse(".").has_value());
  PCP_CHECK(!FacilityId::parse("..").has_value());
  PCP_CHECK(!FacilityId::parse("has space").has_value());
  PCP_CHECK(!FacilityId::parse("has/slash").has_value());
  PCP_CHECK(!FacilityId::parse("has\\slash").has_value());
  PCP_CHECK(!FacilityId::parse(std::string(65, 'a')).has_value());
  PCP_CHECK(FacilityId::parse(std::string(64, 'a')).has_value());
  // A NUL inside the text must be refused: it is not in the grammar.
  const std::string with_nul("ab\0cd", 5);
  PCP_CHECK(!FacilityId::parse(with_nul).has_value());
  // A multi-byte UTF-8 sequence is outside the ASCII grammar and is refused.
  PCP_CHECK(!FacilityId::parse("\xC3\xA9").has_value());
}

PCP_TEST(opaque_identity_hex_round_trip) {
  const StoreIncarnation incarnation =
      StoreIncarnation::from_parts(0x0123456789ABCDEFull, 0xFEDCBA9876543210ull);
  auto parsed = StoreIncarnation::from_hex(incarnation.to_hex());
  PCP_CHECK(parsed.has_value());
  PCP_CHECK(parsed.value() == incarnation);
  PCP_CHECK_EQ(incarnation.to_hex(), std::string("0123456789abcdeffedcba9876543210"));
  PCP_CHECK(!StoreIncarnation::from_hex("short").has_value());
  PCP_CHECK(!StoreIncarnation::from_hex(std::string(32, 'z')).has_value());
}

PCP_TEST(canonical_encoding_is_byte_deterministic) {
  CanonicalWriter first;
  CanonicalWriter second;
  for (int index = 0; index < 32; ++index) {
    first.u16(static_cast<std::uint16_t>(index * 7));
    second.u16(static_cast<std::uint16_t>(index * 7));
    PCP_CHECK(first.text("payload-" + std::to_string(index), 64).ok());
    PCP_CHECK(second.text("payload-" + std::to_string(index), 64).ok());
  }
  PCP_CHECK(first.buffer() == second.buffer());

  CanonicalReader reader(first.buffer());
  for (int index = 0; index < 32; ++index) {
    auto value = reader.u16();
    PCP_CHECK(value.has_value());
    PCP_CHECK_EQ(value.value(), static_cast<std::uint16_t>(index * 7));
    auto text = reader.text(64);
    PCP_CHECK(text.has_value());
    PCP_CHECK_EQ(text.value(), std::string("payload-") + std::to_string(index));
  }
  PCP_CHECK(reader.at_end());
  PCP_CHECK(reader.expect_end().ok());
}

PCP_TEST(canonical_reader_refuses_trailing_and_truncated_input) {
  CanonicalWriter writer;
  writer.u32(7);
  Bytes bytes = writer.buffer();
  bytes.push_back(0x00);
  CanonicalReader trailing(bytes);
  auto value = trailing.u32();
  PCP_CHECK(value.has_value());
  PCP_CHECK(!trailing.expect_end().ok());

  CanonicalReader truncated(bytes.data(), 2);
  PCP_CHECK(!truncated.u32().has_value());

  CanonicalWriter text_writer;
  PCP_CHECK(text_writer.text(std::string(4096, 'x'), 8192).ok());
  CanonicalReader bounded(text_writer.buffer());
  PCP_CHECK(!bounded.text(64).has_value());
  PCP_CHECK_EQ(bounded.text(64).error().code(), ErrorCode::limit_exceeded);

  CanonicalWriter overflow_writer;
  PCP_CHECK(!overflow_writer.text(std::string(4, 'x'), 2).ok());
}

PCP_TEST(facility_state_codec_round_trips_exactly) {
  FacilityState state = FacilityState::vacant(FacilityId::parse("dc1").value(),
                                              StoreIncarnation::from_parts(11, 22));
  const Bytes first = state.encode(Limits::defaults());
  PCP_CHECK(!first.empty());
  auto decoded = FacilityState::decode(first, Limits::defaults());
  PCP_CHECK(decoded.has_value());
  const Bytes second = decoded.value().encode(Limits::defaults());
  PCP_CHECK(first == second);
  PCP_CHECK(decoded.value().canonical_digest() == state.canonical_digest());

  // Trailing bytes are a format violation, never silently ignored: silently ignoring
  // them is how two different byte strings become "the same" state.
  Bytes with_trailer = first;
  with_trailer.push_back(0x5A);
  PCP_CHECK(!FacilityState::decode(with_trailer, Limits::defaults()).has_value());

  // A truncated payload is refused.
  Bytes truncated(first.begin(), first.begin() + static_cast<std::ptrdiff_t>(first.size() - 1));
  PCP_CHECK(!FacilityState::decode(truncated, Limits::defaults()).has_value());

  // An unsupported encoding version is refused with the exact error code, which
  // proves the format identity is validated before any field is trusted.
  Bytes wrong_version = first;
  wrong_version[0] = 0x7F;
  auto rejected = FacilityState::decode(wrong_version, Limits::defaults());
  PCP_CHECK(!rejected.has_value());
  PCP_CHECK_EQ(rejected.error().code(), ErrorCode::unsupported_format);

  // Every single-byte corruption either fails to decode or decodes to a different
  // state. A corruption that silently decoded to the same state would mean the byte
  // is not part of the canonical content.
  std::size_t decodable = 0;
  for (std::size_t offset = 0; offset < first.size(); ++offset) {
    Bytes candidate = first;
    candidate[offset] = static_cast<std::uint8_t>(candidate[offset] ^ 0x01u);
    auto attempt = FacilityState::decode(candidate, Limits::defaults());
    if (!attempt.has_value()) {
      continue;
    }
    ++decodable;
    PCP_CHECK(!(attempt.value().canonical_digest() == state.canonical_digest()));
  }
  context.note("single-byte corruptions that still decoded: " + std::to_string(decodable) +
               " of " + std::to_string(first.size()));
}

PCP_TEST_MAIN("test_identity")
