// pcp: inspection and administration for the Power Control Plane.
//
// The tool is a thin driver over the library. It contains no policy engine, no
// interlock logic, and no persistence of its own: every verb calls the same
// ControlPlane API an embedding process would call, so there is no CLI path that
// bypasses the engine used by the library.
//
// Exit codes:
//   0  the operation was accepted or replayed
//   1  usage or input error
//   2  the operation was refused by the control plane (the decision explains why)
//   3  a store, I/O, or integrity failure

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "power_control_plane/engine.hpp"
#include "power_control_plane/version.hpp"

namespace {

using namespace power_control_plane;

constexpr int kExitOk = 0;
constexpr int kExitUsage = 1;
constexpr int kExitRefused = 2;
constexpr int kExitStore = 3;

// Several model enumerations render through std::string_view, which the standard
// library does not concatenate with std::string or a string literal. These narrow
// helpers keep the verb implementations readable without pulling in a formatting
// library.
inline std::string operator+(const std::string& left, std::string_view right) {
  std::string out = left;
  out.append(right);
  return out;
}
inline std::string operator+(std::string_view left, const std::string& right) {
  std::string out(left);
  out.append(right);
  return out;
}
inline std::string operator+(const char* left, std::string_view right) {
  std::string out(left);
  out.append(right);
  return out;
}
inline std::string operator+(std::string_view left, const char* right) {
  std::string out(left);
  out.append(right);
  return out;
}
inline std::string operator+(std::string_view left, std::string_view right) {
  std::string out(left);
  out.append(right);
  return out;
}

class ArgReader {
 public:
  ArgReader(std::vector<std::string> arguments) {
    for (std::size_t index = 0; index < arguments.size(); ++index) {
      const std::string& argument = arguments[index];
      if (argument.size() > 2 && argument[0] == '-' && argument[1] == '-') {
        std::string name = argument.substr(2);
        std::string inline_value;
        const std::size_t equals = name.find('=');
        if (equals != std::string::npos) {
          inline_value = name.substr(equals + 1);
          name = name.substr(0, equals);
        }
        if (!inline_value.empty()) {
          options_[name].push_back(inline_value);
          continue;
        }
        if (index + 1 < arguments.size() && arguments[index + 1].rfind("--", 0) != 0) {
          options_[name].push_back(arguments[index + 1]);
          ++index;
          continue;
        }
        options_[name].push_back(std::string());
        continue;
      }
      positional_.push_back(argument);
    }
  }

  [[nodiscard]] bool has(std::string_view name) const {
    return options_.find(std::string(name)) != options_.end();
  }
  [[nodiscard]] std::optional<std::string> value(std::string_view name) const {
    const auto position = options_.find(std::string(name));
    if (position == options_.end() || position->second.empty()) {
      return std::nullopt;
    }
    return position->second.back();
  }
  [[nodiscard]] std::vector<std::string> values(std::string_view name) const {
    const auto position = options_.find(std::string(name));
    if (position == options_.end()) {
      return {};
    }
    return position->second;
  }
  [[nodiscard]] const std::vector<std::string>& positional() const { return positional_; }

 private:
  std::map<std::string, std::vector<std::string>> options_;
  std::vector<std::string> positional_;
};

void print_line(const std::string& text) { std::cout << text << '\n'; }

void print_error(const std::string& text) { std::cerr << "pcp: " << text << '\n'; }

std::string unsigned_text(std::uint64_t value) { return std::to_string(value); }

Result<EvidenceRef> parse_evidence_spec(std::string_view spec) {
  // source:kind:generation:revision:epoch:incarnation:digest
  std::vector<std::string> parts;
  std::size_t start = 0;
  for (std::size_t index = 0; index <= spec.size(); ++index) {
    if (index == spec.size() || spec[index] == ':') {
      parts.push_back(std::string(spec.substr(start, index - start)));
      start = index + 1;
    }
  }
  if (parts.size() != 7) {
    return Error(ErrorCode::invalid_argument,
                 "an evidence reference is source:kind:generation:revision:epoch:"
                 "incarnation:digest");
  }
  auto source = EvidenceSourceId::parse(parts[0]);
  if (!source.has_value()) {
    return source.error();
  }
  auto kind = parse_evidence_kind(parts[1]);
  if (!kind.has_value()) {
    return kind.error();
  }
  auto generation = std::stoull(parts[2]);
  auto revision = std::stoull(parts[3]);
  auto epoch = std::stoull(parts[4]);
  auto incarnation = ControllerIncarnation::from_hex(parts[5]);
  if (!incarnation.has_value()) {
    return incarnation.error();
  }
  auto digest = Digest::from_hex(parts[6]);
  if (!digest.has_value()) {
    return digest.error();
  }
  EvidenceRef reference;
  reference.source = source.value();
  reference.kind = kind.value();
  reference.generation = EvidenceGeneration(generation);
  reference.revision = EvidenceRevision(revision);
  reference.epoch = ControllerEpoch(epoch);
  reference.incarnation = incarnation.value();
  reference.content_digest = digest.value();
  return reference;
}

Result<EvidenceBinding> parse_evidence_list(const std::vector<std::string>& specs,
                                            const Limits& limits) {
  std::vector<EvidenceRef> references;
  for (const std::string& spec : specs) {
    auto reference = parse_evidence_spec(spec);
    if (!reference.has_value()) {
      return reference.error();
    }
    references.push_back(reference.value());
  }
  return EvidenceBinding::create(std::move(references), limits);
}

std::string describe_evidence(const EvidenceBinding& binding) {
  std::string out;
  for (const EvidenceRef& reference : binding.refs()) {
    out.append("  ");
    out.append(reference.source.view());
    out.push_back(' ');
    out.append(to_string(reference.kind));
    out.append(" generation=");
    out.append(unsigned_text(reference.generation.value()));
    out.append(" revision=");
    out.append(unsigned_text(reference.revision.value()));
    out.append(" epoch=");
    out.append(unsigned_text(reference.epoch.value()));
    out.append(" incarnation=");
    out.append(reference.incarnation.to_hex());
    out.append(" digest=");
    out.append(reference.content_digest.to_hex());
    out.push_back('\n');
  }
  if (binding.empty()) {
    out.append("  (no evidence is bound)\n");
  }
  return out;
}

Result<MutationRequest> build_request(const ControlPlane& plane, const ArgReader& reader,
                                      std::string_view default_key_seed) {
  auto snapshot = plane.snapshot();
  if (!snapshot.has_value()) {
    return snapshot.error();
  }
  MutationRequest request;
  request.planned.generation = snapshot.value().generation();
  request.planned.revision = snapshot.value().revision();
  request.planned.policy_revision = snapshot.value().policy_revision();
  request.planned.evidence_digest = snapshot.value().evidence().digest();
  const auto expected_generation = reader.value("expect-generation");
  if (expected_generation.has_value()) {
    request.planned.generation = ControlGeneration(std::stoull(expected_generation.value()));
  }
  const auto expected_revision = reader.value("expect-revision");
  if (expected_revision.has_value()) {
    request.planned.revision = StateRevision(std::stoull(expected_revision.value()));
  }
  const auto expected_policy = reader.value("expect-policy");
  if (expected_policy.has_value()) {
    request.planned.policy_revision = PolicyRevision(std::stoull(expected_policy.value()));
  }
  const auto expected_evidence = reader.value("expect-evidence");
  if (expected_evidence.has_value()) {
    auto digest = Digest::from_hex(expected_evidence.value());
    if (!digest.has_value()) {
      return digest.error();
    }
    request.planned.evidence_digest = digest.value();
  }
  const auto key = reader.value("key");
  if (key.has_value()) {
    auto parsed = IdempotencyKey::from_hex(key.value());
    if (!parsed.has_value()) {
      return parsed.error();
    }
    request.key = parsed.value();
  } else {
    auto derived = IdempotencyKey::derive(default_key_seed);
    if (!derived.has_value()) {
      return derived.error();
    }
    request.key = derived.value();
  }
  return request;
}

struct PlaneHandle {
  ControlPlane plane;
  std::optional<WriterLease> lease;
};

// Opens the store and, when required, takes writer authority.
//
// Supplying --evidence asserts that the named external evidence references are
// current. That assertion is a mutation - it is recorded as a revalidation - so the
// tool takes writer authority, publishes it, and then runs the verb with the
// asserted evidence in force for this process. Without it, every verb that depends on
// evidence freshness is refused, which is the fail-closed behaviour the library
// documents; the tool never invents freshness on the operator behalf.
Result<PlaneHandle> open_plane(const ArgReader& reader, bool need_writer) {
  const auto store = reader.value("store");
  if (!store.has_value()) {
    return Error(ErrorCode::invalid_argument, "--store <path> is required");
  }
  EngineOptions options;
  const auto retained = reader.value("retain");
  if (retained.has_value()) {
    options.retained_publications = static_cast<std::size_t>(std::stoull(retained.value()));
  }
  const std::vector<std::string> evidence_specs = reader.values("evidence");
  const bool assert_evidence = !evidence_specs.empty();
  const bool read_only = reader.has("read-only");
  if (read_only && (need_writer || assert_evidence)) {
    return Error(ErrorCode::invalid_argument,
                 "this verb mutates authoritative state and cannot run with --read-only");
  }
  auto plane = ControlPlane::open(store.value(),
                                  read_only ? StoreOpenMode::read_only
                                            : StoreOpenMode::read_write,
                                  options);
  if (!plane.has_value()) {
    return plane.error();
  }
  PlaneHandle handle;
  handle.plane = std::move(plane).value();
  if (need_writer || assert_evidence) {
    auto lease = handle.plane.acquire_writer();
    if (!lease.has_value()) {
      return lease.error();
    }
    handle.lease = lease.value();
  }
  // A store that has never been bootstrapped has no authoritative generation to
  // revalidate against, so the supplied evidence is left for the bootstrap verb to
  // publish as the facility initial binding.
  auto existing = handle.plane.snapshot();
  if (assert_evidence && existing.has_value()) {
    auto binding = parse_evidence_list(evidence_specs, handle.plane.limits());
    if (!binding.has_value()) {
      return binding.error();
    }
    auto request = build_request(handle.plane, reader, "cli/assert-evidence");
    if (!request.has_value()) {
      return request.error();
    }
    auto decision = handle.plane.revalidate(*handle.lease, binding.value(), request.value());
    if (!decision.has_value()) {
      return decision.error();
    }
    if (!decision_committed(decision.value().outcome)) {
      return Error(ErrorCode::denied_by_policy,
                   "the evidence assertion was refused by the control plane:\n" +
                       describe_decision(decision.value(), handle.plane.limits()));
    }
  }
  return handle;
}

int report_decision(const AuthorizationDecision& decision, const Limits& limits) {
  std::cout << describe_decision(decision, limits);
  return decision_committed(decision.outcome) ? kExitOk : kExitRefused;
}

int report_error(const Error& error) {
  print_error(error.describe());
  switch (error.code()) {
    case ErrorCode::invalid_argument:
    case ErrorCode::limit_exceeded:
    case ErrorCode::out_of_range:
    case ErrorCode::unsupported:
      return kExitUsage;
    default:
      break;
  }
  if (is_refusal(error.code())) {
    return kExitRefused;
  }
  return kExitStore;
}

void print_usage() {
  print_line("pcp " + std::string(kVersionString) + " - Power Control Plane administration");
  print_line("");
  print_line("usage: pcp --store <path> [--read-only] [--retain N] <verb> [options]");
  print_line("");
  print_line("inspection:");
  print_line("  version                     library and store format version");
  print_line("  state                       authoritative operating state summary");
  print_line("  mode                        current operating mode");
  print_line("  authority                   writer authority status");
  print_line("  interlocks                  recorded safety interlocks");
  print_line("  obligations                 protected obligations and capacity commitments");
  print_line("  permissions                 issued switching and control permissions");
  print_line("  attempts                    attempt lifecycle states");
  print_line("  evidence                    bound external evidence references");
  print_line("  revalidation                runtime evidence freshness");
  print_line("  history                     operating mode and publication history");
  print_line("  store                       durable store layout, head, and recovery report");
  print_line("  verify [--replay]           integrity check and deterministic replay");
  print_line("  policy                      ordered power policy rules");
  print_line("  policy-eval                 ordered rule trace for a proposed action");
  print_line("  evaluate                    full proposed-action evaluation (no mutation)");
  print_line("");
  print_line("administration (requires writer authority, taken automatically):");
  print_line("  init --facility <id> [--mode <mode>] [--evidence <spec>]...");
  print_line("  mode set <target> --authority <ref> [--suspend <obligation>:<authority>]...");
  print_line("  authority acquire | authority release");
  print_line("  revalidate --evidence <spec>...");
  print_line("  policy set --rule \"<order>|<effect>|<condition>|<argument>|<explanation>\" ...");
  print_line("  interlocks set <id> --source <src> --severity <s> --state <st>");
  print_line("                  [--kind <k>]... [--target <t>]... [--explain <text>]");
  print_line("  interlocks clear <id>");
  print_line("  obligations set <id> --source <src> --authority <ref> [--kind <k>]...");
  print_line("                  [--target <t>]... [--description <text>] [--no-continuity]");
  print_line("  obligations remove <id>");
  print_line("  commitments set <id> --source <src> --authority <ref> --kw <n> [--target <t>]...");
  print_line("  commitments remove <id>");
  print_line("  permissions grant --kind <k>... [--target <t>]... [--uses N]");
  print_line("                    [--generations N] [--revisions N] [--authority <ref>]");
  print_line("  permissions revoke <id> | permissions retire <id> <state>");
  print_line("  attempt --action <id> --kind <k> --target <t> [--load-kw N]");
  print_line("          [--adapter <behaviour>] [--verifier <behaviour>]");
  print_line("");
  print_line("common options:");
  print_line("  --evidence <spec>...        assert that this external evidence is current;");
  print_line("                              recorded as a revalidation before the verb runs");
  print_line("  --expect-generation N --expect-revision N --expect-policy N");
  print_line("  --expect-evidence <hex>     plan the request against specific authority");
  print_line("  --key <hex>                 explicit idempotency key (default: derived)");
  print_line("");
  print_line("evidence spec: source:kind:generation:revision:epoch:incarnation-hex:digest-hex");
}

std::string positional_or_empty(const ArgReader& reader, std::size_t index) {
  if (index < reader.positional().size()) {
    return reader.positional()[index];
  }
  return std::string();
}

int verb_version(const ArgReader& reader) {
  static_cast<void>(reader);
  print_line(std::string("power control plane ") + std::string(kVersionString));
  print_line("store format version: " + unsigned_text(kStoreFormatVersion));
  print_line("state encoding version: " + unsigned_text(kStateFormatVersion));
  return kExitOk;
}

int verb_state(const ArgReader& reader) {
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto status = handle.value().plane.status();
  if (!status.has_value()) {
    return report_error(status.error());
  }
  const ControlPlaneStatus& value = status.value();
  print_line("facility: " + value.facility.value());
  print_line("store incarnation: " + value.incarnation.to_hex());
  print_line("authoritative generation: " +
             (value.authoritative_generation_present ? unsigned_text(value.generation.value())
                                                     : std::string("none")));
  print_line("publication revision: " + unsigned_text(value.revision.value()));
  print_line("policy revision: " + unsigned_text(value.policy_revision.value()));
  print_line("logical tick: " + unsigned_text(value.tick.value()));
  print_line("operating mode: " + std::string(to_string(value.mode)));
  print_line("state digest: " + value.state_digest.to_hex());
  print_line("evidence digest: " + value.evidence_digest.to_hex());
  print_line("interlocks: " + unsigned_text(value.interlock_count) + " (" +
             unsigned_text(value.blocking_interlock_count) + " blocking)");
  print_line("protected obligations: " + unsigned_text(value.obligation_count) + " (" +
             unsigned_text(value.unserved_obligation_count) + " active continuity-required)");
  print_line("capacity commitments: " + unsigned_text(value.commitment_count));
  print_line("active permissions: " + unsigned_text(value.active_permission_count));
  print_line("attempts: " + unsigned_text(value.attempt_count) + " (" +
             unsigned_text(value.open_attempt_count) + " open)");
  print_line("evidence fresh in this incarnation: " +
             std::string(value.revalidation.evidence_fresh ? "yes" : "no"));
  return kExitOk;
}

int verb_mode(const ArgReader& reader) {
  const std::string sub = positional_or_empty(reader, 0);
  if (sub != "set") {
    auto handle = open_plane(reader, false);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    auto snapshot = handle.value().plane.snapshot();
    if (!snapshot.has_value()) {
      return report_error(snapshot.error());
    }
    print_line(std::string(to_string(snapshot.value().mode())));
    return kExitOk;
  }
  auto handle = open_plane(reader, true);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  const std::string target_text = positional_or_empty(reader, 1);
  auto target = parse_mode(target_text);
  if (!target.has_value()) {
    print_error("mode set requires an operating mode: normal, maintenance, degraded, "
                "failover, emergency, isolated");
    return kExitUsage;
  }
  auto authority = AuthorityReference::parse(reader.value("authority").value_or("operator"));
  if (!authority.has_value()) {
    return report_error(authority.error());
  }
  ModeTransitionRequest request;
  request.target = target.value();
  request.authority = authority.value();
  for (const std::string& suspension : reader.values("suspend")) {
    const std::size_t separator = suspension.find(':');
    if (separator == std::string::npos) {
      print_error("--suspend expects <obligation-id>:<authority-reference>");
      return kExitUsage;
    }
    auto obligation = ObligationId::parse(suspension.substr(0, separator));
    if (!obligation.has_value()) {
      return report_error(obligation.error());
    }
    auto reference = AuthorityReference::parse(suspension.substr(separator + 1));
    if (!reference.has_value()) {
      return report_error(reference.error());
    }
    auto current = handle.value().plane.snapshot();
    if (!current.has_value()) {
      return report_error(current.error());
    }
    ObligationSuspension entry;
    entry.obligation = obligation.value();
    entry.record.authority = reference.value();
    entry.record.generation = current.value().generation();
    entry.record.tick = current.value().tick();
    entry.record.reason = "suspended by operator request";
    request.suspensions.push_back(std::move(entry));
  }
  auto built = build_request(handle.value().plane, reader, "mode-set/" + target_text);
  if (!built.has_value()) {
    return report_error(built.error());
  }
  request.planned = built.value().planned;
  request.key = built.value().key;
  auto decision = handle.value().plane.request_mode_transition(*handle.value().lease, request);
  if (!decision.has_value()) {
    return report_error(decision.error());
  }
  return report_decision(decision.value(), handle.value().plane.limits());
}

int verb_authority(const ArgReader& reader) {
  const std::string sub = positional_or_empty(reader, 0);
  if (sub == "acquire") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    print_line("writer authority acquired at epoch " +
               unsigned_text(handle.value().lease->epoch().value()) + " incarnation " +
               handle.value().lease->incarnation().to_hex());
    return kExitOk;
  }
  if (sub == "release") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    const Status released = handle.value().plane.release_writer(*handle.value().lease);
    if (!released.ok()) {
      return report_error(released.error());
    }
    print_line("writer authority released");
    return kExitOk;
  }
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  const WriterStatus writer = handle.value().plane.store().writer_status();
  print_line(std::string("writer authority held by this process: ") +
             (writer.held_by_this_store ? "yes" : "no"));
  print_line("controller epoch: " + unsigned_text(writer.epoch.value()));
  print_line("controller incarnation: " + writer.incarnation.to_hex());
  print_line("writer lock contended: " + std::string(writer.lock_contended ? "yes" : "no"));
  print_line("store incarnation: " + handle.value().plane.store().incarnation().to_hex());
  return kExitOk;
}

int verb_interlocks(const ArgReader& reader) {
  const std::string sub = positional_or_empty(reader, 0);
  if (sub == "set") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    Interlock interlock;
    auto id = InterlockId::parse(positional_or_empty(reader, 1));
    if (!id.has_value()) {
      return report_error(id.error());
    }
    interlock.id = id.value();
    auto source = EvidenceSourceId::parse(reader.value("source").value_or("operator"));
    if (!source.has_value()) {
      return report_error(source.error());
    }
    interlock.source = source.value();
    auto severity = parse_interlock_severity(reader.value("severity").value_or("blocking"));
    if (!severity.has_value()) {
      return report_error(severity.error());
    }
    interlock.severity = severity.value();
    auto state = parse_interlock_state(reader.value("state").value_or("engaged"));
    if (!state.has_value()) {
      return report_error(state.error());
    }
    interlock.state = state.value();
    for (const std::string& kind : reader.values("kind")) {
      auto parsed = parse_action_kind(kind);
      if (!parsed.has_value()) {
        return report_error(parsed.error());
      }
      interlock.scope_kinds.push_back(parsed.value());
    }
    for (const std::string& target : reader.values("target")) {
      auto parsed = ActionTargetId::parse(target);
      if (!parsed.has_value()) {
        return report_error(parsed.error());
      }
      interlock.scope_targets.push_back(parsed.value());
    }
    interlock.explanation = reader.value("explain").value_or("recorded by the operator");
    auto current_state = handle.value().plane.snapshot();
    if (!current_state.has_value()) {
      return report_error(current_state.error());
    }
    interlock.declared_generation = current_state.value().generation();
    auto built = build_request(handle.value().plane, reader, "interlock-set/" + interlock.id.view());
    if (!built.has_value()) {
      return report_error(built.error());
    }
    auto decision = handle.value().plane.record_interlock(*handle.value().lease, interlock,
                                                          built.value());
    if (!decision.has_value()) {
      return report_error(decision.error());
    }
    return report_decision(decision.value(), handle.value().plane.limits());
  }
  if (sub == "clear") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    auto id = InterlockId::parse(positional_or_empty(reader, 1));
    if (!id.has_value()) {
      return report_error(id.error());
    }
    auto built = build_request(handle.value().plane, reader, "interlock-clear/" + id.value().view());
    if (!built.has_value()) {
      return report_error(built.error());
    }
    auto decision =
        handle.value().plane.remove_interlock(*handle.value().lease, id.value(), built.value());
    if (!decision.has_value()) {
      return report_error(decision.error());
    }
    return report_decision(decision.value(), handle.value().plane.limits());
  }
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto snapshot = handle.value().plane.snapshot();
  if (!snapshot.has_value()) {
    return report_error(snapshot.error());
  }
  if (snapshot.value().interlocks().empty()) {
    print_line("(no interlocks are recorded)");
    return kExitOk;
  }
  for (const Interlock& interlock : snapshot.value().interlocks()) {
    print_line(interlock.id.view() + " source=" + interlock.source.view() + " severity=" +
               std::string(to_string(interlock.severity)) + " state=" +
               std::string(to_string(interlock.state)) + " declared_generation=" +
               unsigned_text(interlock.declared_generation.value()) + " updated_generation=" +
               unsigned_text(interlock.updated_generation.value()));
    print_line("  explanation: " + interlock.explanation);
    print_line("  blocks in scope: " + std::string(interlock_blocks(interlock,
                                                                    ActionKind::open_breaker,
                                                                    ActionTargetId{})
                                                       ? "yes"
                                                       : "no"));
  }
  return kExitOk;
}

int verb_obligations(const ArgReader& reader) {
  const std::string sub = positional_or_empty(reader, 0);
  if (sub == "set") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    ProtectedObligation obligation;
    auto id = ObligationId::parse(positional_or_empty(reader, 1));
    if (!id.has_value()) {
      return report_error(id.error());
    }
    obligation.id = id.value();
    auto source = EvidenceSourceId::parse(reader.value("source").value_or("operator"));
    if (!source.has_value()) {
      return report_error(source.error());
    }
    obligation.authority_source = source.value();
    auto authority = AuthorityReference::parse(reader.value("authority").value_or("operator"));
    if (!authority.has_value()) {
      return report_error(authority.error());
    }
    obligation.authority_reference = authority.value();
    obligation.continuity_required = !reader.has("no-continuity");
    obligation.description = reader.value("description").value_or("protected obligation");
    for (const std::string& kind : reader.values("kind")) {
      auto parsed = parse_action_kind(kind);
      if (!parsed.has_value()) {
        return report_error(parsed.error());
      }
      obligation.scope_kinds.push_back(parsed.value());
    }
    for (const std::string& target : reader.values("target")) {
      auto parsed = ActionTargetId::parse(target);
      if (!parsed.has_value()) {
        return report_error(parsed.error());
      }
      obligation.scope_targets.push_back(parsed.value());
    }
    auto built =
        build_request(handle.value().plane, reader, "obligation-set/" + obligation.id.view());
    if (!built.has_value()) {
      return report_error(built.error());
    }
    auto decision = handle.value().plane.record_obligation(*handle.value().lease, obligation,
                                                           built.value());
    if (!decision.has_value()) {
      return report_error(decision.error());
    }
    return report_decision(decision.value(), handle.value().plane.limits());
  }
  if (sub == "remove") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    auto id = ObligationId::parse(positional_or_empty(reader, 1));
    if (!id.has_value()) {
      return report_error(id.error());
    }
    auto built =
        build_request(handle.value().plane, reader, "obligation-remove/" + id.value().view());
    if (!built.has_value()) {
      return report_error(built.error());
    }
    auto decision = handle.value().plane.remove_obligation(*handle.value().lease, id.value(),
                                                           built.value());
    if (!decision.has_value()) {
      return report_error(decision.error());
    }
    return report_decision(decision.value(), handle.value().plane.limits());
  }
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto snapshot = handle.value().plane.snapshot();
  if (!snapshot.has_value()) {
    return report_error(snapshot.error());
  }
  if (snapshot.value().obligations().empty() && snapshot.value().commitments().empty()) {
    print_line("(no protected obligations or capacity commitments are recorded)");
    return kExitOk;
  }
  for (const ProtectedObligation& obligation : snapshot.value().obligations()) {
    print_line("obligation " + obligation.id.view() + " state=" +
               std::string(to_string(obligation.state)) + " authority=" +
               obligation.authority_reference.view() + " continuity_required=" +
               (obligation.continuity_required ? "yes" : "no"));
    print_line("  description: " + obligation.description);
    if (obligation.suspension.has_value()) {
      print_line("  suspended by: " + obligation.suspension->authority.view() + " at generation " +
                 unsigned_text(obligation.suspension->generation.value()));
    }
  }
  for (const CapacityCommitment& commitment : snapshot.value().commitments()) {
    print_line("commitment " + commitment.id.view() + " kw=" +
               unsigned_text(commitment.committed_kw) + " active=" +
               (commitment.active ? "yes" : "no") + " authority=" +
               commitment.authority_reference.view());
  }
  return kExitOk;
}

int verb_commitments(const ArgReader& reader) {
  const std::string sub = positional_or_empty(reader, 0);
  if (sub == "set") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    CapacityCommitment commitment;
    auto id = CapacityCommitmentId::parse(positional_or_empty(reader, 1));
    if (!id.has_value()) {
      return report_error(id.error());
    }
    commitment.id = id.value();
    auto source = EvidenceSourceId::parse(reader.value("source").value_or("operator"));
    if (!source.has_value()) {
      return report_error(source.error());
    }
    commitment.source = source.value();
    auto authority = AuthorityReference::parse(reader.value("authority").value_or("operator"));
    if (!authority.has_value()) {
      return report_error(authority.error());
    }
    commitment.authority_reference = authority.value();
    const auto kilowatts = reader.value("kw");
    if (!kilowatts.has_value()) {
      print_error("commitments set requires --kw <kilowatts>");
      return kExitUsage;
    }
    commitment.committed_kw = std::stoull(kilowatts.value());
    commitment.active = !reader.has("retired");
    for (const std::string& target : reader.values("target")) {
      auto parsed = ActionTargetId::parse(target);
      if (!parsed.has_value()) {
        return report_error(parsed.error());
      }
      commitment.targets.push_back(parsed.value());
    }
    commitment.evidence.source = commitment.source;
    commitment.evidence.kind = EvidenceKind::power_capacity;
    commitment.evidence.generation =
        EvidenceGeneration(std::stoull(reader.value("evidence-generation").value_or("1")));
    commitment.evidence.revision =
        EvidenceRevision(std::stoull(reader.value("evidence-revision").value_or("1")));
    commitment.evidence.incarnation = ControllerIncarnation::generate();
    commitment.evidence.content_digest =
        sha256_domain("pcp/cli-commitment/v1", commitment.id.view());
    auto built =
        build_request(handle.value().plane, reader, "commitment-set/" + commitment.id.view());
    if (!built.has_value()) {
      return report_error(built.error());
    }
    auto decision = handle.value().plane.record_commitment(*handle.value().lease, commitment,
                                                           built.value());
    if (!decision.has_value()) {
      return report_error(decision.error());
    }
    return report_decision(decision.value(), handle.value().plane.limits());
  }
  if (sub == "remove") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    auto id = CapacityCommitmentId::parse(positional_or_empty(reader, 1));
    if (!id.has_value()) {
      return report_error(id.error());
    }
    auto built =
        build_request(handle.value().plane, reader, "commitment-remove/" + id.value().view());
    if (!built.has_value()) {
      return report_error(built.error());
    }
    auto decision = handle.value().plane.remove_commitment(*handle.value().lease, id.value(),
                                                           built.value());
    if (!decision.has_value()) {
      return report_error(decision.error());
    }
    return report_decision(decision.value(), handle.value().plane.limits());
  }
  return verb_obligations(reader);
}

int verb_permissions(const ArgReader& reader) {
  const std::string sub = positional_or_empty(reader, 0);
  if (sub == "grant") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    PermissionGrant grant;
    for (const std::string& kind : reader.values("kind")) {
      auto parsed = parse_action_kind(kind);
      if (!parsed.has_value()) {
        return report_error(parsed.error());
      }
      grant.kinds.push_back(parsed.value());
    }
    if (grant.kinds.empty()) {
      print_error("permissions grant requires at least one --kind");
      return kExitUsage;
    }
    for (const std::string& target : reader.values("target")) {
      auto parsed = ActionTargetId::parse(target);
      if (!parsed.has_value()) {
        return report_error(parsed.error());
      }
      grant.targets.push_back(parsed.value());
    }
    auto authority = AuthorityReference::parse(reader.value("authority").value_or("operator"));
    if (!authority.has_value()) {
      return report_error(authority.error());
    }
    grant.granted_by = authority.value();
    grant.max_uses = static_cast<std::uint32_t>(
        std::stoull(reader.value("uses").value_or("1")));
    const std::uint64_t generations =
        std::stoull(reader.value("generations").value_or("8"));
    const std::uint64_t revisions = std::stoull(reader.value("revisions").value_or("64"));
    grant.expiry_generation = ControlGeneration(generations);
    grant.expiry_revision = StateRevision(revisions);
    auto built = build_request(handle.value().plane, reader, "permission-grant");
    if (!built.has_value()) {
      return report_error(built.error());
    }
    // Expiry is relative to the authority the grant was planned against.
    auto snapshot = handle.value().plane.snapshot();
    if (!snapshot.has_value()) {
      return report_error(snapshot.error());
    }
    grant.issued_generation = built.value().planned.generation;
    grant.issued_revision = built.value().planned.revision;
    auto expiry_generation =
        checked_add(grant.issued_generation.value(), generations);
    if (!expiry_generation.has_value()) {
      return report_error(expiry_generation.error());
    }
    grant.expiry_generation = ControlGeneration(expiry_generation.value());
    auto expiry_revision = checked_add(grant.issued_revision.value(), revisions);
    if (!expiry_revision.has_value()) {
      return report_error(expiry_revision.error());
    }
    grant.expiry_revision = StateRevision(expiry_revision.value());
    grant.policy_revision = built.value().planned.policy_revision;
    grant.evidence = snapshot.value().evidence();
    auto decision =
        handle.value().plane.grant_permission(*handle.value().lease, grant, built.value());
    if (!decision.has_value()) {
      return report_error(decision.error());
    }
    return report_decision(decision.value(), handle.value().plane.limits());
  }
  if (sub == "revoke" || sub == "retire") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    auto id = PermissionId(std::stoull(positional_or_empty(reader, 1)));
    PermissionState state = PermissionState::revoked;
    if (sub == "retire") {
      auto parsed = parse_permission_state(positional_or_empty(reader, 2));
      if (!parsed.has_value()) {
        return report_error(parsed.error());
      }
      state = parsed.value();
    }
    auto built = build_request(handle.value().plane, reader,
                               "permission-retire/" + unsigned_text(id.value()));
    if (!built.has_value()) {
      return report_error(built.error());
    }
    auto decision = handle.value().plane.retire_permission(*handle.value().lease, id, state,
                                                           built.value());
    if (!decision.has_value()) {
      return report_error(decision.error());
    }
    return report_decision(decision.value(), handle.value().plane.limits());
  }
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto snapshot = handle.value().plane.snapshot();
  if (!snapshot.has_value()) {
    return report_error(snapshot.error());
  }
  if (snapshot.value().permissions().empty()) {
    print_line("(no permissions are recorded)");
    return kExitOk;
  }
  for (const PermissionGrant& grant : snapshot.value().permissions()) {
    print_line("permission " + unsigned_text(grant.id.value()) + " state=" +
               std::string(to_string(grant.state)) + " uses=" + unsigned_text(grant.uses) + "/" +
               unsigned_text(grant.max_uses));
    print_line("  issued_generation=" + unsigned_text(grant.issued_generation.value()) +
               " expiry_generation=" + unsigned_text(grant.expiry_generation.value()) +
               " issued_revision=" + unsigned_text(grant.issued_revision.value()) +
               " expiry_revision=" + unsigned_text(grant.expiry_revision.value()));
    print_line("  policy_revision=" + unsigned_text(grant.policy_revision.value()) +
               " evidence=" + grant.evidence.digest().to_hex());
    std::string kinds;
    for (const ActionKind kind : grant.kinds) {
      kinds.append(to_string(kind));
      kinds.push_back(' ');
    }
    print_line("  kinds: " + kinds);
  }
  return kExitOk;
}

int verb_attempts(const ArgReader& reader) {
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto snapshot = handle.value().plane.snapshot();
  if (!snapshot.has_value()) {
    return report_error(snapshot.error());
  }
  if (snapshot.value().attempts().empty()) {
    print_line("(no attempts are recorded)");
    return kExitOk;
  }
  for (const AttemptRecord& attempt : snapshot.value().attempts()) {
    print_line("attempt " + unsigned_text(attempt.id.value()) + " action=" +
               attempt.intent.id.view() + " target=" + attempt.intent.target.view() +
               " kind=" + std::string(to_string(attempt.intent.kind)));
    print_line("  state=" + std::string(to_string(attempt.state)) + " authorized_generation=" +
               unsigned_text(attempt.authorized_generation.value()) +
               " authorized_revision=" + unsigned_text(attempt.authorized_revision.value()) +
               " updated_revision=" + unsigned_text(attempt.updated_revision.value()));
    print_line(std::string("  authorization=") +
               (attempt.state == AttemptState::refused ? "refused" : "granted") +
               " acknowledged=" + (attempt.acknowledgement.has_value() ? "yes" : "no") +
               " effect_observed=" + (attempt.effect.has_value() ? "yes" : "no") +
               " verified=" +
               (attempt.verification.has_value() && attempt.verification->matches_intent ? "yes"
                                                                                         : "no"));
    if (attempt.acknowledgement.has_value()) {
      print_line("  acknowledged by " + attempt.acknowledgement->adapter.view() + ": " +
                 attempt.acknowledgement->detail);
    }
    if (attempt.verification.has_value()) {
      print_line("  verified by " + attempt.verification->verifier.view() + ": " +
                 attempt.verification->detail);
    }
  }
  return kExitOk;
}

int verb_evidence(const ArgReader& reader) {
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto snapshot = handle.value().plane.snapshot();
  if (!snapshot.has_value()) {
    return report_error(snapshot.error());
  }
  std::cout << describe_evidence(snapshot.value().evidence());
  print_line("binding digest: " + snapshot.value().evidence().digest().to_hex());
  return kExitOk;
}

int verb_revalidation(const ArgReader& reader) {
  const std::string sub = positional_or_empty(reader, 0);
  if (sub == "run" || reader.has("evidence")) {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    auto binding = parse_evidence_list(reader.values("evidence"),
                                       handle.value().plane.limits());
    if (!binding.has_value()) {
      return report_error(binding.error());
    }
    auto built = build_request(handle.value().plane, reader, "revalidate");
    if (!built.has_value()) {
      return report_error(built.error());
    }
    auto decision =
        handle.value().plane.revalidate(*handle.value().lease, binding.value(), built.value());
    if (!decision.has_value()) {
      return report_error(decision.error());
    }
    return report_decision(decision.value(), handle.value().plane.limits());
  }
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  const RevalidationReport report = handle.value().plane.revalidation_status();
  print_line("evidence fresh: " + std::string(report.evidence_fresh ? "yes" : "no"));
  print_line("revalidated in this incarnation: " +
             std::string(report.revalidated_in_this_incarnation ? "yes" : "no"));
  print_line("bound digest: " + report.bound_digest.to_hex());
  print_line("fresh digest: " + report.fresh_digest.to_hex());
  print_line("revalidated generation: " + unsigned_text(report.revalidated_generation.value()));
  print_line("revalidated revision: " + unsigned_text(report.revalidated_revision.value()));
  print_line("detail: " + report.detail);
  return kExitOk;
}

Result<PolicyCondition> build_condition(std::string_view condition, std::string_view argument) {
  PolicyCondition built;
  if (condition == "always") {
    built.kind = PolicyConditionKind::always;
    return built;
  }
  if (condition == "mode") {
    auto mode = parse_mode(argument);
    if (!mode.has_value()) {
      return mode.error();
    }
    built.kind = PolicyConditionKind::mode_is;
    built.mode = mode.value();
    return built;
  }
  if (condition == "kind") {
    auto kind = parse_action_kind(argument);
    if (!kind.has_value()) {
      return kind.error();
    }
    built.kind = PolicyConditionKind::action_kind_is;
    built.action_kind = kind.value();
    return built;
  }
  if (condition == "target") {
    auto target = ActionTargetId::parse(argument);
    if (!target.has_value()) {
      return target.error();
    }
    built.kind = PolicyConditionKind::target_is;
    built.target = target.value();
    return built;
  }
  if (condition == "interlock") {
    auto state = parse_interlock_state(argument);
    if (!state.has_value()) {
      return state.error();
    }
    built.kind = PolicyConditionKind::interlock_state_is;
    built.interlock_state = state.value();
    return built;
  }
  if (condition == "obligation") {
    auto state = parse_obligation_state(argument);
    if (!state.has_value()) {
      return state.error();
    }
    built.kind = PolicyConditionKind::obligation_state_is;
    built.obligation_state = state.value();
    return built;
  }
  if (condition == "evidence") {
    auto source = EvidenceSourceId::parse(argument);
    if (!source.has_value()) {
      return source.error();
    }
    built.kind = PolicyConditionKind::evidence_source_present;
    built.evidence_source = source.value();
    return built;
  }
  if (condition == "load") {
    built.kind = PolicyConditionKind::requested_load_at_least;
    built.threshold_kw = std::stoull(std::string(argument));
    return built;
  }
  return Error(ErrorCode::invalid_argument,
               "unknown policy condition; expected always, mode, kind, target, interlock, "
               "obligation, evidence, or load");
}

int verb_policy(const ArgReader& reader) {
  const std::string sub = positional_or_empty(reader, 0);
  if (sub == "set") {
    auto handle = open_plane(reader, true);
    if (!handle.has_value()) {
      return report_error(handle.error());
    }
    std::vector<PolicyRule> rules;
    std::size_t index = 0;
    for (const std::string& text : reader.values("rule")) {
      std::vector<std::string> parts;
      std::size_t start = 0;
      for (std::size_t position = 0; position <= text.size(); ++position) {
        if (position == text.size() || text[position] == '|') {
          parts.push_back(text.substr(start, position - start));
          start = position + 1;
        }
      }
      if (parts.size() != 5) {
        print_error("--rule expects \"<order>|<effect>|<condition>|<argument>|<explanation>\"");
        return kExitUsage;
      }
      ++index;
      PolicyRule rule;
      auto id = RuleId::parse("rule-" + unsigned_text(index));
      if (!id.has_value()) {
        return report_error(id.error());
      }
      rule.id = id.value();
      rule.order = static_cast<std::uint32_t>(std::stoull(parts[0]));
      auto effect = parse_policy_effect(parts[1]);
      if (!effect.has_value()) {
        return report_error(effect.error());
      }
      rule.effect = effect.value();
      auto condition = build_condition(parts[2], parts[3]);
      if (!condition.has_value()) {
        return report_error(condition.error());
      }
      rule.condition = condition.value();
      rule.explanation = parts[4];
      rules.push_back(std::move(rule));
    }
    auto snapshot = handle.value().plane.snapshot();
    if (!snapshot.has_value()) {
      return report_error(snapshot.error());
    }
    auto revision = checked_increment(snapshot.value().policy_revision().value());
    if (!revision.has_value()) {
      return report_error(revision.error());
    }
    auto policy = PowerPolicy::create(PolicyRevision(revision.value()), std::move(rules),
                                      handle.value().plane.limits());
    if (!policy.has_value()) {
      return report_error(policy.error());
    }
    auto built = build_request(handle.value().plane, reader, "policy-set");
    if (!built.has_value()) {
      return report_error(built.error());
    }
    auto decision =
        handle.value().plane.rebind_policy(*handle.value().lease, policy.value(), built.value());
    if (!decision.has_value()) {
      return report_error(decision.error());
    }
    return report_decision(decision.value(), handle.value().plane.limits());
  }
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto snapshot = handle.value().plane.snapshot();
  if (!snapshot.has_value()) {
    return report_error(snapshot.error());
  }
  print_line("policy revision: " + unsigned_text(snapshot.value().policy_revision().value()));
  print_line("policy digest: " + snapshot.value().policy().digest().to_hex());
  if (snapshot.value().policy().empty()) {
    print_line("(no policy rules are installed; every action is refused by default)");
    return kExitOk;
  }
  for (const PolicyRule& rule : snapshot.value().policy().rules()) {
    print_line("  order=" + unsigned_text(rule.order) + " " + rule.id.view() + " effect=" +
               std::string(to_string(rule.effect)) + " condition=" +
               std::string(to_string(rule.condition.kind)) + " | " + rule.explanation);
  }
  return kExitOk;
}

Result<ActionIntent> build_intent(const ControlPlane& plane, const ArgReader& reader,
                                  std::string_view default_key_seed) {
  static_cast<void>(default_key_seed);
  auto snapshot = plane.snapshot();
  if (!snapshot.has_value()) {
    return snapshot.error();
  }
  ActionIntent intent;
  std::string action = reader.value("action").value_or("action");
  auto id = ActionId::parse(action);
  if (!id.has_value()) {
    return id.error();
  }
  intent.id = id.value();
  const auto kind_text = reader.value("kind");
  if (!kind_text.has_value()) {
    return Error(ErrorCode::invalid_argument, "--kind <action-kind> is required");
  }
  auto kind = parse_action_kind(kind_text.value());
  if (!kind.has_value()) {
    return kind.error();
  }
  intent.kind = kind.value();
  const auto target_text = reader.value("target");
  if (!target_text.has_value()) {
    intent.target = ActionTargetId::parse("facility").value();
  } else {
    auto target = ActionTargetId::parse(target_text.value());
    if (!target.has_value()) {
      return target.error();
    }
    intent.target = target.value();
  }
  const auto load = reader.value("load-kw");
  if (load.has_value()) {
    intent.requested_load_kw = std::stoull(load.value());
  }
  intent.planned.generation = snapshot.value().generation();
  intent.planned.revision = snapshot.value().revision();
  intent.planned.policy_revision = snapshot.value().policy_revision();
  intent.planned.evidence_digest = snapshot.value().evidence().digest();
  const auto expected_generation = reader.value("expect-generation");
  if (expected_generation.has_value()) {
    intent.planned.generation = ControlGeneration(std::stoull(expected_generation.value()));
  }
  const auto expected_revision = reader.value("expect-revision");
  if (expected_revision.has_value()) {
    intent.planned.revision = StateRevision(std::stoull(expected_revision.value()));
  }
  const auto expected_policy = reader.value("expect-policy");
  if (expected_policy.has_value()) {
    intent.planned.policy_revision = PolicyRevision(std::stoull(expected_policy.value()));
  }
  const auto expected_evidence = reader.value("expect-evidence");
  if (expected_evidence.has_value()) {
    auto digest = Digest::from_hex(expected_evidence.value());
    if (!digest.has_value()) {
      return digest.error();
    }
    intent.planned.evidence_digest = digest.value();
  }
  return intent;
}

int verb_evaluate(const ArgReader& reader) {
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto intent = build_intent(handle.value().plane, reader, "evaluate");
  if (!intent.has_value()) {
    return report_error(intent.error());
  }
  auto decision = handle.value().plane.evaluate_action(intent.value());
  if (!decision.has_value()) {
    return report_error(decision.error());
  }
  return report_decision(decision.value(), handle.value().plane.limits());
}

int verb_policy_eval(const ArgReader& reader) {
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto intent = build_intent(handle.value().plane, reader, "policy-eval");
  if (!intent.has_value()) {
    return report_error(intent.error());
  }
  auto evaluation = handle.value().plane.evaluate_policy(intent.value());
  if (!evaluation.has_value()) {
    return report_error(evaluation.error());
  }
  print_line("policy revision: " + unsigned_text(evaluation.value().revision.value()));
  print_line("outcome: " + std::string(to_string(evaluation.value().outcome)));
  for (const PolicyRuleTrace& trace : evaluation.value().trace) {
    print_line("  order=" + unsigned_text(trace.order) + " " + trace.rule.view() +
               (trace.matched ? " MATCH " : " skip  ") +
               std::string(to_string(trace.effect)) + " | " + trace.explanation);
  }
  return kExitOk;
}

int verb_attempt(const ArgReader& reader) {
  auto handle = open_plane(reader, true);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto intent = build_intent(handle.value().plane, reader, "attempt");
  if (!intent.has_value()) {
    return report_error(intent.error());
  }
  auto built = build_request(handle.value().plane, reader,
                             "attempt/" + intent.value().id.view());
  if (!built.has_value()) {
    return report_error(built.error());
  }
  auto behaviour = parse_simulation_behaviour(reader.value("adapter").value_or("full_success"));
  if (!behaviour.has_value()) {
    return report_error(behaviour.error());
  }
  auto verifier_behaviour =
      parse_simulation_behaviour(reader.value("verifier").value_or("full_success"));
  if (!verifier_behaviour.has_value()) {
    return report_error(verifier_behaviour.error());
  }
  auto adapter_id = AdapterId::parse(reader.value("adapter-id").value_or("adapter-a"));
  if (!adapter_id.has_value()) {
    return report_error(adapter_id.error());
  }
  auto verifier_id = AdapterId::parse(reader.value("verifier-id").value_or("verifier-b"));
  if (!verifier_id.has_value()) {
    return report_error(verifier_id.error());
  }
  SimulationAdapter adapter(adapter_id.value(), behaviour.value());
  SimulationAdapter verifier(verifier_id.value(), verifier_behaviour.value());
  // The verifying adapter observes through the same scripted behaviour; the engine
  // still requires the verifier identity to differ from the acknowledging adapter.
  ActuationOutcome outcome;
  auto decision = handle.value().plane.actuate(*handle.value().lease, intent.value(),
                                               built.value(), adapter, outcome);
  if (!decision.has_value()) {
    return report_error(decision.error());
  }
  const int code = report_decision(decision.value(), handle.value().plane.limits());
  static_cast<void>(verifier);
  print_line("actuation: authorized=" +
             std::string(decision_committed(decision.value().outcome) ? "yes" : "no") +
             " command_issued=" + (outcome.command_issued ? "yes" : "no") +
             " acknowledged=" + (outcome.acknowledged ? "yes" : "no") +
             " effect_observed=" + (outcome.effect_observed ? "yes" : "no") +
             " verified=" + (outcome.verified ? "yes" : "no"));
  print_line("final attempt state: " + std::string(to_string(outcome.final_state)));
  if (!outcome.detail.empty()) {
    print_line("detail: " + outcome.detail);
  }
  print_line("adapter evidence is SYNTHETIC: it is produced by a deterministic simulator and "
             "is not hardware validation");
  return code;
}

int verb_history(const ArgReader& reader) {
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto snapshot = handle.value().plane.snapshot();
  if (!snapshot.has_value()) {
    return report_error(snapshot.error());
  }
  print_line("operating mode history:");
  if (snapshot.value().mode_history().empty()) {
    print_line("  (no mode transitions are recorded)");
  }
  for (const ModeHistoryEntry& entry : snapshot.value().mode_history()) {
    print_line("  generation=" + unsigned_text(entry.generation.value()) + " " +
               std::string(to_string(entry.from)) + " -> " + std::string(to_string(entry.to)) +
               " authority=" + entry.authority.view() + " tick=" +
               unsigned_text(entry.tick.value()));
  }
  print_line("publication history:");
  for (const TransitionLogEntry& entry : snapshot.value().transition_log()) {
    print_line("  revision=" + unsigned_text(entry.revision.value()) + " generation=" +
               unsigned_text(entry.generation.value()) + " kind=" +
               std::string(to_string(entry.kind)) + " payload_bytes=" +
               unsigned_text(entry.payload.size()) + " previous_digest=" +
               entry.previous_state_digest.to_hex().substr(0, 16));
  }
  return kExitOk;
}

int verb_store(const ArgReader& reader) {
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  const DurableStore& store = handle.value().plane.store();
  const StoreHead head = store.head();
  print_line("store root: " + store.root());
  print_line("store incarnation: " + store.incarnation().to_hex());
  print_line("head present: " + std::string(head.present ? "yes" : "no"));
  if (head.present) {
    print_line("head generation: " + unsigned_text(head.generation.value()));
    print_line("head revision: " + unsigned_text(head.revision.value()));
    print_line("head state file: " + head.state_file);
    print_line("head payload bytes: " + unsigned_text(head.payload_bytes));
    print_line("head payload digest: " + head.payload_digest.to_hex());
  }
  std::string publications;
  for (const StateRevision revision : store.retained_publications()) {
    publications.append(unsigned_text(revision.value()));
    publications.push_back(' ');
  }
  print_line("retained publications: " + publications);
  const StoreOpenReport& report = store.open_report();
  print_line(std::string("created: ") + (report.created ? "yes" : "no") +
             " recovered: " + (report.recovered ? "yes" : "no") +
             " rollback_detected: " + (report.rollback_detected ? "yes" : "no"));
  print_line("retired staging files: " + unsigned_text(report.retired_staging_files) +
             " retired orphan generations: " + unsigned_text(report.retired_orphan_states) +
             " retired old publications: " + unsigned_text(report.retired_old_publications));
  print_line("recovery detail: " + report.detail);
  const WriterStatus writer = store.writer_status();
  print_line("writer epoch: " + unsigned_text(writer.epoch.value()) +
             " lock contended: " + (writer.lock_contended ? "yes" : "no"));
  return kExitOk;
}

int verb_verify(const ArgReader& reader) {
  auto handle = open_plane(reader, false);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  auto integrity = handle.value().plane.verify_store();
  if (!integrity.has_value()) {
    return report_error(integrity.error());
  }
  const StoreIntegrityReport& report = integrity.value();
  print_line("integrity ok: " + std::string(report.ok ? "yes" : "no"));
  print_line("head present: " + std::string(report.head_present ? "yes" : "no") +
             " head checksum ok: " + (report.head_checksum_ok ? "yes" : "no"));
  print_line("payload present: " + std::string(report.payload_present ? "yes" : "no") +
             " payload checksum ok: " + (report.payload_checksum_ok ? "yes" : "no") +
             " head matches payload: " + (report.head_matches_payload ? "yes" : "no"));
  print_line("authority present: " + std::string(report.authority_present ? "yes" : "no") +
             " authority checksum ok: " + (report.authority_checksum_ok ? "yes" : "no"));
  print_line("rollback detected: " + std::string(report.rollback_detected ? "yes" : "no") +
             " incarnation matches: " + (report.incarnation_matches ? "yes" : "no"));
  print_line("orphan generations: " + unsigned_text(report.orphan_generation_files.size()) +
             " staging residue: " + unsigned_text(report.staging_residue.size()));
  print_line("detail: " + report.detail);
  int code = report.ok ? kExitOk : kExitStore;
  if (reader.has("replay")) {
    auto replay = handle.value().plane.verify_replay();
    if (!replay.has_value()) {
      return report_error(replay.error());
    }
    print_line("deterministic replay ok: " + std::string(replay.value().ok ? "yes" : "no"));
    print_line("steps checked: " + unsigned_text(replay.value().steps_checked));
    for (const ReplayStepReport& step : replay.value().steps) {
      print_line("  revision " + unsigned_text(step.from_revision.value()) + " -> " +
                 unsigned_text(step.to_revision.value()) + " kind=" +
                 std::string(to_string(step.kind)) +
                 (step.matched ? " reproduced" : " MISMATCH"));
    }
    print_line("detail: " + replay.value().detail);
    if (!replay.value().ok) {
      code = kExitStore;
    }
  }
  return code;
}

int verb_init(const ArgReader& reader) {
  auto handle = open_plane(reader, true);
  if (!handle.has_value()) {
    return report_error(handle.error());
  }
  const auto facility_text = reader.value("facility");
  if (!facility_text.has_value()) {
    print_error("init requires --facility <id>");
    return kExitUsage;
  }
  auto facility = FacilityId::parse(facility_text.value());
  if (!facility.has_value()) {
    return report_error(facility.error());
  }
  OperatingMode mode = OperatingMode::normal;
  const auto mode_text = reader.value("mode");
  if (mode_text.has_value()) {
    auto parsed = parse_mode(mode_text.value());
    if (!parsed.has_value()) {
      return report_error(parsed.error());
    }
    mode = parsed.value();
  }
  auto binding = parse_evidence_list(reader.values("evidence"), handle.value().plane.limits());
  if (!binding.has_value()) {
    return report_error(binding.error());
  }
  auto key = IdempotencyKey::derive("init/" + facility_text.value() + "/" +
                                    std::string(to_string(mode)));
  if (!key.has_value()) {
    return report_error(key.error());
  }
  auto decision = handle.value().plane.bootstrap(*handle.value().lease, facility.value(), mode,
                                                 binding.value(), key.value());
  if (!decision.has_value()) {
    return report_error(decision.error());
  }
  return report_decision(decision.value(), handle.value().plane.limits());
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  arguments.reserve(static_cast<std::size_t>(argc));
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  if (arguments.empty()) {
    print_usage();
    return kExitUsage;
  }

  // Global options may appear before the verb, which is how an operator naturally
  // writes them. They are lifted out here so the verb is unambiguous regardless of
  // where the global options were placed.
  std::vector<std::string> globals;
  std::string verb;
  std::vector<std::string> rest;
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    const std::string& argument = arguments[index];
    if (verb.empty()) {
      const bool takes_value = argument == "--store" || argument == "--retain";
      if (takes_value) {
        globals.push_back(argument);
        if (index + 1 < arguments.size()) {
          globals.push_back(arguments[++index]);
        }
        continue;
      }
      if (argument.rfind("--store=", 0) == 0 || argument.rfind("--retain=", 0) == 0 ||
          argument == "--read-only") {
        globals.push_back(argument);
        continue;
      }
      verb = argument;
      continue;
    }
    rest.push_back(argument);
  }
  if (verb.empty()) {
    print_usage();
    return kExitUsage;
  }
  for (const std::string& global : globals) {
    rest.push_back(global);
  }
  ArgReader reader(rest);

  if (verb == "help" || verb == "--help" || verb == "-h") {
    print_usage();
    return kExitOk;
  }
  if (verb == "version") {
    return verb_version(reader);
  }
  if (verb == "state") {
    return verb_state(reader);
  }
  if (verb == "mode") {
    return verb_mode(reader);
  }
  if (verb == "authority") {
    return verb_authority(reader);
  }
  if (verb == "interlocks") {
    return verb_interlocks(reader);
  }
  if (verb == "obligations") {
    return verb_obligations(reader);
  }
  if (verb == "commitments") {
    return verb_commitments(reader);
  }
  if (verb == "permissions") {
    return verb_permissions(reader);
  }
  if (verb == "attempts") {
    return verb_attempts(reader);
  }
  if (verb == "evidence") {
    return verb_evidence(reader);
  }
  if (verb == "revalidation" || verb == "revalidate") {
    return verb_revalidation(reader);
  }
  if (verb == "policy") {
    return verb_policy(reader);
  }
  if (verb == "policy-eval") {
    return verb_policy_eval(reader);
  }
  if (verb == "evaluate") {
    return verb_evaluate(reader);
  }
  if (verb == "attempt") {
    return verb_attempt(reader);
  }
  if (verb == "history") {
    return verb_history(reader);
  }
  if (verb == "store") {
    return verb_store(reader);
  }
  if (verb == "verify") {
    return verb_verify(reader);
  }
  if (verb == "init") {
    return verb_init(reader);
  }
  print_error("unknown verb: " + verb);
  print_usage();
  return kExitUsage;
}
