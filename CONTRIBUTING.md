# Contributing to Power Control Plane

Power Control Plane is licensed under the Apache License 2.0. Contributions are
accepted under the same license.

## Licensing of contributions

By submitting a contribution to this repository you agree that your contribution is
provided under the terms of the Apache License 2.0, without additional terms or
conditions, as described in section 5 of that license. There is no Contributor
License Agreement (CLA) and no copyright assignment requirement. You retain the
copyright to your contribution.

Do not add copyright headers that attribute work to anyone other than the actual
author, and do not add `Co-authored-by` trailers or other attribution trailers to
commits in this repository.

## Building and testing

Requirements: CMake 3.21 or newer and a C++20 compiler. The primary exercised
platform is Windows with MSVC (Visual Studio 2022, toolset 19.44 or newer).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The build must be warning-free. First-party warnings are errors: MSVC builds with
`/W4 /WX /permissive-`, other compilers with `-Wall -Wextra -Wpedantic -Werror`.
Do not disable a warning globally to make a change compile; fix the defect or, when a
warning is genuinely wrong for a specific construct, suppress it narrowly at the site
with a comment that explains why.

## What a change must preserve

This runtime decides facility electrical operating state. A change that weakens any
of the following is not acceptable without a documented safety argument:

* safety interlocks fail closed, including when the interlock state is unknown;
* a policy rule can never outrank an interlock;
* missing, stale, contradictory, or unavailable evidence never becomes permission;
* a permission is valid only against the exact generation, revision, policy revision,
  and evidence binding it names;
* a denied or indeterminate operation changes no authoritative state;
* acknowledgement, observed effect, and verified effect stay distinct;
* protected obligations are never dropped silently;
* recovery never treats persisted dynamic evidence as fresh.

## Code quality requirements

* Public headers carry doc comments that state what a type or function guarantees,
  not only what it does.
* New model enumerations use the existing text-table pattern so that a spelling is
  defined in exactly one place.
* New persisted fields require a matching canonical encoder, a bounded decoder, a
  decode-time validation, and a test that a corrupted value is refused.
* Errors are typed. Do not signal a refusal by throwing, by returning a bool, or by
  encoding it in a string.
* Bounded collections state their bound in `Limits` and refuse overflow rather than
  wrapping or clamping.
