---
name: randbotd-validation-and-release
description: Mandatory validation, cleanliness, Debian packaging, and changelog workflow for randbotd. Use whenever validating changes, preparing commits, releasing versions, running verification, or building Debian packages.
---

# `randbotd` Mandatory Validation & Release Workflow

This skill defines the non-negotiable verification, cleanliness, Debian packaging, and changelog workflow for all contributions, features, bug fixes, and releases in `randbotd`.

Every agent working on this codebase **must** complete these steps before declaring any task complete or preparing a release.

---

## 📋 Complete Release & Validation Pipeline Overview

```
 [1. Code Formatting]      ->  cargo fmt --check
 [2. Full Test Suite]      ->  cargo test --features full-suite
 [3. Strict Clippy Checks] ->  cargo clippy --all-targets --all-features -- -D warnings
 [4. Project Cleanliness]  ->  ./scripts/sh/check_cleanliness.sh
            │
            ▼ (Any change or refactoring loops back to Step 1!)
 [5. Version Bump Prompt]  ->  Ask user: Patch / Minor / Major
 [6. Build Debian Package] ->  ./scripts/sh/build_deb.sh <bump_type>
 [7. Release Changelog]    ->  docs/changelog/<major>.x.x/<major>.<minor>.x/<version>.md
```

---

## 🔍 Phase 1: Mandatory Pre-Release Validation

Never skip any of these 4 validation steps. If any step fails, fix all root causes and re-run verification from Step 1.

### 1. Code Formatting
Ensure all Rust code adheres to standard formatting:
```bash
cargo fmt --check
```
*If formatting errors are present, run `cargo fmt` to resolve them.*

### 2. Full Test Suite (`--features full-suite`)
Execute the complete test suite including heavy end-to-end socket and IPC tests:
```bash
cargo test --features full-suite
```
*Every unit and integration test must pass with 0 failures.*

### 3. Strict Clippy Verification & Warning Justification Policy
Ensure there are no compiler or lint warnings anywhere in the codebase:
```bash
cargo clippy --all-targets --all-features -- -D warnings
```
> [!IMPORTANT]
> **Zero-Warning & Annotation Justification Invariant**:
> - Treat all warnings as errors (`-D warnings`).
> - **Solving Clippy Warnings with Annotations Must Be Properly Justified**:
>   - Silencing clippy warnings with annotations or attributes (e.g. `#[allow(dead_code)]`, `#[allow(unused_...)]`) is strictly forbidden unless **properly justified** (either via clear explanatory comments in code or direct explicit messages to the user).
>   - **SPECIALLY `dead_code`**: Maintaining code that does nothing is stupid unless it has a concrete, planned purpose for an upcoming phase (e.g., wireframing for an upcoming roadmap phase, threshold custodian APIs, or public IPC endpoints).
>   - If code does not do anything and has no documented future roadmap need, **delete it** immediately rather than hiding it under `#[allow(dead_code)]`.

### 4. Project Cleanliness & Anti-Clutter Enforcement
Run the project's tidiness enforcement script:
```bash
./scripts/sh/check_cleanliness.sh
```
The cleanliness script enforces two strict architectural invariants on all affected directories and files:
1. **Directory Item Limit**: No directory affected by changes can exceed **9 items** (files or subdirectories).
2. **File Line Count Limit**: No source or text file affected by changes can exceed **500 lines**.

> [!CAUTION]
> **No Line-Collapsing Tricks! Demand Modularization, Interfaces & Good Architecture**:
> - **Tricks are Strictly Prohibited**: Never use tricks such as collapsing lines, merging statements onto single lines, minifying code, or stripping out docstrings/whitespace to sneak under the 500-line cleanliness limit.
> - **Cleanliness Through Architecture**: Achieve cleanliness solely through **modularization, interfaces, and good architecture in general**:
>   - Split large files or bloated test suites into clean submodules (e.g., `tests.rs`, `submodule_tests.rs`, or dedicated submodule directories like `foo/mod.rs` and `foo/tests.rs`).
>   - Extract domain logic, builders, parsers, or state machines into dedicated sub-components with well-defined interfaces and traits.
>   - Decompose monolithic handlers into focused, modular structs.
> - **The Verification Loop Catch**: After **ANY** change, the full verification pipeline must pass again from Step 1. Because `cargo fmt` runs before cleanliness checks, if anyone attempts line-collapsing tricks, `cargo fmt` will immediately un-collapse them back to standard formatting and expose the trick, failing `check_cleanliness.sh`.

---

## ❓ Phase 2: User Version Bump Inquiry

Once all 4 validation checks pass without errors:

**You must ask the user whether the release is a `patch`, `minor`, or `major` version bump.**

Use the `ask_question` tool:
- **Question**: `"Validation has passed all checks. Which SemVer version bump should be applied for the new Debian build?"`
- **Options**:
  - `(Recommended) Patch (e.g. bug fixes, wireframing, internal improvements, backwards-compatible fixes)`
  - `Minor (e.g. new features like CA modules, protocol additions, additive functionality)`
  - `Major (e.g. breaking protocol changes, major architectural migrations)`

---

## 📦 Phase 3: Debian Package Build

Once the user selects the bump type (`patch`, `minor`, or `major`):

1. Execute the packaging script with the selected bump type:
   ```bash
   ./scripts/sh/build_deb.sh <patch|minor|major>
   ```
2. The script will:
   - Automatically execute `./scripts/sh/check_cleanliness.sh` first.
   - Increment the version in `Cargo.toml`.
   - Build release binaries (`cargo build --release`).
   - Package systemd services, binaries, manpages, and config files into `randbotd_<version>-<release>_<arch>.deb`.
3. Verify that the `.deb` file was generated successfully in `$HOME/randbotd-repo/` or the project root.

---

## 📝 Phase 4: Release Changelog Documentation

Create a dedicated changelog markdown file for the newly built version:

### File Location
```
docs/changelog/<major>.x.x/<major>.<minor>.x/<version>.md
```
*(Example: for version `3.5.0`, place in `docs/changelog/3.x.x/3.5.x/3.5.0.md`)*

### Required Changelog Structure
```markdown
# Changelog — randbotd <version>

**Released:** <YYYY-MM-DD>

## Summary
Brief executive summary of what this release delivers, what features or bugs were addressed, and why the release is significant.

---

## Key Features & Enhancements

### 1. <Feature/Module Name> (`<Feature-ID>`)
- Detailed breakdown of architectural and functional improvements.

### 2. <Feature/Module Name>
- Details.

---

## Retrocompatibility Guarantees
- Explicit description of database schemas, wire frames, and backward compatibility invariants preserved or migrated.

---

## Verification & Quality Assurance
- Confirmation that:
  - `cargo fmt --check` passed.
  - `cargo test --features full-suite` passed (<N> tests passed, 0 failed).
  - `cargo clippy --all-targets --all-features -- -D warnings` passed with 0 warnings (with any roadmap annotations justified).
  - `./scripts/sh/check_cleanliness.sh` passed cleanly without line-collapsing tricks.
  - Debian package `randbotd_<version>-<release>_amd64.deb` built successfully.
```
