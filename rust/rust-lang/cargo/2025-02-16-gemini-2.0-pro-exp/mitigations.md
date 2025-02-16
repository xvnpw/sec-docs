# Mitigation Strategies Analysis for rust-lang/cargo

## Mitigation Strategy: [Explicit Registry Configuration and Dependency Pinning](./mitigation_strategies/explicit_registry_configuration_and_dependency_pinning.md)

**Description:**
1.  **Identify Private Dependencies:** List all internal or private crates.
2.  **Configure Private Registry (if applicable):** In `.cargo/config.toml` (project-level or user-level), define your private registry:
    ```toml
    [registries]
    my-private-registry = { index = "https://my-private-registry.com/index" }
    ```
3.  **Specify Registry for Dependencies:** In `Cargo.toml`, explicitly specify the registry for each private dependency:
    ```toml
    [dependencies]
    my-internal-crate = { version = "1.0", registry = "my-private-registry" }
    ```
    For path dependencies, use *absolute* paths:
    ```toml
    my-local-crate = { path = "/absolute/path/to/my-local-crate" }
    ```
4.  **Commit `Cargo.lock`:** Always commit `Cargo.lock` to version control.
5.  **Review `Cargo.lock` Changes:** After `cargo update`, carefully review the `Cargo.lock` diff.
6.  **Regularly run `cargo update`:** Keep dependencies updated, but review changes.

*   **Threats Mitigated:**
    *   **Dependency Confusion/Substitution (High Severity):** Prevents malicious package injection.
    *   **Typosquatting (Medium Severity):** Reduces risk of pulling similarly-named malicious packages.
    *   **Unintentional Dependency Updates (Medium Severity):** `Cargo.lock` prevents unexpected upgrades.

*   **Impact:**
    *   **Dependency Confusion/Substitution:** Risk significantly reduced (almost eliminated with a private registry and scoped packages).
    *   **Typosquatting:** Risk reduced (manual review still important).
    *   **Unintentional Dependency Updates:** Risk significantly reduced; updates are controlled.

*   **Currently Implemented:**
    *   `Cargo.lock` is committed.
    *   Basic `Cargo.toml` configuration.

*   **Missing Implementation:**
    *   Explicit registry configuration in `.cargo/config.toml` is missing.
    *   No `Cargo.lock` change review process.
    *   No absolute paths for local dependencies.

## Mitigation Strategy: [Dependency Auditing and Policy Enforcement (using `cargo audit` and `cargo deny`)](./mitigation_strategies/dependency_auditing_and_policy_enforcement__using__cargo_audit__and__cargo_deny__.md)

**Description:**
1.  **Integrate `cargo audit`:** Add `cargo audit` to CI/CD to check for vulnerabilities. Run on every build/PR.
2.  **Integrate `cargo deny`:** Add `cargo deny` to CI/CD to enforce policies (licenses, duplicates, etc.). Configure with `.cargo/deny.toml`.
3. **Establish a Dependency Update Policy:** Define how often to run `cargo update` and the review process.

*   **Threats Mitigated:**
    *   **Malicious Crates (High Severity):** `cargo audit` detects known vulnerabilities.
    *   **Vulnerable Dependencies (High Severity):** `cargo audit` directly addresses this.
    *   **License Compliance Issues (Medium Severity):** `cargo deny` enforces policies.
    *   **Code Quality Issues (Medium Severity):** `cargo deny` can prevent problematic crates.

*   **Impact:**
    *   **Malicious Crates:** Risk reduced by identifying known vulnerabilities.
    *   **Vulnerable Dependencies:** Risk significantly reduced via automated detection.
    *   **License Compliance Issues:** Risk significantly reduced via automated enforcement.
    *   **Code Quality Issues:** Risk reduced through policy enforcement.

*   **Currently Implemented:**
    *   Basic license checks (manual).

*   **Missing Implementation:**
    *   `cargo audit` not in CI/CD.
    *   `cargo deny` not used.
    *   No formal dependency update policy.

## Mitigation Strategy: [`build.rs` Script Review (using manual review and potentially `cargo build` flags)](./mitigation_strategies/_build_rs__script_review__using_manual_review_and_potentially__cargo_build__flags_.md)

**Description:**
1.  **Identify Dependencies with `build.rs`:** List dependencies with `build.rs`.
2.  **Manual Review:** Review `build.rs` code for:
    *   Network access.
    *   File system modifications outside `OUT_DIR`.
    *   External command execution.
    *   Complex/obfuscated logic.
3.  **`cargo build --target` (Limited Mitigation):**  Use `cargo build --target ...` to potentially limit the capabilities of a malicious `build.rs` that relies on host-specific tools.  *This is not a strong defense.*
4.  **Document Findings:** Document concerns.

*   **Threats Mitigated:**
    *   **Malicious Build Scripts (High Severity):** Reduces risk of compromised build environment.
    *   **Accidental Build Script Errors (Medium Severity):** Helps identify unintentional errors.

*   **Impact:**
    *   **Malicious Build Scripts:** Risk significantly reduced through manual review.  `--target` offers *very* limited mitigation.
    *   **Accidental Build Script Errors:** Risk reduced through manual review.

*   **Currently Implemented:**
    *   None.

*   **Missing Implementation:**
    *   No `build.rs` review process.

## Mitigation Strategy: [Feature Flag Management (using `Cargo.toml`)](./mitigation_strategies/feature_flag_management__using__cargo_toml__.md)

**Description:**
1.  **Identify Feature Flags:** List all feature flags.
2.  **Explicit Feature Selection:** In `Cargo.toml`, explicitly specify features:
    ```toml
    [dependencies]
    some-crate = { version = "1.0", features = ["feature1", "feature2"] }
    ```
    Avoid wildcards (`features = ["*"]`).
3.  **Document Feature Implications:** Document purpose, security implications, and rationale.
4.  **Regular Review:** Periodically review enabled flags.

*   **Threats Mitigated:**
    *   **Unintentional Feature Exposure (Medium Severity):** Prevents enabling vulnerable features.
    *   **Overly Permissive Features (Medium Severity):** Ensures minimal feature set.

*   **Impact:**
    *   **Unintentional Feature Exposure:** Risk significantly reduced.
    *   **Overly Permissive Features:** Risk reduced.

*   **Currently Implemented:**
    *   Some flags explicitly specified.

*   **Missing Implementation:**
    *   Not all flags explicit; some use defaults.
    *   No documentation.
    *   No regular review.

## Mitigation Strategy: [Vendoring (using `cargo vendor`)](./mitigation_strategies/vendoring__using__cargo_vendor__.md)

**Description:**
1. Run `cargo vendor` to copy dependencies into a `vendor` directory.
2. Configure cargo in `.cargo/config.toml`:
    ```toml
    [source.crates-io]
    replace-with = "vendored-sources"

    [source.vendored-sources]
    directory = "vendor"
    ```
3. Commit the `vendor` directory.
4. Update by re-running `cargo vendor` and committing.
5. Consider `cargo-vendor-filterer` to reduce `vendor` size.

*   **Threats Mitigated:**
    *   **Dependency Confusion/Substitution (High Severity):** Eliminates reliance on external registries.
    *   **Network Outages/Registry Unavailability (Medium Severity):** Builds continue offline.
    *   **Supply Chain Attacks (Tampering during transit) (High Severity):** Dependencies pulled once.

*   **Impact:**
    *   **Dependency Confusion/Substitution:** Risk eliminated.
    *   **Network Outages/Registry Unavailability:** Risk eliminated.
    *   **Supply Chain Attacks (Tampering during transit):** Risk significantly reduced.

*   **Currently Implemented:**
    *   None

*   **Missing Implementation:**
    *   Vendoring not used; relies on external registries.

