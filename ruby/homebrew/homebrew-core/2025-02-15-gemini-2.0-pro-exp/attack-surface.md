# Attack Surface Analysis for homebrew/homebrew-core

## Attack Surface: [Malicious Formula Submission/Compromise](./attack_surfaces/malicious_formula_submissioncompromise.md)

*   **Description:** An attacker submits or modifies a formula in `homebrew-core` to include malicious code.
*   **How Homebrew-Core Contributes:** `homebrew-core` is the central, official repository.  Its open nature, while beneficial, makes it a target.  Compromise *here* has a wide impact.
*   **Example:** An attacker gains access to a Homebrew maintainer's account and modifies a widely-used formula (e.g., `wget`) to include a backdoor.
*   **Impact:** Remote Code Execution (RCE), data theft, system compromise, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Pin Formula Versions:**  Specify exact formula versions (e.g., `brew install wget@1.21.2`). Regularly review and update these pinned versions after thorough vetting.
    *   **Audit Formula Code:**  Manually review the source code of the formula and its installation scripts *before* installation.  Focus on external downloads and system modifications.
    *   **Monitor Formula Changes:** Track changes to the formulas you use in the `homebrew-core` repository.

## Attack Surface: [Dependency Hijacking/Confusion (Specifically within `homebrew-core`'s managed dependencies)](./attack_surfaces/dependency_hijackingconfusion__specifically_within__homebrew-core_'s_managed_dependencies_.md)

*   **Description:** An attacker compromises a dependency *that is also managed within `homebrew-core`*. This is distinct from dependencies hosted externally.
*   **How Homebrew-Core Contributes:** If a formula within `homebrew-core` depends on *another* formula within `homebrew-core`, a compromise of the dependent formula becomes a direct `homebrew-core` risk.
*   **Example:** Formula A depends on Formula B, both in `homebrew-core`.  An attacker compromises Formula B, which then affects users of Formula A.
*   **Impact:** RCE, data theft, system compromise – the same as a direct compromise of the primary formula.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Thorough Dependency Auditing:**  Manually review the source code of *all* dependencies, including other `homebrew-core` formulas that are used.
    *   **Pin Formula Versions:** Pin versions for *both* the primary formula *and* its `homebrew-core` dependencies.
    *   **Verify Checksums Manually:** Although Homebrew does this, independent verification adds a layer of security.

## Attack Surface: [Insecure CI/CD Integration (Specifically using `homebrew-core`)](./attack_surfaces/insecure_cicd_integration__specifically_using__homebrew-core__.md)

*   **Description:**  Homebrew is used insecurely within a CI/CD pipeline, specifically pulling formulas from `homebrew-core` without proper checks.
*   **How Homebrew-Core Contributes:** The CI/CD pipeline's reliance on `homebrew-core` for packages makes it vulnerable to supply chain attacks originating from `homebrew-core`.
*   **Example:** A CI/CD pipeline automatically runs `brew install <formula>` without pinning the version. A compromised version of the formula is pushed to `homebrew-core`, and the pipeline installs it.
*   **Impact:** Compromise of the CI/CD pipeline, leading to malicious code injection into the application.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Pin Formula Versions in CI/CD:**  Use specific formula versions from `homebrew-core` in CI/CD scripts.
    *   **Validate Checksums in CI/CD:**  Verify checksums of downloaded files from `homebrew-core` within the CI/CD pipeline.
    *   **Least Privilege for CI/CD:** Run CI/CD jobs with minimal necessary privileges.

