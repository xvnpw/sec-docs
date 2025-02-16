# Mitigation Strategies Analysis for habitat-sh/habitat

## Mitigation Strategy: [Strict Origin Control and Key Verification](./mitigation_strategies/strict_origin_control_and_key_verification.md)

*   **Description:**
    1.  **Identify Trusted Origins:** Determine which Habitat origins (your private depot, specific *bldr* channels) are trustworthy.
    2.  **Configure Supervisor:** Use the `HAB_ORIGIN` environment variable or the `--origin` flag with `hab sup run` and related commands to *only* accept packages from the trusted origins.  Example: `HAB_ORIGIN=my-company`.
    3.  **Configure Build Process:** Ensure `hab pkg build` commands and CI/CD pipelines use the same trusted origins via the `--origin` flag.
    4.  **Obtain Origin Public Keys:** Use `hab origin key download <origin>` to get the public keys.  *Crucially*, verify the key fingerprint out-of-band.
    5.  **Verify Key Fingerprints:** Before trusting a downloaded key, *always* verify its fingerprint against a known good value from a secure channel.
    6.  **Store Keys Securely:** Store downloaded public keys in a location accessible to the Supervisor and build processes.
    7.  **Regularly Review Origins:** Periodically review trusted origins and keys.

*   **Threats Mitigated:**
    *   **Malicious Package Injection (Severity: Critical):** Prevents using packages from untrusted Habitat origins.
    *   **Supply Chain Attacks (Severity: High):** Reduces risk from compromised upstream Habitat origins.
    *   **Accidental Use of Untrusted Packages (Severity: Medium):** Prevents using packages from untrusted origins.

*   **Impact:**
    *   **Malicious Package Injection:** Risk significantly reduced.
    *   **Supply Chain Attacks:** Risk substantially reduced.
    *   **Accidental Use of Untrusted Packages:** Risk eliminated.

*   **Currently Implemented:**
    *   Supervisor configuration: Partially (e.g., `HAB_ORIGIN` set, but key verification inconsistent).
    *   Build process: Partially (CI/CD uses `HAB_ORIGIN`, but ad-hoc key management).

*   **Missing Implementation:**
    *   Consistent key fingerprint verification.
    *   Formalized key management (secure storage, rotation).
    *   Developer training on origin key verification.

## Mitigation Strategy: [Private Depot with Channel Promotion (Habitat-Specific Aspects)](./mitigation_strategies/private_depot_with_channel_promotion__habitat-specific_aspects_.md)

*   **Description:**
    1.  **Set up Private Depot:** Deploy a private Habitat depot.
    2.  **Define Channels:** Create channels (e.g., `dev`, `staging`, `prod`) within your depot.
    3.  **Establish Promotion Workflow:** Define how packages move between channels (e.g., `dev` -> `staging` -> `prod` after testing).
    4.  **Automate Promotion:** Use `hab pkg promote` and `hab pkg demote` in CI/CD pipelines to automate the process.
    5.  **Configure Supervisor (Channels):** Use `hab sup run --channel <channel>` (or the `HAB_BLDR_CHANNEL` environment variable) to configure the Supervisor to use the correct channel for its environment.

*   **Threats Mitigated:**
    *   **Malicious Package Injection (Severity: Critical):** Limits who can upload to production channels.
    *   **Untested Code Deployment (Severity: High):** Ensures only tested code reaches production channels.
    *   **Accidental Deployment of Development Code (Severity: Medium):** Prevents deploying unstable code to production.

*   **Impact:**
    *   **Malicious Package Injection:** Risk significantly reduced.
    *   **Untested Code Deployment:** Risk significantly reduced.
    *   **Accidental Deployment of Development Code:** Risk eliminated.

*   **Currently Implemented:**
    *   Private depot setup: Implemented.
    *   Basic access control: Implemented.

*   **Missing Implementation:**
    *   Formalized, *automated* channel promotion using `hab pkg promote/demote`.
    *   Supervisor configuration to consistently use channels via `--channel` or `HAB_BLDR_CHANNEL`.

## Mitigation Strategy: [Hash Verification (Supervisor)](./mitigation_strategies/hash_verification__supervisor_.md)

*   **Description:**
    1.  **Enable Hash Verification (Supervisor):** Ensure the Habitat Supervisor verifies package hashes on load/update.  This is the *default* behavior, but confirm it's not disabled (there are no flags to explicitly *enable* it; it's about avoiding flags that might *disable* it).  Focus on ensuring no configuration accidentally disables this core feature.

*   **Threats Mitigated:**
    *   **Package Tampering (Severity: High):** Prevents loading a modified package.

*   **Impact:**
    *   **Package Tampering:** Risk significantly reduced (if the default behavior is maintained).

*   **Currently Implemented:**
    *   Implemented (default Supervisor behavior).

*   **Missing Implementation:**
    *   Need to *verify* no configuration options are being used that could inadvertently disable hash verification.  This requires careful review of Supervisor startup scripts and environment variables.

## Mitigation Strategy: [Supervisor Configuration Hardening (Habitat-Specific Flags)](./mitigation_strategies/supervisor_configuration_hardening__habitat-specific_flags_.md)

*   **Description:**
    1.  **`hab sup run` Flags:** Carefully review and use the following flags:
        *   `--listen-gossip <address:port>`: Bind the gossip interface to a specific address/port.  Avoid binding to `0.0.0.0` unless absolutely necessary.
        *   `--listen-http <address:port>`: Bind the HTTP API interface similarly.
        *   `--peer <address:port>`:  Explicitly define peers for clustering.  Avoid automatic peer discovery in untrusted networks.
        *   `--ring-key <key-name>`:  Enable gossip encryption (see separate strategy).
        *   `--tls-cert`, `--tls-key`, `--tls-ca-cert`: Enable TLS for the HTTP API.
        *   `--bind`: Carefully control bind mounts.
    2. **Environment Variables:** Review environment variables that affect the Supervisor (e.g., `HAB_ORIGIN`, `HAB_BLDR_CHANNEL`, `HAB_AUTH_TOKEN`).

*   **Threats Mitigated:**
    *   **Supervisor Compromise (Severity: Critical):** Reduces the impact by limiting network exposure and enforcing secure communication.
    *   **Unauthorized Access to Supervisor API (Severity: High):** TLS and controlled binding restrict API access.

*   **Impact:**
    *   **Supervisor Compromise:** Impact significantly reduced.
    *   **Unauthorized Access to Supervisor API:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Basic `hab sup run` flags: Partially implemented.

*   **Missing Implementation:**
    *   Consistent use of `--listen-gossip` and `--listen-http` to bind to specific interfaces.
    *   TLS encryption for the HTTP API (`--tls-cert`, etc.).
    *   Careful review and restriction of `--bind` mounts.

## Mitigation Strategy: [Dependency Management (Habitat `plan.sh`)](./mitigation_strategies/dependency_management__habitat__plan_sh__.md)

*   **Description:**
    1.  **Pin Dependencies:** In your `plan.sh`, specify *precise* versions for *all* dependencies, including the release number.  Use the fully qualified package identifier (e.g., `core/glibc/2.31/20200306220202`).  Do *not* use version ranges.
    2. **`pkg_deps` and `pkg_build_deps`:** Use these arrays correctly in your `plan.sh` to declare runtime and build-time dependencies, respectively.

*   **Threats Mitigated:**
    *   **Vulnerable Dependency Exploitation (Severity: High):** Reduces risk by controlling which dependency versions are used.
    *   **Supply Chain Attacks (Severity: High):** Helps mitigate vulnerabilities from compromised upstream dependencies *if* you keep your pinned versions up-to-date.

*   **Impact:**
    *   **Vulnerable Dependency Exploitation:** Risk significantly reduced (but requires ongoing updates).
    *   **Supply Chain Attacks:** Risk reduced (but requires vigilance).

*   **Currently Implemented:**
    *   Basic dependency pinning: Partially implemented.

*   **Missing Implementation:**
    *   Consistent and strict pinning of *all* dependencies to specific release numbers.

## Mitigation Strategy: [Secure Configuration Updates (Habitat Hooks and API)](./mitigation_strategies/secure_configuration_updates__habitat_hooks_and_api_.md)

*   **Description:**
    1.  **TLS for API:** Use TLS encryption for the Habitat Supervisor's HTTP API (see previous strategy).  This protects configuration updates sent via the API.
    2.  **Input Validation (Hooks):** Within your Habitat plan's `run` hook (and any other hooks that handle configuration), implement strict validation for *all* configuration values.  Use `pkg_bind_map` to define expected configuration keys.
    3. **Configuration Auditing:** Habitat logs configuration changes. Ensure these logs are collected and monitored.

*   **Threats Mitigated:**
    *   **Malicious Configuration Injection (Severity: High):** Prevents injecting malicious configurations.
    *   **Configuration Errors (Severity: Medium):** Reduces accidental misconfigurations.

*   **Impact:**
    *   **Malicious Configuration Injection:** Risk significantly reduced.
    *   **Configuration Errors:** Risk reduced.

*   **Currently Implemented:**
    *   Basic configuration updates via API: Implemented.

*   **Missing Implementation:**
    *   TLS for the API.
    *   Comprehensive input validation within `run` and other relevant hooks using `pkg_bind_map`.

## Mitigation Strategy: [Plan.sh Security (Habitat Build Process)](./mitigation_strategies/plan_sh_security__habitat_build_process_.md)

*   **Description:**
    1.  **Shell Injection Prevention:**
        *   Avoid string concatenation for shell commands.
        *   Use Habitat's helper functions (e.g., `add_pkg_to_env`, `download_file`) instead of raw shell commands where possible.
        *   Sanitize any user input used in shell commands.
    2. **Avoid Hardcoded Secrets:** Do not store secrets in `plan.sh`. Use environment variables or Habitat's configuration system.
    3. **Use `hab pkg install` Carefully:** Ensure you are installing from trusted origins and verifying package integrity when using `hab pkg install` within `plan.sh`.

*   **Threats Mitigated:**
    *   **Code Injection (Severity: High):** Prevents injecting malicious code into `plan.sh`.
    *   **Secret Exposure (Severity: High):** Prevents leaking secrets.

*   **Impact:**
    *   **Code Injection:** Risk significantly reduced.
    *   **Secret Exposure:** Risk eliminated (if secrets are managed correctly).

*   **Currently Implemented:**
    *   Basic `plan.sh` files: Implemented.

*   **Missing Implementation:**
    *   Strict adherence to shell injection prevention.
    *   Secure secret management (not hardcoding in `plan.sh`).

## Mitigation Strategy: [Gossip Encryption (Habitat Ring)](./mitigation_strategies/gossip_encryption__habitat_ring_.md)

*   **Description:**
    1.  **Generate Ring Key:** `hab ring key generate <ring-name>`.
    2.  **Secure Key Distribution:** Securely distribute the *private* key to all Supervisors in the ring.
    3.  **Configure Supervisors:** Use `--ring-key <key-name>` with `hab sup run` on *all* Supervisors in the ring.
    4.  **Regular Key Rotation:** Periodically rotate the ring key.

*   **Threats Mitigated:**
    *   **Gossip Eavesdropping (Severity: High):** Prevents reading gossip traffic.
    *   **Gossip Manipulation (Severity: High):** Prevents injecting false information.

*   **Impact:**
    *   **Gossip Eavesdropping:** Risk eliminated (with proper key management).
    *   **Gossip Manipulation:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Not implemented.

*   **Missing Implementation:**
    *   Generate and distribute a ring key.
    *   Configure Supervisors with `--ring-key`.
    *   Establish key rotation process.

