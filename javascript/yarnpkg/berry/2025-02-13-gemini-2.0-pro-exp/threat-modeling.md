# Threat Model Analysis for yarnpkg/berry

## Threat: [Compromised Registry Mirror (Cache Poisoning) – Berry-Specific Impact](./threats/compromised_registry_mirror__cache_poisoning__–_berry-specific_impact.md)

*   **Description:** An attacker compromises a configured registry mirror or uses a man-in-the-middle attack.  Because Yarn Berry relies heavily on its cache (`.yarn/cache`) for deterministic builds and Zero-Installs, a poisoned package in the cache has a *wider and more persistent* impact than with traditional package managers.  The attacker serves a modified package that is then stored in the cache.
*   **Impact:** Execution of arbitrary malicious code during installation, build, *and* runtime (due to Zero-Installs). Data exfiltration, system compromise, and potential lateral movement. The compromised package persists in the cache and affects all projects using it.
*   **Affected Component:** `npmRegistryServer` configuration in `.yarnrc.yml`, network communication, `.yarn/cache` (specifically its role in Zero-Installs and deterministic builds).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Use only trusted, official registry mirrors (e.g., `https://registry.npmjs.org/`).
    *   Implement strong network security controls (TLS, firewalls) to prevent MITM attacks.
    *   Regularly audit `.yarnrc.yml` for correct registry settings.
    *   Consider using a private, controlled package registry.
    *   While checksum verification helps *after* initial download, it doesn't prevent the initial poisoning of the cache.  Focus on preventing the initial compromise.

## Threat: [Tampered `.yarn/cache` – Berry-Specific Impact](./threats/tampered___yarncache__–_berry-specific_impact.md)

*   **Description:** An attacker gains write access to the `.yarn/cache` directory.  Due to Yarn Berry's Zero-Install feature, this directory is *essential* for application runtime, not just build time.  Modifying the cache directly impacts the running application.
*   **Impact:** Execution of malicious code *directly within the running application* (due to Zero-Installs). This is a persistent and widespread threat, affecting all projects using the compromised cache.
*   **Affected Component:** `.yarn/cache` directory, Zero-Install mechanism (PnP).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Implement *extremely* strict access controls on the `.yarn/cache` directory.  Limit write access to the absolute minimum necessary processes.
    *   Use immutable infrastructure or containerization to prevent persistent modifications.  The running application should *never* be able to write to the cache.
    *   *Do not* commit the `.yarn/cache` to version control unless you have absolute control over its integrity and have robust security measures in place. If committed, treat it as executable code.
    *   Consider using a read-only cache for production deployments.

## Threat: [Tampered `install-state.gz`](./threats/tampered__install-state_gz_.md)

*   **Description:** An attacker modifies the `.yarn/install-state.gz` file, which contains checksums and metadata used by Yarn Berry for integrity verification. This bypasses Yarn's built-in security checks.
*   **Impact:** Installation of incorrect or malicious packages, bypassing security checks, leading to potential runtime compromise due to Zero-Installs.
*   **Affected Component:** `.yarn/install-state.gz` file, integrity verification process, Zero-Install mechanism.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Treat `install-state.gz` with the same security considerations as `yarn.lock`.
    *   Do not manually modify this file.
    *   Ensure proper file permissions and access controls.
    *   Version control this file and review changes carefully.

## Threat: [Compromised Yarn Plugin](./threats/compromised_yarn_plugin.md)

*   **Description:** An attacker publishes a malicious Yarn plugin or compromises an existing one. Yarn Berry's plugin architecture allows for significant control over the build and dependency resolution process, making a compromised plugin extremely dangerous.
*   **Impact:** Full system compromise, as the plugin can execute arbitrary code with the privileges of the user running Yarn. This can affect both build-time and, potentially, runtime behavior if the plugin interacts with PnP.
*   **Affected Component:** Yarn plugin system (`.yarnrc.yml` plugin configuration, `.yarn/plugins`), any Yarn command that utilizes the compromised plugin, potentially PnP runtime.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Only install plugins from *highly* trusted sources (official Yarn plugins or extremely well-vetted community plugins).
    *   *Thoroughly* review the source code of *any* third-party plugins before installation.
    *   Regularly update plugins to get security patches.
    *   Implement a strict plugin allowlist, limiting which plugins can be loaded.
    *   Audit `.yarnrc.yml` for unexpected or unauthorized plugin configurations.

## Threat: [`unsafeHttpWhitelist` Misuse](./threats/_unsafehttpwhitelist__misuse.md)

*   **Description:** The `unsafeHttpWhitelist` setting in `.yarnrc.yml` is misused to allow non-HTTPS connections to untrusted or compromised hosts, bypassing crucial security protections during package retrieval. This directly impacts Yarn Berry's ability to securely fetch packages for its cache.
*   **Impact:** Exposure to man-in-the-middle attacks, leading to the download and caching of compromised packages, which then affects the application due to Zero-Installs.
*   **Affected Component:** `unsafeHttpWhitelist` setting in `.yarnrc.yml`, network communication with registries, `.yarn/cache`.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strongly avoid using `unsafeHttpWhitelist`.**
    *   If absolutely necessary, restrict it to the *absolute minimum* number of hosts, and ensure those hosts are *extremely* well-trusted and secured.
    *   Regularly audit `.yarnrc.yml` to ensure this setting is not being misused. Always prefer HTTPS.

## Threat: [Malicious `postinstall` (and other lifecycle) Scripts – Berry-Specific Considerations](./threats/malicious__postinstall___and_other_lifecycle__scripts_–_berry-specific_considerations.md)

*   **Description:** A package includes a malicious lifecycle script. While this is a general package management issue, Yarn Berry's `enableScripts` setting (defaulting to `true`) and its caching behavior have specific implications.  A malicious script can compromise the cache, affecting all projects that use it.
*   **Impact:** Arbitrary code execution, potential for privilege escalation, system compromise, and *persistent* compromise of the `.yarn/cache`.
*   **Affected Component:** Package lifecycle scripts (`scripts` field in `package.json`), Yarn's script execution mechanism, `enableScripts` setting in `.yarnrc.yml`, `.yarn/cache`.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Be *extremely* cautious about packages with lifecycle scripts, especially from untrusted sources.
    *   Consider using tools to analyze or sandbox these scripts.
    *   Run Yarn with limited privileges.
    *   **Seriously consider setting `enableScripts: false` in `.yarnrc.yml`**. This is a *major* decision with significant trade-offs. It disables *all* lifecycle scripts, greatly reducing risk but breaking many packages that rely on them.  Thorough testing is *essential* if you disable scripts.  This is the most effective mitigation, but also the most disruptive.

