# Attack Surface Analysis for jordansissel/fpm

## Attack Surface: [Malicious Source Code Injection (via `fpm`'s Source Handling)](./attack_surfaces/malicious_source_code_injection__via__fpm_'s_source_handling_.md)

**Description:** An attacker compromises a source that `fpm` is *configured* to use (Git repository, package repository, local files), injecting malicious code that `fpm` then packages.

**How `fpm` Contributes:** `fpm`'s core function is to package code from specified sources.  It is the *direct mechanism* by which the malicious code is incorporated into the package.  `fpm` does not inherently validate the integrity of these sources beyond what the underlying package managers (if any) might do.

**Example:** An attacker compromises a private Git repository that `fpm` is configured to pull from.  `fpm` then packages the malicious code.  Or, `fpm` is configured to use a compromised version of a package from PyPI.

**Impact:** Complete system compromise. The attacker gains arbitrary code execution on any system where the compromised package is installed.

**Risk Severity:** Critical

**Mitigation Strategies:**
    *   **Source Verification:** Rigorously verify the integrity and authenticity of *all* sources *before* providing them to `fpm`. Use checksums, digital signatures (if available via underlying package managers), and GPG-signed commits for Git.
    *   **Version Pinning:**  Pin all dependency and source versions *within the configuration provided to `fpm`*. Use a `Gemfile.lock`, `requirements.txt` (with hashes), or equivalent, and ensure `fpm` respects these.
    *   **Dependency Auditing:** Regularly audit all dependencies for known vulnerabilities.  This includes dependencies of the software being packaged *and* dependencies of `fpm` itself.
    *   **Private Repository Security:** Implement strong access controls and multi-factor authentication for any private repositories used as sources by `fpm`.

## Attack Surface: [Command Injection via `fpm` Arguments](./attack_surfaces/command_injection_via__fpm__arguments.md)

**Description:** An attacker crafts malicious input that is used to construct `fpm`'s command-line arguments, leading to the execution of arbitrary commands on the system *where `fpm` is run*.

**How `fpm` Contributes:** `fpm`'s command-line interface is the primary interaction point.  If arguments are built from untrusted input without proper sanitization, `fpm` becomes the direct vector for command injection.

**Example:** A web application uses user-provided input to specify the package type to build with `fpm`. The user enters `deb; rm -rf /`. If the application doesn't sanitize, `fpm` might execute the `rm -rf /` command.

**Impact:** Potentially complete system compromise, data loss, or denial of service on the system *running `fpm`* (not necessarily the target system for the package).

**Risk Severity:** High

**Mitigation Strategies:**
    *   **Input Sanitization:** *Never* directly use unsanitized user input in `fpm` commands. Implement strict input validation and escaping.
    *   **Parameterized API (if available):** If `fpm` offers a programmatic API (and you are using it programmatically), use that API to avoid manual string construction.
    *   **Principle of Least Privilege:** Run `fpm` itself with the minimum necessary privileges. Avoid running it as root.
    *   **Whitelisting:** Use a whitelist of allowed characters or patterns for any input that will be used in `fpm` arguments.

## Attack Surface: [Malicious Pre/Post-Install Scripts (Controlled by `fpm`'s Packaging)](./attack_surfaces/malicious_prepost-install_scripts__controlled_by__fpm_'s_packaging_.md)

**Description:** An attacker injects malicious code into pre-install or post-install scripts that `fpm` is *configured* to include in the package.

**How `fpm` Contributes:** `fpm` provides the mechanism to *define and include* these scripts within the package.  It is the direct means by which these scripts are delivered and executed during installation.

**Example:** An attacker modifies the source code to include a malicious post-install script that downloads and executes a remote payload. `fpm` packages this script.

**Impact:** Complete system compromise on the system where the package is *installed*, as the scripts typically run with installer privileges (often root).

**Risk Severity:** Critical

**Mitigation Strategies:**
    *   **Script Review:** Thoroughly review *all* pre-install and post-install scripts for any suspicious code *before* providing them to `fpm` for packaging.
    *   **Minimize Script Complexity:** Keep pre/post-install scripts as simple as possible. Avoid complex logic or external dependencies within the scripts that `fpm` will include.
    *   **Principle of Least Privilege:** If possible, install packages (created by `fpm`) with the minimum necessary privileges. Avoid installing as root unless absolutely necessary. This mitigates the *impact* of a compromised script, even though it doesn't directly address `fpm`'s role.

