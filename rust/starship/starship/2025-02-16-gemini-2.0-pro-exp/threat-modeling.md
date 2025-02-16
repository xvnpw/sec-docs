# Threat Model Analysis for starship/starship

## Threat: [Sensitive Information Disclosure via Environment Variables](./threats/sensitive_information_disclosure_via_environment_variables.md)

*   **Description:** `starship` is configured, either in `starship.toml` or through a custom module, to display sensitive environment variables directly in the prompt.  An attacker with access to the rendered prompt (e.g., in a web-based terminal) can directly read these variables, which might include API keys, database credentials, cloud provider secrets, or other confidential information. The attacker does not need to exploit any other vulnerability; the information is presented by design.
    *   **Impact:** Leakage of credentials, API keys, or other sensitive data, potentially leading to unauthorized access to other systems or services, data breaches, or financial loss.
    *   **Affected Starship Component:**  `env_var` module, custom modules that access and display environment variables, and the overall prompt rendering engine.
    *   **Risk Severity:** High (if sensitive environment variables are exposed) or Critical (if highly sensitive credentials like root keys or master API keys are exposed).
    *   **Mitigation Strategies:**
        *   **Configuration Review:**  Thoroughly review `starship.toml` and remove or disable (`disabled = true`) any `env_var` configurations that expose sensitive variables.
        *   **Prefix Filtering:** Use the `prefix` option within the `env_var` module to *only* display variables with a specific, non-sensitive prefix.  Avoid broad wildcards.
        *   **Substitution:** Instead of displaying the actual value, use a placeholder or a descriptive label (e.g., "[AWS Credentials Configured]").  Do *not* display any part of the sensitive value.
        *   **Custom Module Audit:**  If custom modules are used, rigorously audit them to ensure they *never* directly output sensitive environment variables to the prompt, regardless of input.
        *   **Application-Level Sanitization:** As a defense-in-depth measure, the application displaying the prompt should further sanitize the output, even if `starship` is believed to be configured correctly. This protects against configuration errors.

## Threat: [Command Injection via Custom Module Input](./threats/command_injection_via_custom_module_input.md)

*   **Description:** A custom `starship` module (especially one written in a shell scripting language) takes input from the application and uses it unsafely within a shell command.  An attacker crafts malicious input that, due to improper escaping or string interpolation, allows them to inject arbitrary shell commands.  These commands are then executed by the server running `starship`.  Example: A module displaying git information might use `git log -n 1 --grep="$INPUT"`.  An attacker could provide input like `"; whoami; #` to execute the `whoami` command.
    *   **Impact:**  Remote Code Execution (RCE) on the server, potentially leading to complete system compromise, data theft, or installation of malware.
    *   **Affected Starship Component:** Custom modules (written in any language, but particularly shell scripts) that execute shell commands based on external, attacker-controllable input.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Input Validation:**  Implement strict input validation and sanitization for *all* input passed to custom modules.  Use allow-lists (defining what *is* permitted) rather than block-lists (defining what is *not* permitted).
        *   **Parameterized Commands:**  Whenever possible, use parameterized commands or language-specific APIs that prevent shell injection.  For example, use a Git library in Python instead of shelling out to the `git` command.
        *   **Escaping:** If shell execution is absolutely unavoidable, use proper escaping functions provided by the scripting language to prevent metacharacter interpretation (e.g., `shellescape` in Python, `printf %q` in Bash).  Test escaping thoroughly.
        *   **Least Privilege:** Run the `starship` process (and any child processes it spawns) with the least necessary privileges.  *Never* run `starship` as root.
        *   **Code Review:**  Mandatory, thorough code reviews of all custom modules, with a specific focus on input handling and command execution, are essential.

## Threat: [Supply Chain Attack via Compromised Dependency (of Starship Itself)](./threats/supply_chain_attack_via_compromised_dependency__of_starship_itself_.md)

*   **Description:** An attacker compromises a Rust crate that `starship` itself depends on. This is distinct from a compromised *third-party module*. When `starship` is built or updated, the compromised code within the dependency is executed, potentially leading to RCE or other malicious actions on the system building or running `starship`.
    *   **Impact:** Varies depending on the compromised dependency, but could range from information disclosure to RCE on the system where `starship` is built or executed.
    *   **Affected Starship Component:** `starship` itself, due to a compromised dependency in its `Cargo.toml` file.
    *   **Risk Severity:** High to Critical (depending on the compromised dependency and its role within `starship`).
    *   **Mitigation Strategies:**
        *   **Dependency Auditing:** Regularly audit `starship`'s dependencies using tools like `cargo audit` to identify known vulnerabilities.
        *   **Version Pinning:** Pin `starship`'s dependencies to specific, known-good versions in its `Cargo.toml` file. This prevents automatic updates to potentially compromised versions.
        *   **Vendor Dependencies:** Consider vendoring `starship`'s dependencies (copying the source code into `starship`'s repository) to reduce reliance on external crates.io. This gives more control but increases maintenance burden.
        *   **Software Bill of Materials (SBOM):** Maintain an SBOM for `starship` to track all dependencies and their versions, facilitating rapid response to vulnerability disclosures.
        * **Build in secure environment:** Build starship in isolated, secure environment.

## Threat: [Configuration Tampering Leading to Command Injection or Information Disclosure](./threats/configuration_tampering_leading_to_command_injection_or_information_disclosure.md)

*   **Description:** An attacker gains write access to the `starship.toml` file. This could be through a compromised server account, a separate vulnerability in the application, or a misconfigured file system. The attacker modifies the configuration to: 1) Add malicious custom modules that execute arbitrary commands. 2) Expose sensitive environment variables in the prompt. 3) Change the behavior of existing modules to introduce vulnerabilities.
    *   **Impact:**  Remote Code Execution (RCE) or Information Disclosure, depending on the specific modifications made to the configuration file.
    *   **Affected Starship Component:** The `starship.toml` configuration file and any modules it references.
    *   **Risk Severity:** High to Critical (depending on the nature of the tampering and the sensitivity of the exposed information or the power of the injected commands).
    *   **Mitigation Strategies:**
        *   **File Permissions:**  Enforce strict file system permissions on `starship.toml`. Only the user running the `starship` process (and *not* the web server user or any other general user) should have write access. Ideally, even the `starship` user should only have read access after initial configuration.
        *   **Integrity Monitoring:**  Implement file integrity monitoring (FIM) using tools like AIDE, Tripwire, or Samhain to detect any unauthorized changes to `starship.toml`.
        *   **Configuration Management:**  Use a configuration management system (e.g., Ansible, Chef, Puppet, SaltStack) to manage the `starship.toml` file and ensure it remains in a known-good state. This also allows for automated remediation if tampering is detected.
        *   **Read-Only Configuration:** If feasible, store the `starship.toml` file in a read-only location after the initial setup is complete. This prevents any modifications, even by privileged users.
        *   **Regular Backups:** Maintain regular backups of the `starship.toml` file so it can be quickly restored to a known-good state if tampering is detected.

