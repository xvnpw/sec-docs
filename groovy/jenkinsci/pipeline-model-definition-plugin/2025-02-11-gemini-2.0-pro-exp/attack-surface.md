# Attack Surface Analysis for jenkinsci/pipeline-model-definition-plugin

## Attack Surface: [Groovy Sandbox Escape](./attack_surfaces/groovy_sandbox_escape.md)

*   **1. Groovy Sandbox Escape**

    *   **Description:** Attackers exploit vulnerabilities in the Groovy sandbox to execute arbitrary code on the Jenkins master with elevated privileges.
    *   **`pipeline-model-definition-plugin` Contribution:** The plugin's core functionality relies on Groovy execution within a sandbox. Declarative Pipelines *inherently* use Groovy, making the sandbox the *primary* defense against malicious code introduced *through the pipeline definition itself*. This is the defining characteristic of this attack surface being plugin-specific.
    *   **Example:** An attacker crafts a Groovy script within a `script` block in a Declarative Pipeline, exploiting a known (or zero-day) sandbox bypass vulnerability (e.g., using reflection, serialization tricks, or other Groovy-specific techniques) to gain access to the Jenkins master's file system, environment variables, or execute arbitrary system commands.
    *   **Impact:** Complete compromise of the Jenkins master, including access to all projects, credentials, and potentially the entire network connected to the Jenkins master.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Keep Jenkins and all plugins (especially `pipeline-model-definition-plugin` and Script Security) up-to-date:** This is paramount, as sandbox escapes are often patched quickly in response to vulnerability disclosures.
        *   **Use Script Security Plugin with Strict Approvals:** Require administrator approval for *any* script that uses methods outside the sandbox whitelist.  Administrators must *thoroughly* review all approved scripts for malicious code or potential bypass techniques.
        *   **Minimize `script` Block Usage:** Favor built-in Declarative Pipeline directives over custom Groovy code whenever possible.  This reduces the attack surface exposed to Groovy sandbox vulnerabilities.
        *   **Regularly Audit Approved Scripts:** Periodically review the list of approved scripts to ensure they are still necessary, haven't been tampered with, and don't contain newly discovered vulnerabilities.
        *   **Harden Jenkins Master (Defense in Depth):** While not directly related to the plugin, a hardened Jenkins setup (network segmentation, strong authentication, limited user privileges) provides an additional layer of defense.

## Attack Surface: [Shared Library Compromise (Pipeline-Specific Aspects)](./attack_surfaces/shared_library_compromise__pipeline-specific_aspects_.md)

*   **2. Shared Library Compromise (Pipeline-Specific Aspects)**

    *   **Description:** Attackers inject malicious code into a shared library *specifically designed for and used by* Declarative Pipelines.
    *   **`pipeline-model-definition-plugin` Contribution:** Declarative Pipelines *strongly encourage* the use of shared libraries for code reuse and maintainability. This creates a *direct* dependency on the security of these libraries, making them a prime target *because of how the plugin promotes their use*. The attack is not just "a library is compromised," but "a library *central to the Declarative Pipeline workflow* is compromised."
    *   **Example:** An attacker compromises the Git repository hosting a shared library that provides custom steps for a Declarative Pipeline. They add a backdoor that exfiltrates credentials or modifies build artifacts whenever the library's functions are called within a pipeline.
    *   **Impact:** Compromise of any pipeline using the affected shared library, potentially leading to credential theft, data exfiltration, or execution of arbitrary code *within the context of the pipeline's execution*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Secure Shared Library Repository:** Use strong authentication (including multi-factor authentication) and strict access controls for the repository hosting shared libraries (e.g., Git, SVN).
        *   **Mandatory Code Review for Shared Libraries:** Implement a *rigorous* code review process for *all* changes to shared libraries, with a specific focus on security implications and potential injection vulnerabilities.
        *   **Use Version Control and *Specific* Tagging:** *Always* use specific, immutable versions (tags) of shared libraries in pipelines.  *Never* use `@Library('my-library')` (which defaults to the latest version).  Use `@Library('my-library@v1.2.3')` instead, and *never* update the tag to point to a different commit. Create new tags for new versions.
        *   **Dependency Management (within the Library):** Carefully manage dependencies *within* shared libraries to avoid dependency confusion attacks. Use a lock file or similar mechanism to ensure consistent and secure dependency resolution.
        *   **Regular Vulnerability Scanning of Shared Libraries:** Use static analysis tools and dependency vulnerability scanners to identify potential security issues in shared library code *before* they are used in pipelines.

## Attack Surface: [Input Parameter Injection (within Pipeline Context)](./attack_surfaces/input_parameter_injection__within_pipeline_context_.md)

*   **3. Input Parameter Injection (within Pipeline Context)**

    *   **Description:** Attackers inject malicious input into pipeline parameters that are then used *unsafely within the Declarative Pipeline's Groovy code or shell scripts*.
    *   **`pipeline-model-definition-plugin` Contribution:** Declarative Pipelines provide the `parameters` directive, creating a *defined mechanism* for accepting user input. The vulnerability arises from how this input is *handled within the pipeline definition itself*. This is distinct from general Jenkins parameterization; it's about the *pipeline's* handling of those parameters.
    *   **Example:** A Declarative Pipeline has a string parameter `userInput` that is directly used within a `sh` step without proper escaping: `sh "echo ${userInput}"`. An attacker provides the input `"; rm -rf /; echo "`, resulting in command injection *on the agent executing the pipeline*.
    *   **Impact:** Execution of arbitrary commands on the agent where the pipeline stage is running, potentially leading to data deletion, system compromise, or information disclosure.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Input Validation:** Implement *strict* input validation for *all* pipeline parameters, especially string parameters. Use whitelisting (allowing only known-good values) whenever possible.
        *   **Proper Escaping:** If parameters *must* be used in shell commands or Groovy code, use appropriate escaping mechanisms to prevent injection attacks. For shell scripts within Declarative Pipelines, use `'''triple single quotes'''` to create a literal string that prevents variable expansion and command substitution.
        *   **Avoid Direct Parameter Use in `sh`:** Whenever possible, use built-in pipeline steps or functions that handle input safely, rather than constructing shell commands directly from parameters.
        *   **Parameterized Builds with *Extreme* Caution:** Be acutely aware of the risks associated with parameterized builds and design them with security as the *primary* concern.

