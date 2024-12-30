### High and Critical Threats Directly Involving `act`

Here's a filtered list of high and critical threats that directly involve the `act` tool:

**Threat:** Malicious Workflow Code Execution
*   **Description:** An attacker could introduce malicious code within a workflow definition (either locally created or from an untrusted source). When `act` executes this workflow, the malicious code will run with the privileges of the user running `act`. This directly involves `act`'s core functionality of interpreting and executing workflow steps.
*   **Impact:** Complete compromise of the developer's local machine, including data theft, malware installation, or denial of service.
*   **Affected Component:** Workflow Execution Engine (within `act`).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Thoroughly review and understand the code in any workflow before execution, especially those from external or untrusted sources.
    *   Implement code review processes for locally developed workflows.
    *   Utilize static analysis tools to scan workflow files for potentially malicious patterns.
    *   Run `act` in a sandboxed environment or virtual machine for testing untrusted workflows.

**Threat:** Command Injection via Workflow Inputs
*   **Description:** An attacker could craft malicious input values that, when used within workflow commands executed by `act`, lead to the execution of arbitrary commands on the host system. This directly involves `act`'s handling of workflow inputs and their substitution into commands.
*   **Impact:**  Arbitrary command execution on the developer's machine, potentially leading to data theft, system compromise, or denial of service.
*   **Affected Component:** Input Parsing and Variable Substitution (within `act`).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Always sanitize and validate workflow inputs before using them in shell commands.
    *   Avoid directly embedding user-provided input into shell commands.
    *   Use parameterized commands or functions that handle input safely.
    *   Employ input validation libraries or functions specific to the scripting language used in workflow steps.

**Threat:** Insecure Handling of Secrets in Local Environment
*   **Description:** While `act` attempts to simulate GitHub Actions' secret handling, its implementation in a local environment might not be as secure. Secrets could be inadvertently logged by `act`, stored in easily accessible environment variables managed by `act`, or written to temporary files during `act`'s execution without proper protection.
*   **Impact:** Exposure of sensitive credentials (API keys, passwords, etc.) that could be used to compromise other systems or accounts.
*   **Affected Component:** Secret Management (within `act`).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Be cautious about logging output during local `act` runs, ensuring secrets are not inadvertently included.
    *   Avoid storing secrets directly in workflow files or environment variables used with `act` unless absolutely necessary.
    *   Utilize `act`'s `-s` or `--secret-file` options to manage secrets from separate, more secure files.
    *   Consider using a dedicated secrets management tool even for local development.