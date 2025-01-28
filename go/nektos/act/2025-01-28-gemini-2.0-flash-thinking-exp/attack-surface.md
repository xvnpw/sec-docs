# Attack Surface Analysis for nektos/act

## Attack Surface: [Workflow Command Injection](./attack_surfaces/workflow_command_injection.md)

*   **Description:** `act` executes commands defined in GitHub Actions workflows. If these commands are constructed using unsanitized user-controlled input within the workflow definition, command injection vulnerabilities can be exploited *during act execution*.
    *   **How act contributes:** `act` directly interprets and executes the command steps defined in workflow YAML files. It faithfully runs commands, including those that are vulnerable to injection if the workflow is poorly designed. `act`'s core function is to execute these commands locally, thus directly enabling this attack surface if present in the workflow.
    *   **Example:** A workflow step uses an environment variable (e.g., `INPUT_BRANCH_NAME`) to construct a shell command without proper escaping: `run: echo "Branch name is $INPUT_BRANCH_NAME"`. If a malicious actor can control `INPUT_BRANCH_NAME` (e.g., by crafting a pull request that influences workflow inputs in a CI context *simulated by act*), they could inject commands like `; rm -rf /`. When `act` executes this workflow, the injected command will be executed on the developer's machine or within the Docker container.
    *   **Impact:** Arbitrary command execution on the host system or within the container, potentially leading to data theft, system compromise, or denial of service.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Input Sanitization in Workflows:**  Developers must rigorously sanitize and validate all user-controlled inputs (environment variables, workflow inputs, action outputs) *within their workflow definitions* before using them in commands.
        *   **Parameterization in Workflows:**  Utilize parameterized commands or functions within workflows to avoid direct string concatenation of user inputs into shell commands.  Use action features or scripting languages within actions to handle inputs safely.
        *   **Code Review of Workflows:** Thoroughly review workflow files for potential command injection vulnerabilities before testing them with `act`. Treat workflow definitions as code that requires security scrutiny.

## Attack Surface: [Malicious or Vulnerable Actions Executed by Act](./attack_surfaces/malicious_or_vulnerable_actions_executed_by_act.md)

*   **Description:** `act` executes actions as defined in workflows. If a workflow uses a malicious action or an action with vulnerabilities, `act` will execute this potentially harmful code locally. The risk is directly introduced by the *execution* of these actions *by act*.
    *   **How act contributes:** `act` is designed to simulate GitHub Actions execution, which includes fetching and running action code. `act`'s primary function is to execute these actions locally, making it the direct enabler of this attack surface if malicious or vulnerable actions are used in workflows. `act` itself does not inherently validate the security of action code.
    *   **Example:** A developer includes an action from a seemingly legitimate but compromised GitHub repository in their workflow. When `act` runs this workflow, it fetches and executes the malicious action code. This action could contain code to exfiltrate secrets from the local environment, attempt container escapes, or perform other malicious activities *during act execution*.
    *   **Impact:** Data exfiltration from the local development environment, system compromise (container escape), supply chain compromise within local testing, potentially leading to wider organizational risks if compromised developer machines are used to push code.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Action Source Trust:**  Developers should strictly use actions from trusted and verified sources. Favor official GitHub actions or actions from reputable maintainers and organizations.
        *   **Action Code Review Before Use:**  Critically review the code of actions, especially those from third-party sources, *before* incorporating them into workflows and testing with `act`. Understand what the action does and look for any suspicious or unexpected behavior in its code.
        *   **Pin Action Versions in Workflows:**  Always pin actions to specific, immutable versions (commits or tags) in workflow definitions instead of using `latest` or branch names. This prevents actions from unexpectedly changing due to malicious updates in the action repository, especially when testing workflows repeatedly with `act`.
        *   **Action Dependency Scanning (If Applicable):** If actions include their own dependencies, consider scanning those dependencies for known vulnerabilities, although this is often more complex for actions.

## Attack Surface: [Container Escape via Malicious Workflow Actions Executed by Act](./attack_surfaces/container_escape_via_malicious_workflow_actions_executed_by_act.md)

*   **Description:** Actions executed by `act` run within Docker containers. Malicious actions could contain exploits that target vulnerabilities in the container runtime or kernel, aiming to escape the container sandbox and gain access to the host system *during act execution*.
    *   **How act contributes:** `act` provides the Docker container execution environment for actions. If a malicious action contains a container escape exploit, `act`'s execution environment becomes the platform where this exploit is triggered. `act` is directly involved in setting up and running the containers where these exploits could be activated.
    *   **Example:** A crafted malicious action contains code that exploits a known vulnerability in the Docker runtime (e.g., a vulnerability in `runc` or the kernel's containerization features). When `act` executes this action within a Docker container, the exploit is triggered. Successful exploitation allows the action to break out of the container and gain code execution on the developer's host machine, outside of the intended container isolation.
    *   **Impact:** Full host system compromise, data breach, privilege escalation on the developer's machine. This is a critical breach of the intended security boundary of containerization during local workflow testing with `act`.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Regular Docker and OS Updates:**  Ensure the Docker daemon and the host operating system are regularly updated with the latest security patches. This is crucial to mitigate known container escape vulnerabilities that malicious actions might attempt to exploit when run by `act`.
        *   **Security Hardening of Host and Docker:**  Harden the host operating system and the Docker daemon according to security best practices. This reduces the attack surface available for container escape exploits.
        *   **Least Privilege for Docker and Act:** Run the Docker daemon with the least necessary privileges. Avoid running `act` as root if possible. Running `act` as a standard user can limit the impact of a container escape, although it might not prevent all types of escapes.
        *   **Container Security Context (Awareness):** While `act` doesn't directly configure container security context, developers should be aware of and potentially configure Docker to use security features like seccomp, AppArmor, or SELinux to further restrict container capabilities and system calls. This can limit the potential damage from a container escape, even when using `act`.

## Attack Surface: [YAML Parsing Vulnerabilities in Act](./attack_surfaces/yaml_parsing_vulnerabilities_in_act.md)

*   **Description:** `act` parses YAML workflow files to understand and execute workflows. If the YAML parsing library used by `act itself` has vulnerabilities, maliciously crafted YAML workflow files could exploit these vulnerabilities *during act's parsing process*.
    *   **How act contributes:** `act`'s core functionality relies on parsing YAML workflow definitions.  Vulnerabilities in the YAML parser directly impact `act`'s security. If the parser is vulnerable, `act` becomes vulnerable to attacks triggered by malicious YAML. This is a direct vulnerability *in act itself* due to its dependency on YAML parsing.
    *   **Example:** A specially crafted YAML workflow file is designed to exploit a buffer overflow or other vulnerability in the YAML parser used by `act`. When `act` attempts to parse this malicious workflow file, the vulnerability is triggered. This could lead to arbitrary code execution within the `act` process itself, potentially giving an attacker control over the developer's machine *simply by running act on a malicious workflow file*.
    *   **Impact:** Arbitrary code execution on the developer's machine, potentially leading to full system compromise. This is a direct compromise of the developer's environment through a vulnerability in `act`'s core functionality.
    *   **Risk Severity:** **High** (potentially **Critical** depending on the nature of the vulnerability)
    *   **Mitigation Strategies:**
        *   **Keep Act Updated:**  Regularly update `act` to the latest version. Updates often include bug fixes and security patches for `act` itself and its dependencies, including YAML parsing libraries. This is the primary mitigation for YAML parsing vulnerabilities in `act`.
        *   **Workflow File Source Trust (Indirect):** Be cautious about running `act` on workflow files from untrusted sources. While the vulnerability is in `act`'s parser, the attack vector is the malicious workflow file. Only use `act` with workflow files from sources you trust.
        *   **Report Suspected Vulnerabilities:** If you suspect a YAML parsing vulnerability in `act` or encounter unexpected behavior when parsing specific YAML files, report it to the `nektos/act` maintainers so they can investigate and patch it.

