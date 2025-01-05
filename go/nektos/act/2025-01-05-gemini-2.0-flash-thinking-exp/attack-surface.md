# Attack Surface Analysis for nektos/act

## Attack Surface: [Malicious Workflow Definitions](./attack_surfaces/malicious_workflow_definitions.md)

**Description:** A workflow file contains malicious code or commands designed to harm the system running `act`.

**How `act` Contributes:** `act` directly parses and executes the instructions within the workflow file.

**Example:** A workflow includes a `run` step with the command `rm -rf /` (on Linux/macOS) or equivalent destructive commands on other operating systems.

**Impact:**  Complete compromise of the machine running `act`, including data loss, system instability, and potential for further lateral movement if the machine has network access.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Code Review: Carefully review all workflow files before execution, especially those from untrusted sources.
* Source Control: Store workflow files in version control to track changes and identify potentially malicious modifications.
* Principle of Least Privilege: Run `act` with the minimum necessary privileges. Avoid running it as root or with highly privileged accounts.
* Static Analysis: Use static analysis tools to scan workflow files for potentially dangerous commands or patterns.

## Attack Surface: [Pulling and Executing Malicious Docker Images](./attack_surfaces/pulling_and_executing_malicious_docker_images.md)

**Description:** Workflows often specify Docker images to run actions within containers. If a workflow references a compromised or malicious Docker image, `act` will pull and execute it.

**How `act` Contributes:** `act` directly interacts with the Docker daemon to pull and run the specified images.

**Example:** A workflow uses an image from an untrusted registry that contains malware designed to escape the container and compromise the host system.

**Impact:**  Compromise of the machine running `act` through container escape vulnerabilities, execution of arbitrary code within the container with potential to access host resources.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Use Trusted Registries: Only use Docker images from trusted and reputable registries (e.g., Docker Hub official images, verified publishers).
* Image Scanning: Implement automated vulnerability scanning for Docker images before using them in workflows.
* Image Digests: Pin Docker images using their immutable digests instead of tags to ensure you are using the intended version.

## Attack Surface: [.actrc Configuration Vulnerabilities](./attack_surfaces/_actrc_configuration_vulnerabilities.md)

**Description:** The `.actrc` file allows for configuration of `act`. Malicious modifications to this file could lead to security issues.

**How `act` Contributes:** `act` reads and applies the configurations defined in the `.actrc` file.

**Example:** A compromised `.actrc` file could be modified to always pull Docker images from a malicious registry, regardless of what the workflow specifies.

**Impact:**  Subtle and persistent compromise as all subsequent `act` executions could be affected, leading to the execution of malicious code or the use of compromised images.

**Risk Severity:** High

**Mitigation Strategies:**
* Secure `.actrc` File: Protect the `.actrc` file with appropriate file system permissions to prevent unauthorized modification.
* Regularly Inspect `.actrc`:** Periodically review the contents of the `.actrc` file to ensure it hasn't been tampered with.
* Principle of Least Privilege: Ensure the user running `act` only has necessary permissions to modify `.actrc`.

## Attack Surface: [Environment Variable Manipulation and Exposure](./attack_surfaces/environment_variable_manipulation_and_exposure.md)

**Description:** Workflows can access environment variables. If sensitive information is stored in environment variables or if malicious environment variables are injected, it can be exploited.

**How `act` Contributes:** `act` makes environment variables available to the running workflows, mirroring how GitHub Actions operates.

**Example:** A workflow unintentionally logs an API key stored in an environment variable, or a malicious actor injects a harmful environment variable that is used by a subsequent action.

**Impact:**  Exposure of sensitive credentials, potential for command injection if environment variables are used in shell commands without proper sanitization.

**Risk Severity:** High

**Mitigation Strategies:**
* Avoid Storing Secrets in Environment Variables: Use secure secret management solutions instead of directly storing sensitive data in environment variables.
* Sanitize Input: If environment variables are used in shell commands within workflows, ensure proper sanitization to prevent command injection.
* Review Workflow Logs: Regularly review workflow logs for accidental exposure of sensitive information.

## Attack Surface: [Local File System Access and Manipulation](./attack_surfaces/local_file_system_access_and_manipulation.md)

**Description:** Workflows executed by `act` have access to the local file system of the user running `act`. This can be exploited to read sensitive files or write malicious ones.

**How `act` Contributes:** `act` executes workflows in an environment where they can interact with the file system, similar to GitHub Actions runners.

**Example:** A malicious workflow reads SSH private keys from `~/.ssh` or writes a backdoor script to a common startup directory.

**Impact:**  Data breaches through unauthorized access to sensitive files, persistent compromise through the introduction of malicious files.

**Risk Severity:** High

**Mitigation Strategies:**
* Principle of Least Privilege: Run `act` with a user account that has limited access to sensitive files and directories.
* Input Validation: If workflows accept file paths as input, validate and sanitize them to prevent path traversal attacks.

## Attack Surface: [Vulnerabilities within the `act` Tool Itself](./attack_surfaces/vulnerabilities_within_the__act__tool_itself.md)

**Description:** Like any software, `act` itself may contain bugs or security vulnerabilities that could be exploited.

**How `act` Contributes:** The vulnerability exists within the `act` codebase.

**Example:** A buffer overflow vulnerability in `act` could allow an attacker to execute arbitrary code on the machine running `act` by crafting a specific malicious workflow.

**Impact:**  Complete compromise of the machine running `act`, depending on the nature of the vulnerability.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Keep `act` Updated: Regularly update `act` to the latest version to benefit from security patches and bug fixes.
* Monitor Security Advisories: Stay informed about any reported security vulnerabilities in `act`.
* Use Official Releases: Only download `act` from official and trusted sources.

