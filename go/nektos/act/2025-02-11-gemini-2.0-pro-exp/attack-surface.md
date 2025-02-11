# Attack Surface Analysis for nektos/act

## Attack Surface: [1. Untrusted Workflow Execution](./attack_surfaces/1__untrusted_workflow_execution.md)

*   **Description:** Running workflow files (`.github/workflows/*.yml`) from untrusted sources or with unreviewed changes. These files define the actions executed by `act`.
*   **How `act` Contributes:** `act` is the *direct execution engine* for the workflow files. It interprets and runs the commands specified within them, making it the primary enabler of this attack.
*   **Example:**
    *   A developer copies a workflow snippet from a Stack Overflow answer without fully understanding its contents. The snippet includes a `run` command that executes a Base64-encoded script, which turns out to be malicious. `act` executes this script.
    *   A malicious actor submits a pull request to an open-source project, modifying a workflow file to include a command that exfiltrates environment variables (which might contain secrets) to a remote server. If merged and run with `act`, the secrets are compromised.
*   **Impact:** Complete system compromise, data exfiltration, installation of malware, lateral movement within a network, cryptocurrency mining.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Source Control & Code Review:** Treat workflow files as *the most critical* code. Implement mandatory, thorough code reviews for *all* workflow changes, focusing on `run` commands, used actions, and any external scripts. Never run workflows from untrusted sources.
    *   **Least Privilege:** Run `act` itself with the absolute minimum necessary privileges (definitely *not* as root/administrator). Use a dedicated, non-privileged user account specifically for running `act`.
    *   **Workflow Sandboxing (Limited):** Acknowledge that `act`'s Docker-based isolation is helpful but *not* a complete security solution. It provides a layer of defense, but it's not foolproof against determined attackers or sophisticated exploits.
    * **Static Analysis:** If available, use static analysis tools specifically designed for GitHub Actions workflow files to automatically detect suspicious patterns or commands.

## Attack Surface: [2. Insecure Secret Handling](./attack_surfaces/2__insecure_secret_handling.md)

*   **Description:** Workflows often require secrets (API keys, passwords, tokens). Improper handling within the context of `act` can lead to exposure.
*   **How `act` Contributes:** `act` provides mechanisms for passing secrets to workflows (e.g., `-s`, `--secret-file`).  Misusing these features, or relying on insecure methods, directly exposes secrets during `act`'s execution.
*   **Example:**
    *   A developer uses `act -s MY_SECRET=verysecretvalue` and then includes a debugging step in the workflow: `run: env`. This prints all environment variables, including the secret, to the console output, which might be logged or otherwise exposed.
    *   A workflow file uses a hardcoded secret, and that file is committed to a version control system. `act` will use this hardcoded secret.
    *   The file used with `act --secret-file mysecrets.txt` is accidentally left with world-readable permissions (`chmod 644 mysecrets.txt`), allowing any user on the system to read the secrets.
*   **Impact:** Unauthorized access to cloud resources, data breaches, compromise of third-party services, financial loss.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Never Hardcode Secrets:** This is paramount. Secrets must *never* be directly embedded in workflow files.
    *   **Use `act`'s Secret Features *Correctly*:** Utilize `act`'s `-s` or `--secret-file` options, but *ensure* the secret file itself is protected with the *strictest* possible file permissions (e.g., `chmod 600`).  Never commit the secret file to version control.
    *   **Avoid Environment Variable Exposure:** Be extremely cautious when using environment variables for secrets with `act`.  *Never* log environment variables or expose them to untrusted processes within the workflow. Assume any process within the container can potentially access them.
    *   **Secrets Manager (Strongly Recommended):** For robust security, even in local development, integrate a dedicated secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). This adds complexity but provides a significantly higher level of protection than `act`'s built-in mechanisms.

## Attack Surface: [3. Docker Socket Exposure (If Applicable and Directly Used by `act`)](./attack_surfaces/3__docker_socket_exposure__if_applicable_and_directly_used_by__act__.md)

*   **Description:** Granting `act` access to the Docker socket (`/var/run/docker.sock`) gives it extensive control over the Docker daemon on the host machine.
*   **How `act` Contributes:** If `act` is *intentionally* run with the Docker socket mounted (e.g., `act -v /var/run/docker.sock:/var/run/docker.sock`), it directly inherits these elevated privileges. This is most common when the workflow itself needs to interact with Docker (e.g., building and pushing images).
*   **Example:**
    *   A workflow includes steps to build a Docker image and push it to a registry. To enable this, the developer runs `act` with the Docker socket mounted. A malicious or compromised action within the workflow could then use this access to create a privileged container that escapes to the host system.
    *   A workflow uses a third-party action that, unbeknownst to the developer, requires Docker socket access. Running `act` with the socket mounted allows this action to potentially compromise the host.
*   **Impact:** Complete control over the Docker daemon, high potential for host system compromise, ability to manipulate other containers running on the host, data exfiltration.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid Docker Socket Access (Primary Mitigation):** This is the most crucial step. Run `act` *without* mounting the Docker socket unless it is *absolutely, demonstrably essential* for the workflow's functionality.
    *   **Rootless Docker:** If Docker-in-Docker functionality is truly required, strongly consider using rootless Docker. This runs the Docker daemon itself without root privileges, significantly reducing the impact of a compromise.
    *   **Sysbox:** Explore using Sysbox as a container runtime. It provides enhanced isolation for nested containers, offering a more secure alternative to direct Docker socket access for Docker-in-Docker scenarios.
    *   **Least Privilege for Docker Daemon:** If socket access is unavoidable, ensure the Docker daemon itself is running with the *absolute minimum* necessary privileges. Review Docker's security documentation for best practices.

