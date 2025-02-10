# Attack Surface Analysis for containers/podman

## Attack Surface: [Container Escape (Rootful Mode)](./attack_surfaces/container_escape__rootful_mode_.md)

*   **Description:** A vulnerability within the container runtime or kernel allows a process inside a container to break out and gain host access.
*   **How Podman Contributes:** Rootful Podman runs containers with *host root privileges*. A successful escape grants the attacker *root access to the entire host*.
*   **Example:** A `runc` vulnerability is exploited to overwrite host binaries, allowing arbitrary code execution with root privileges.
*   **Impact:** Complete host system compromise: data theft, system modification, lateral movement.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Use Rootless Mode:** *Primary* mitigation. Significantly reduces escape impact.
    *   **Keep Podman/Dependencies Updated:** Regularly update Podman, `runc`, `crun`, and the host kernel.
    *   **Use Seccomp, AppArmor, or SELinux:** Strict security profiles to limit system calls and resource access.
    *   **Minimize Container Capabilities:** Grant only *minimum necessary* capabilities. Avoid `--privileged`.
    *   **Container-Specific Security Tools:** Use vulnerability scanners and runtime security monitors.

## Attack Surface: [Container Escape (Rootless Mode)](./attack_surfaces/container_escape__rootless_mode_.md)

*   **Description:** A vulnerability allows escaping the user namespace, gaining elevated privileges *within the user's context*.
*   **How Podman Contributes:** While rootless isolates container root from host root, vulnerabilities can still grant the attacker the privileges of the user running Podman.
*   **Example:** A setuid binary vulnerability inside the container is exploited to gain the user's host privileges, accessing the user's files/processes.
*   **Impact:** Compromise of the user's account, access to user data, potential for further attacks within the user's context.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Keep Podman/Dependencies Updated:** Regularly update Podman and related components.
    *   **Use Seccomp, AppArmor, or SELinux:** Strict security profiles, even in rootless mode.
    *   **Minimize Container Capabilities:** Grant only necessary capabilities.
    *   **Avoid setuid/setgid Binaries in Images:** Remove or carefully audit setuid/setgid binaries within images.
    *   **Regularly Audit User Permissions:** Ensure the user running Podman doesn't have excessive host privileges.

## Attack Surface: [Image Vulnerabilities (Malicious Images)](./attack_surfaces/image_vulnerabilities__malicious_images_.md)

*   **Description:** Using container images containing known vulnerabilities or malicious code.
*   **How Podman Contributes:** Podman pulls and runs images. A compromised image means the container executes malicious code.
*   **Example:** A seemingly legitimate image on a public registry contains a backdoor that opens a reverse shell on startup.
*   **Impact:** Depends on the malicious code. Ranges from data exfiltration to complete system compromise (especially rootful).
*   **Risk Severity:** High to Critical (depends on image and Podman mode)
*   **Mitigation Strategies:**
    *   **Use Trusted Registries:** Only pull from trusted sources (official or private registries with strict access).
    *   **Verify Image Signatures:** Use Podman's signature verification (`containers/image`) to ensure integrity.
    *   **Scan Images for Vulnerabilities:** Use scanners (Clair, Trivy, Anchore) *before* running containers.
    *   **Trusted Base Images:** Use minimal, well-maintained base images from reputable sources.
    *   **Secure Image Build Process:** Secure the build environment; ensure only authorized code is included.

## Attack Surface: [Compromised `~/.config/containers` (Rootless Mode)](./attack_surfaces/compromised__~_configcontainers___rootless_mode_.md)

*   **Description:** An attacker accesses the user's home directory and modifies Podman's configuration or stored images.
*   **How Podman Contributes:** Rootless Podman stores configuration/data in the user's home directory.
*   **Example:** An attacker exploits a *separate* vulnerability to access the user's account, then modifies `~/.config/containers/storage.conf` to point to a malicious image repository.
*   **Impact:** Attacker controls which images are run, potentially executing malicious code.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure User Accounts:** Strong passwords, multi-factor authentication.
    *   **Audit User Permissions:** Users have only necessary permissions on their home directories.
    *   **Monitor File Integrity:** Detect unauthorized changes to critical files/directories.
    *   **Restrict Home Directory Access:** Limit access from other users/processes.

## Attack Surface: [Improper Volume Mounts](./attack_surfaces/improper_volume_mounts.md)

*   **Description:** Mounting sensitive host directories into containers, allowing a compromised container to access/modify host data.
*   **How Podman Contributes:** Podman allows mounting host directories via `-v` or `--volume`.
*   **Example:** A container is run with `-v /etc:/mnt/host-etc`, giving it read-write access to the host's `/etc`. A compromised container could modify system configuration.
*   **Impact:** Data leakage, system modification, potential privilege escalation.
*   **Risk Severity:** High to Critical (depends on mounted directory)
*   **Mitigation Strategies:**
    *   **Avoid Sensitive Directory Mounts:** Only mount *necessary* directories; avoid `/etc`, `/bin`, `/sbin`, `/usr`.
    *   **Read-Only Mounts:** If possible, mount directories read-only (`:ro`) to prevent modification.
    *   **Named Volumes:** Use named volumes instead of direct host mounts for better isolation.
    *   **Review Mount Permissions:** Ensure mounted directories have appropriate host permissions.

## Attack Surface: [Command Injection in Podman Commands](./attack_surfaces/command_injection_in_podman_commands.md)

* **Description:** User input constructs Podman commands without sanitization, allowing arbitrary command injection.
* **How Podman Contributes:** If an application uses user input to build `podman run/exec` (or others), it's vulnerable.
* **Example:** An app takes a container name as input and uses it directly: `podman exec $userInput sh`.  An attacker provides `; rm -rf / #`.
* **Impact:** Arbitrary command execution within the container or potentially on the host (especially rootful).
* **Risk Severity:** High to Critical
* **Mitigation Strategies:**
    * **Avoid Direct User Input:** Don't construct Podman commands directly from user input.
    * **Parameterized Commands:** Use libraries/APIs with parameterized commands to prevent injection.
    * **Sanitize/Validate Input:** If using user input, *thoroughly* sanitize and validate (whitelist, not blacklist).
    * **Dedicated API:** Use a well-vetted library (e.g., Python library for Podman API) instead of shell commands.

