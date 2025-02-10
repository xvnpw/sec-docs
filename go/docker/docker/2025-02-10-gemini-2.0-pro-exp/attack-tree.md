# Attack Tree Analysis for docker/docker

Objective: Gain Unauthorized Root-Level Access to Host or Other Containers

## Attack Tree Visualization

Goal: Gain Unauthorized Root-Level Access to Host or Other Containers
├── 1. Escape Container
│   ├── 1.1 Exploit Kernel Vulnerabilities
│   │   ├── 1.1.1  Unpatched Host Kernel Vulnerability (CVE-XXXX-XXXX) [CRITICAL]
│   │   │   └── Action:  Craft exploit within container targeting specific kernel vulnerability.
│   │   └── 1.1.3  Race Condition in Container Runtime (e.g., runc CVE-2019-5736, CVE-2024-21626) [CRITICAL]
│   │   │   └── Action:  Exploit race condition to overwrite host `runc` binary.
│   ├── 1.2  Exploit Docker Daemon Vulnerabilities
│   │   ├── 1.2.1  Docker API Exposure (Unauthenticated/Misconfigured) [CRITICAL]
│   │   │   ├── -> HIGH RISK -> Action:  Send malicious requests to Docker API (e.g., create privileged container, exec).
│   │   │   └── Mitigation:  Require authentication, restrict API access (network policies, TLS).
│   │   └── 1.2.2  Vulnerability in Docker Daemon (CVE-XXXX-XXXX) [CRITICAL]
│   │   │   └── Action:  Craft exploit targeting specific Docker daemon vulnerability.
│   ├── -> HIGH RISK -> 1.3  Exploit Misconfigured Container Settings
│   │   ├── -> HIGH RISK -> 1.3.1  Running Container as Root (Default User)
│   │   │   └── Action:  If container process compromised, attacker has root privileges *within* the container.
│   │   ├── -> HIGH RISK -> 1.3.2  Excessive Capabilities Granted (e.g., CAP_SYS_ADMIN, CAP_NET_ADMIN) [CRITICAL]
│   │   │   └── Action:  Use granted capabilities to manipulate kernel, network, or other containers.
│   │   ├── -> HIGH RISK -> 1.3.3  Mounted Host Directories/Files (/proc, /sys, /dev, docker.sock) [CRITICAL]
│   │   │   ├── Action:  Write to sensitive host files, potentially modifying kernel modules or gaining control of Docker daemon.
│   │   │   └── Mitigation:  Use read-only mounts, avoid mounting sensitive host paths.
│   └── 1.4  Leverage Container Breakout Techniques
│       └── 1.4.2 Leaky Vessels (CVE-2024-21626) - runc [CRITICAL]
│           └── Action: Exploit vulnerability in runc to escape container.
├── 2. Compromise Other Containers
│   └── 2.2  Docker API Access (from within compromised container) [CRITICAL]
│       └── Action:  If Docker API is accessible, create/modify/control other containers.
└── 3.  Lateral Movement on Host (Post-Escape) [CRITICAL]
    ├── 3.1  Exploit Host Vulnerabilities
    │   └── Action:  Use standard privilege escalation techniques on the host OS.
    ├── 3.2  Access Host Resources
    │   └── Action:  Read/write sensitive files, access network resources, etc.
    └── 3.3  Attack Other Systems on the Network
        └── Action:  Use the compromised host as a pivot point to attack other systems.

## Attack Tree Path: [1.1.1 Unpatched Host Kernel Vulnerability [CRITICAL]](./attack_tree_paths/1_1_1_unpatched_host_kernel_vulnerability__critical_.md)

*   **Description:** The host operating system's kernel has a known vulnerability that has not been patched. Attackers can craft exploits that run within a container and target this vulnerability to gain elevated privileges on the host.
*   **Example:** A vulnerability allowing arbitrary code execution in the kernel.
*   **Mitigation:** Keep the host OS and kernel fully patched and up-to-date. Use a minimal, hardened host OS. Consider using a security-enhanced kernel (grsecurity, SELinux, AppArmor).

## Attack Tree Path: [1.1.3 Race Condition in Container Runtime (runc) [CRITICAL]](./attack_tree_paths/1_1_3_race_condition_in_container_runtime__runc___critical_.md)

*   **Description:** Vulnerabilities in the container runtime (like `runc`) can be exploited to escape the container. Race conditions are timing-dependent vulnerabilities where the attacker tries to win a "race" against the system to perform a malicious action.
*   **Example:** CVE-2019-5736 (overwriting `/proc/self/exe`), CVE-2024-21626 (Leaky Vessels).
*   **Mitigation:** Keep the container runtime (e.g., `runc`, `containerd`) updated to the latest version.

## Attack Tree Path: [1.2.1 Docker API Exposure (Unauthenticated/Misconfigured) [CRITICAL] -> HIGH RISK ->](./attack_tree_paths/1_2_1_docker_api_exposure__unauthenticatedmisconfigured___critical__-_high_risk_-.md)

*   **Description:** The Docker API is exposed without authentication or with weak authentication, allowing anyone to send commands to the Docker daemon.
*   **Example:** An attacker can use `curl` to create a new container with privileged access, mount the host filesystem, and effectively gain root access to the host.
*   **Mitigation:** *Never* expose the Docker API unauthenticated. Use TLS with client certificate authentication. Restrict access using firewall rules or network policies.

## Attack Tree Path: [1.2.2 Vulnerability in Docker Daemon [CRITICAL]](./attack_tree_paths/1_2_2_vulnerability_in_docker_daemon__critical_.md)

*   **Description:** The Docker daemon itself has a vulnerability that can be exploited.
*   **Example:** A vulnerability allowing remote code execution in the daemon.
*   **Mitigation:** Keep the Docker Engine updated to the latest version.

## Attack Tree Path: [-> HIGH RISK -> 1.3 Exploit Misconfigured Container Settings](./attack_tree_paths/-_high_risk_-_1_3_exploit_misconfigured_container_settings.md)

This entire section is high-risk due to common misconfigurations

## Attack Tree Path: [-> HIGH RISK -> 1.3.1 Running Container as Root (Default User)](./attack_tree_paths/-_high_risk_-_1_3_1_running_container_as_root__default_user_.md)

*   **Description:** The container's main process runs as the root user *inside* the container. While this doesn't directly grant host access, it significantly simplifies escaping the container if another vulnerability is found.
*   **Example:** If a web application inside the container has a remote code execution vulnerability, the attacker gains root privileges *within* the container, making further attacks much easier.
*   **Mitigation:** Use the `USER` instruction in the Dockerfile to run the container process as a non-root user.

## Attack Tree Path: [-> HIGH RISK -> 1.3.2 Excessive Capabilities Granted [CRITICAL]](./attack_tree_paths/-_high_risk_-_1_3_2_excessive_capabilities_granted__critical_.md)

*   **Description:** The container is granted more Linux capabilities than it needs. Capabilities like `CAP_SYS_ADMIN` are particularly dangerous.
*   **Example:** A container with `CAP_SYS_ADMIN` can mount filesystems, modify kernel parameters, and perform other actions that can lead to container escape.
*   **Mitigation:** Use the `--cap-drop=all` flag and then selectively add back only the *absolutely necessary* capabilities using `--cap-add`.

## Attack Tree Path: [-> HIGH RISK -> 1.3.3 Mounted Host Directories/Files [CRITICAL]](./attack_tree_paths/-_high_risk_-_1_3_3_mounted_host_directoriesfiles__critical_.md)

*   **Description:** Sensitive host directories or files (e.g., `/proc`, `/sys`, `/dev`, `/var/run/docker.sock`) are mounted into the container.
*   **Example:** Mounting `/var/run/docker.sock` allows the container process to control the Docker daemon on the host. Mounting `/proc` or `/sys` can allow modification of kernel parameters.
*   **Mitigation:** Avoid mounting sensitive host paths. Use read-only mounts (`:ro`) whenever possible.

## Attack Tree Path: [1.4.2 Leaky Vessels (CVE-2024-21626) - runc [CRITICAL]](./attack_tree_paths/1_4_2_leaky_vessels__cve-2024-21626__-_runc__critical_.md)

* **Description:** A specific, recent vulnerability in `runc` that allows container escape.
* **Mitigation:** Update `runc` to a patched version.

## Attack Tree Path: [2.2 Docker API Access (from within compromised container) [CRITICAL]](./attack_tree_paths/2_2_docker_api_access__from_within_compromised_container___critical_.md)

*   **Description:** A compromised container gains access to the Docker API (usually because the Docker socket is mounted inside).
*   **Example:** The attacker can use the Docker API from within the compromised container to create new privileged containers, stop/start other containers, or exfiltrate data.
*   **Mitigation:** Never mount the Docker socket (`/var/run/docker.sock`) into a container unless absolutely necessary, and if you do, understand the extreme risk and implement strict controls.

## Attack Tree Path: [3. Lateral Movement on Host (Post-Escape) [CRITICAL]](./attack_tree_paths/3__lateral_movement_on_host__post-escape___critical_.md)

This entire section is critical after a successful escape

## Attack Tree Path: [3.1 Exploit Host Vulnerabilities](./attack_tree_paths/3_1_exploit_host_vulnerabilities.md)

*   **Description:** After escaping the container, the attacker attempts to escalate privileges on the host OS using standard techniques.
*   **Mitigation:** Keep the host OS patched, use strong passwords, and implement least privilege principles.

## Attack Tree Path: [3.2 Access Host Resources](./attack_tree_paths/3_2_access_host_resources.md)

*   **Description:** The attacker accesses sensitive files, network resources, or other data on the host.
*   **Mitigation:** Implement strong access controls and data encryption.

## Attack Tree Path: [3.3 Attack Other Systems on the Network](./attack_tree_paths/3_3_attack_other_systems_on_the_network.md)

*   **Description:** The compromised host is used as a pivot point to attack other systems on the network.
*   **Mitigation:** Implement network segmentation and intrusion detection/prevention systems.

