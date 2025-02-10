# Attack Tree Analysis for docker/compose

Objective: Gain unauthorized access to, control over, or data from the application or its underlying infrastructure.

## Attack Tree Visualization

Goal: Gain unauthorized access to, control over, or data from the application or its underlying infrastructure.

├── 1.  Escape Container (Breakout) [HIGH-RISK]
│   ├── 1.1 Exploit Kernel Vulnerabilities [CRITICAL]
│   │   ├── 1.1.1  Unpatched Host Kernel [HIGH-RISK] [CRITICAL]
│   │   └── 1.1.2  Misconfigured Capabilities (e.g., SYS_ADMIN, SYS_PTRACE) [HIGH-RISK]
│   ├── 1.2 Exploit Docker Daemon Vulnerabilities [CRITICAL]
│   │   ├── 1.2.1  Unpatched Docker Daemon [HIGH-RISK] [CRITICAL]
│   │   ├── 1.2.2  Docker Daemon API Exposure (without authentication) [HIGH-RISK]
│   │   └── 1.2.3  Privileged Container Execution (`--privileged`) [HIGH-RISK]
│   └── 1.3 Exploit Misconfigured Container Runtime
│       └── 1.3.2  Vulnerable runc version [HIGH-RISK]

├── 2.  Lateral Movement (Between Containers)
│   ├── 2.1  Default Network Bridging [CRITICAL]
│   │   └── 2.1.1  Unrestricted Inter-Container Communication [HIGH-RISK]
│   ├── 2.2  Shared Volumes
│   │   └── 2.2.1  Overly Permissive Volume Permissions [HIGH-RISK]

├── 3.  Denial of Service (DoS)
│   ├── 3.1  Resource Exhaustion
│   │   ├── 3.1.1  CPU/Memory Limits Not Set [HIGH-RISK]
│   │   └── 3.1.2  Disk Space Exhaustion (Logs, Data) [HIGH-RISK]
│   └── 3.2  Docker Compose Configuration Errors
│       └── 3.2.1  Infinite Restart Loops [HIGH-RISK]

├── 4.  Data Exfiltration
│   ├── 4.1  Exposed Ports [CRITICAL]
│   │   ├── 4.1.1  Unnecessary Ports Published to Host [HIGH-RISK]
│   │   └── 4.1.2  Unauthenticated Access to Exposed Ports [HIGH-RISK]
├── 5.  Privilege Escalation (Within Container) [HIGH-RISK]
    ├── 5.1 Running as Root Inside Container [CRITICAL]
    │   └── 5.1.1  Default Root User [HIGH-RISK] [CRITICAL]
    └── 5.2  Misconfigured Capabilities
        └── 5.2.1  Excessive Capabilities Granted [HIGH-RISK]

## Attack Tree Path: [1. Escape Container (Breakout) [HIGH-RISK]](./attack_tree_paths/1__escape_container__breakout___high-risk_.md)

**Description:** Attackers exploit vulnerabilities to break out of the container's isolation and gain access to the host.

*   **1.1 Exploit Kernel Vulnerabilities [CRITICAL]**
    *   **Description:**  Attackers exploit vulnerabilities in the host operating system's kernel to break out of the container's isolation and gain access to the host.
    *   **1.1.1 Unpatched Host Kernel [HIGH-RISK] [CRITICAL]**
        *   **Description:**  The host OS kernel has known vulnerabilities that have not been patched.
        *   **Likelihood:** Medium (if updates are neglected) / Low (if updates are regular)
        *   **Impact:** Very High (full host compromise)
        *   **Effort:** High (finding and exploiting a 0-day) / Medium (exploiting a known but unpatched vulnerability)
        *   **Skill Level:** Expert (0-day) / Advanced (known vulnerability)
        *   **Detection Difficulty:** Hard (0-day) / Medium (known vulnerability, if monitoring is in place)
        *   **Action:** Regularly update the host OS and Docker Engine. Use minimal base images.
    *   **1.1.2 Misconfigured Capabilities (e.g., SYS_ADMIN, SYS_PTRACE) [HIGH-RISK]**
        *   **Description:**  Containers are granted excessive Linux capabilities, allowing them to perform actions that should be restricted.
        *   **Likelihood:** Medium (common misconfiguration)
        *   **Impact:** High (increased attack surface, potential for escape)
        *   **Effort:** Low (exploiting known capability weaknesses)
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium (requires auditing container configurations)
        *   **Action:** Use `cap_drop: all` and only add necessary capabilities. Audit capabilities granted.

*   **1.2 Exploit Docker Daemon Vulnerabilities [CRITICAL]**
    *   **Description:** Attackers exploit vulnerabilities in the Docker daemon itself to gain control over containers or the host.
    *   **1.2.1 Unpatched Docker Daemon [HIGH-RISK] [CRITICAL]**
        *   **Description:** The Docker daemon has known vulnerabilities that have not been patched.
        *   **Likelihood:** Medium (if updates are neglected) / Low (if updates are regular)
        *   **Impact:** Very High (full control over all containers)
        *   **Effort:** High (finding and exploiting a 0-day) / Medium (exploiting a known vulnerability)
        *   **Skill Level:** Expert (0-day) / Advanced (known vulnerability)
        *   **Detection Difficulty:** Hard (0-day) / Medium (known vulnerability, if monitoring is in place)
        *   **Action:** Regularly update the Docker Engine.
    *   **1.2.2 Docker Daemon API Exposure (without authentication) [HIGH-RISK]**
        *   **Description:** The Docker daemon API is exposed to the network without any authentication, allowing anyone to control it.
        *   **Likelihood:** Low (requires misconfiguration and network exposure)
        *   **Impact:** Very High (full control over all containers)
        *   **Effort:** Low (if exposed, simple API calls)
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium (network monitoring can detect unusual API traffic)
        *   **Action:** Secure the Docker daemon socket. Use TLS authentication. Restrict access to the API.
    *   **1.2.3 Privileged Container Execution (`--privileged`) [HIGH-RISK]**
        *   **Description:**  A container is run with the `--privileged` flag, granting it almost full access to the host system.
        *   **Likelihood:** Low (should be avoided in production)
        *   **Impact:** Very High (near-host level access from within the container)
        *   **Effort:** Very Low (if the flag is used, exploitation is trivial)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Easy (can be detected through configuration audits)
        *   **Action:** Avoid `--privileged` flag. Use specific capabilities instead.
* **1.3 Exploit Misconfigured Container Runtime**
    *   **1.3.2  Vulnerable runc version [HIGH-RISK]**
        *   **Description:** The container runtime (runc) has known vulnerabilities.
        *   **Likelihood:** Medium (if updates are neglected) / Low (if updates are regular)
        *   **Impact:** High (potential for container escape)
        *   **Effort:** Medium (exploiting a known vulnerability)
        *   **Skill Level:** Advanced
        *   **Detection Difficulty:** Medium (if vulnerability scanning is in place)
        *   **Action:** Keep Docker Engine (and thus runc) updated.

## Attack Tree Path: [2. Lateral Movement (Between Containers)](./attack_tree_paths/2__lateral_movement__between_containers_.md)

*   **2.1 Default Network Bridging [CRITICAL]**
    *   **Description:**  Containers are connected to the default Docker bridge network, allowing unrestricted communication between them.
    *   **2.1.1 Unrestricted Inter-Container Communication [HIGH-RISK]**
        *   **Description:**  Containers on the default bridge network can freely communicate with each other.
        *   **Likelihood:** High (default behavior)
        *   **Impact:** Medium (depends on the services and data exposed)
        *   **Effort:** Very Low (no special tools needed)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Medium (requires network traffic analysis)
        *   **Action:** Define custom networks in Compose. Limit inter-container communication to only what's necessary. Use network policies.

*   **2.2 Shared Volumes**
    *   **2.2.1 Overly Permissive Volume Permissions [HIGH-RISK]**
        *   **Description:**  Shared volumes between containers have overly permissive file permissions, allowing one container to access or modify data in another.
        *   **Likelihood:** Medium (common misconfiguration)
        *   **Impact:** Medium (data modification or access)
        *   **Effort:** Low
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Easy (file system inspection)
        *   **Action:** Use read-only volumes where possible (`:ro`). Set appropriate user/group ownership and permissions on host directories.

## Attack Tree Path: [3. Denial of Service (DoS)](./attack_tree_paths/3__denial_of_service__dos_.md)

*   **3.1 Resource Exhaustion**
    *   **3.1.1 CPU/Memory Limits Not Set [HIGH-RISK]**
        *   **Description:**  Containers are not configured with CPU and memory limits, allowing them to consume all available resources and cause a denial of service.
        *   **Likelihood:** High (default behavior)
        *   **Impact:** Medium (service disruption)
        *   **Effort:** Low (can be triggered by malicious traffic or resource-intensive operations)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Easy (resource monitoring)
        *   **Action:** Define resource limits (CPU, memory) for each service in the Compose file using `deploy.resources`.
    *   **3.1.2 Disk Space Exhaustion (Logs, Data) [HIGH-RISK]**
        *   **Description:**  Containers generate excessive logs or data, filling up the available disk space and causing a denial of service.
        *   **Likelihood:** Medium (depends on logging practices and data volume)
        *   **Impact:** Medium (service disruption)
        *   **Effort:** Low (can be triggered by writing large amounts of data)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Easy (disk space monitoring)
        *   **Action:** Implement log rotation. Use volume size limits. Monitor disk usage.

*   **3.2 Docker Compose Configuration Errors**
    *   **3.2.1 Infinite Restart Loops [HIGH-RISK]**
        *   **Description:**  A misconfigured restart policy causes a container to repeatedly restart, consuming resources and potentially causing instability.
        *   **Likelihood:** Medium (common misconfiguration)
        *   **Impact:** Medium (resource consumption, potential service instability)
        *   **Effort:** Very Low (caused by configuration error)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Easy (container logs and status)
        *   **Action:** Use `restart: on-failure:5` (or similar) to limit restart attempts. Test restart policies thoroughly.

## Attack Tree Path: [4. Data Exfiltration](./attack_tree_paths/4__data_exfiltration.md)

*   **4.1 Exposed Ports [CRITICAL]**
    *   **Description:**  Containers expose ports to the host or external networks, creating potential entry points for attackers.
    *   **4.1.1 Unnecessary Ports Published to Host [HIGH-RISK]**
        *   **Description:**  More ports are exposed than are actually needed by the application.
        *   **Likelihood:** Medium (common misconfiguration)
        *   **Impact:** Medium to High (depends on the service exposed)
        *   **Effort:** Very Low (port scanning)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Easy (port scanning, network monitoring)
        *   **Action:** Only expose necessary ports. Use specific port mappings (e.g., `127.0.0.1:8000:8000` instead of `8000:8000`).
    *   **4.1.2 Unauthenticated Access to Exposed Ports [HIGH-RISK]**
        *   **Description:**  Exposed ports do not require authentication, allowing anyone to access the service.
        *   **Likelihood:** Medium (depends on service configuration)
        *   **Impact:** High (data breach, unauthorized access)
        *   **Effort:** Low (if no authentication is required)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Medium (requires monitoring access logs)
        *   **Action:** Implement authentication and authorization for all exposed services.

## Attack Tree Path: [5. Privilege Escalation (Within Container) [HIGH-RISK]](./attack_tree_paths/5__privilege_escalation__within_container___high-risk_.md)

*   **5.1 Running as Root Inside Container [CRITICAL]**
    *   **Description:** Processes within the container run as the root user, increasing the potential impact of vulnerabilities.
    *   **5.1.1 Default Root User [HIGH-RISK] [CRITICAL]**
        *   **Description:** The container's main process runs as root by default.
        *   **Likelihood:** High (default behavior in many base images)
        *   **Impact:** Medium (increased attack surface within the container)
        *   **Effort:** Very Low
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Easy (container inspection)
        *   **Action:** Use a non-root user inside the container. Specify `user:` in the Compose file.
*   **5.2 Misconfigured Capabilities**
    *   **5.2.1 Excessive Capabilities Granted [HIGH-RISK]**
        *   **Description:** Containers are granted more Linux capabilities than necessary.
        *   **Likelihood:** Medium
        *   **Impact:** Medium
        *   **Effort:** Low
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium
        *   **Action:** Use `cap_drop: all` and only add necessary capabilities.

