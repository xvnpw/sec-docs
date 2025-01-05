# Attack Tree Analysis for moby/moby

Objective: To compromise the application utilizing the Moby/Docker platform by exploiting the most probable and impactful vulnerabilities within the containerization environment.

## Attack Tree Visualization

```
* **HIGH RISK** [CRITICAL NODE] Exploit Container Vulnerabilities
    * **HIGH RISK** Exploit Vulnerabilities in Container Image
        * **HIGH RISK** Pull and Run Malicious Container Image
            * **HIGH RISK** Exploit Misconfiguration in Application to Pull Untrusted Image
        * **HIGH RISK** Exploit Vulnerabilities in Base Image
        * **HIGH RISK** Exploit Vulnerabilities Introduced During Image Build Process
            * **HIGH RISK** Extract Secrets or Sensitive Data Embedded in Image Layers
    * **HIGH RISK** [CRITICAL NODE] Achieve Container Escape
        * **HIGH RISK** Exploit Misconfigurations in Container Runtime
            * **CRITICAL NODE** **HIGH RISK** Abuse Privileged Containers
            * **HIGH RISK** Abuse Host Path Mounts with Write Access
* **HIGH RISK** [CRITICAL NODE] Exploit Docker Daemon
    * **HIGH RISK** Gain Unauthorized Access to Docker Daemon
        * **CRITICAL NODE** **HIGH RISK** Exploit Unprotected Docker Daemon Socket
            * **HIGH RISK** Access the socket through exposed network port
            * **HIGH RISK** Gain local access to the socket (e.g., through compromised application user)
    * **HIGH RISK** Execute Malicious Operations on Docker Daemon
        * **HIGH RISK** Create and Run Malicious Containers
        * **HIGH RISK** Modify Existing Containers
        * **HIGH RISK** Access Sensitive Data Managed by Docker
* Exploit Container Storage
    * **HIGH RISK** Exploit Insecure Volume Permissions
        * Access volumes mounted with overly permissive permissions
```


## Attack Tree Path: [**HIGH RISK [CRITICAL NODE] Exploit Container Vulnerabilities:**](./attack_tree_paths/high_risk__critical_node__exploit_container_vulnerabilities.md)

* **HIGH RISK Exploit Vulnerabilities in Container Image:**
    * **HIGH RISK Pull and Run Malicious Container Image:**
        * **HIGH RISK Exploit Misconfiguration in Application to Pull Untrusted Image:**
            * Attack Vector: The application's logic for pulling container images is flawed, allowing an attacker to manipulate the image name or registry source, leading to the execution of a malicious image.
    * **HIGH RISK Exploit Vulnerabilities in Base Image:**
        * Attack Vector: The container image is built upon a base image containing known vulnerabilities (CVEs) that can be exploited to compromise the container or potentially escape it.
    * **HIGH RISK Exploit Vulnerabilities Introduced During Image Build Process:**
        * **HIGH RISK Extract Secrets or Sensitive Data Embedded in Image Layers:**
            * Attack Vector: Sensitive information like API keys, passwords, or private keys are inadvertently included in the container image layers, making them accessible to anyone who can pull the image.

## Attack Tree Path: [**HIGH RISK [CRITICAL NODE] Achieve Container Escape:**](./attack_tree_paths/high_risk__critical_node__achieve_container_escape.md)

* **HIGH RISK Exploit Misconfigurations in Container Runtime:**
    * **CRITICAL NODE HIGH RISK Abuse Privileged Containers:**
        * Attack Vector: The container is run with the `--privileged` flag, granting it almost all the capabilities of the host operating system, making container escape relatively easy.
    * **HIGH RISK Abuse Host Path Mounts with Write Access:**
        * Attack Vector: A directory from the host system is mounted into the container with write permissions, allowing an attacker inside the container to modify files on the host.

## Attack Tree Path: [**HIGH RISK [CRITICAL NODE] Exploit Docker Daemon:**](./attack_tree_paths/high_risk__critical_node__exploit_docker_daemon.md)

* **HIGH RISK Gain Unauthorized Access to Docker Daemon:**
    * **CRITICAL NODE HIGH RISK Exploit Unprotected Docker Daemon Socket:**
        * **HIGH RISK Access the socket through exposed network port:**
            * Attack Vector: The Docker daemon's socket is exposed on a network port without proper authentication, allowing remote attackers to connect and issue Docker commands.
        * **HIGH RISK Gain local access to the socket (e.g., through compromised application user):**
            * Attack Vector: An attacker compromises the user account or process under which the application runs, gaining local access to the Docker daemon's socket and the ability to control Docker.
    * **HIGH RISK Execute Malicious Operations on Docker Daemon:**
        * **HIGH RISK Create and Run Malicious Containers:**
            * Attack Vector: After gaining access to the Docker daemon, the attacker creates and runs new containers designed to further compromise the host or other containers.
        * **HIGH RISK Modify Existing Containers:**
            * Attack Vector: The attacker injects malicious code or modifies configurations within existing running containers to gain control or steal data.
        * **HIGH RISK Access Sensitive Data Managed by Docker:**
            * Attack Vector: The attacker uses their access to the Docker daemon to retrieve sensitive information like secrets or configurations stored and managed by Docker.

## Attack Tree Path: [* **Exploit Container Storage:**](./attack_tree_paths/exploit_container_storage.md)

    * **HIGH RISK Exploit Insecure Volume Permissions:**
        * Attack Vector: Container volumes are configured with overly permissive permissions, allowing unauthorized access to the data stored within them, potentially exposing sensitive information.

