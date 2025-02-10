# Threat Model Analysis for containers/podman

## Threat: [Rootless Mode Bypass/Escalation](./threats/rootless_mode_bypassescalation.md)

*   **Threat:** Rootless Mode Bypass/Escalation

    *   **Description:** An attacker exploits a vulnerability in user namespace mapping, cgroups, or other kernel features used by Podman's rootless mode. The attacker crafts a malicious container image or exploits a vulnerability in a running container to gain elevated privileges outside the container, potentially achieving root access on the host system. This bypasses the core security feature of rootless Podman.
    *   **Impact:** Complete host system compromise. The attacker gains full control over the host, including all other containers, data, and potentially the ability to pivot to other systems on the network.
    *   **Affected Component:** `libpod` (Podman's core library), user namespace implementation in the Linux kernel, cgroups implementation, container runtime (e.g., `runc`, `crun`).  *Directly involves Podman's core functionality and its interaction with the kernel.*
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Keep the host kernel and Podman updated to the latest versions.
        *   Regularly audit user namespace and cgroup configurations.
        *   Employ SELinux or AppArmor in enforcing mode.
        *   Use minimal base images.
        *   Monitor system calls and resource usage for anomalies.
        *   Use dedicated, non-login user accounts for rootless containers.
        *   Avoid mounting sensitive host directories.

## Threat: [Rootful Container Misconfiguration (Privilege Escalation)](./threats/rootful_container_misconfiguration__privilege_escalation_.md)

*   **Threat:** Rootful Container Misconfiguration (Privilege Escalation)

    *   **Description:** If rootful containers are used (against best practices), an attacker exploits a misconfigured container running with excessive privileges (e.g., `--privileged`, unnecessary capabilities, or insecure host mounts). The attacker gains control *inside* the container and then leverages the misconfiguration, facilitated by Podman's handling of these options, to gain root access on the host.
    *   **Impact:** Complete host system compromise.
    *   **Affected Component:** `libpod`, container runtime (e.g., `runc`, `crun`), container configuration (e.g., `podman run` options). *Directly involves how Podman interprets and enforces (or fails to enforce) security-related command-line options.*
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strongly prefer rootless mode.**
        *   If rootful is unavoidable, use the principle of least privilege: drop unnecessary capabilities (`--cap-drop`).
        *   Restrict host mounts; use read-only mounts (`:ro`).
        *   Avoid `--privileged` unless absolutely necessary.
        *   Implement container image signing and verification.
        *   Use a restricted user *inside* the container.

## Threat: [Malicious Image from Untrusted Registry (Code Injection)](./threats/malicious_image_from_untrusted_registry__code_injection_.md)

*   **Threat:** Malicious Image from Untrusted Registry (Code Injection)

    *   **Description:** An attacker publishes a malicious image. A user, using Podman, unknowingly pulls and runs this image. Podman executes the malicious code within the container. While the container *should* provide isolation, the initial act of pulling and running the image is facilitated by Podman.
    *   **Impact:**  Compromise of the containerized application and potentially the host system (if combined with escape vulnerabilities).
    *   **Affected Component:** `libpod` (image pulling), container runtime. *Directly involves Podman's image management capabilities.*
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use only trusted registries.
        *   Implement image scanning.
        *   Use image signing and verification (Podman's signature verification).
        *   Regularly update base images.
        *   Use minimal base images.

## Threat: [Image Layer Caching Poisoning (Code Injection)](./threats/image_layer_caching_poisoning__code_injection_.md)

*   **Threat:** Image Layer Caching Poisoning (Code Injection)

    *   **Description:** An attacker gains access to Podman's build cache and injects malicious code. Subsequent `podman build` commands unknowingly incorporate the attacker's code. This is a direct attack on Podman's build process.
    *   **Impact:** Compromise of the containerized application and potentially the host.
    *   **Affected Component:**  Podman's build process (`podman build`), build cache storage. *Directly involves Podman's build functionality.*
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use a secure build environment.
        *   Regularly clear the build cache.
        *   Use isolated build systems.
        *   Implement strong access controls on build servers and cache storage.
        *   Use content-addressable storage for image layers.

## Threat: [Container Network Exposure (Unauthorized Access)](./threats/container_network_exposure__unauthorized_access_.md)

*   **Threat:** Container Network Exposure (Unauthorized Access)

    *   **Description:**  A container's network is misconfigured *using Podman's networking features*, exposing services. An attacker accesses these exposed services. The vulnerability lies in how Podman's network configuration is used (or misused).
    *   **Impact:** Unauthorized access to the application and its data.
    *   **Affected Component:** `libpod` (network management), CNI plugins, container network configuration (`podman run` options, network creation). *Directly involves Podman's network management capabilities.*
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use Podman's network modes appropriately.
        *   Explicitly expose only necessary ports (`-p` or `--publish`).
        *   Avoid `host` mode unless strictly necessary.
        *   Use container network policies (Calico, Cilium).
        *   Implement host firewalls.
        *   Use dedicated network namespaces for pods.

## Threat: [Vulnerabilities in Podman Daemon or `conmon` (Privilege Escalation)](./threats/vulnerabilities_in_podman_daemon_or__conmon___privilege_escalation_.md)

*   **Threat:** Vulnerabilities in Podman Daemon or `conmon` (Privilege Escalation)

    *   **Description:**  A vulnerability is discovered in the `podman` daemon (if used in daemon mode) or the `conmon` process (always used). An attacker exploits this vulnerability *directly in Podman's code* to gain control.
    *   **Impact:**  Potential for complete host compromise.
    *   **Affected Component:** `podman` daemon (if used), `conmon`, `libpod`. *Directly involves vulnerabilities within Podman itself.*
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Keep Podman and dependencies updated.
        *   Review security advisories and apply patches.
        *   Run Podman with least privileges (prefer rootless).
        *   Monitor Podman's logs.

## Threat: [Improper Socket Permissions (Unauthorized Control)](./threats/improper_socket_permissions__unauthorized_control_.md)

* **Threat:** Improper Socket Permissions (Unauthorized Control)
    * **Description:** The Podman socket is exposed with overly permissive permissions. An unauthorized user on the host gains access to the socket and can issue commands *directly to Podman*, controlling containers.
    * **Impact:** Unauthorized control over containers, potential for data breaches, denial of service, or further exploitation.
    * **Affected Component:** Podman socket (`/run/podman/podman.sock` or user-specific socket), system permissions. *Directly involves the Podman API endpoint.*
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Ensure the Podman socket has appropriate permissions.
        * Use SSH tunneling for remote access.
        * Avoid exposing the socket to untrusted networks.

## Threat: [Data Leakage via Shared Volumes (Data Exposure)](./threats/data_leakage_via_shared_volumes__data_exposure_.md)

* **Threat:** Data Leakage via Shared Volumes (Data Exposure)
    * **Description:** Sensitive data is stored in a volume that is shared between multiple containers *using Podman's volume management*. A compromised container gains access to this data due to Podman's handling of the shared volume.
    * **Impact:** Data breach, unauthorized access to sensitive information.
    * **Affected Component:** Podman volumes (`podman volume`), container configuration. *Directly involves Podman's volume management features.*
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Use separate volumes for different containers.
        * Use read-only mounts (`:ro`).
        * Encrypt sensitive data in volumes.
        * Implement access controls on the host.
        * Avoid mounting host directories directly.

