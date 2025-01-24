# Mitigation Strategies Analysis for containers/podman

## Mitigation Strategy: [Prefer Rootless Podman](./mitigation_strategies/prefer_rootless_podman.md)

*   **Description:**
    1.  **Configure Podman for Rootless Mode:** Ensure Podman is configured to run in rootless mode by default. This is often the default in modern Podman installations. Verify by checking Podman configuration files (e.g., `containers.conf`) or running `podman info` and looking for `rootless: true`.
    2.  **User Context for Podman Commands:** When running Podman commands (e.g., `podman run`, `podman build`), ensure they are executed by a non-root user. Avoid using `sudo` with Podman commands unless absolutely necessary for specific rootful operations.
    3.  **Migrate to Rootless Configurations:** Transition existing services running with rootful Podman to rootless configurations. This may involve adjusting file permissions, volume mounts, and network configurations to be compatible with rootless operation within Podman.

*   **List of Threats Mitigated:**
    *   **Container Escape Privilege Escalation (High Severity):**  If a container process escapes in rootful mode, it can potentially gain root privileges on the host system. Rootless mode, a core Podman feature, significantly reduces this risk by isolating container processes within the user namespace.
    *   **Host System Compromise from Container Vulnerability (High Severity):** A vulnerability in a containerized application running in rootful mode could be exploited to compromise the entire host system due to the container's root privileges. Rootless Podman limits the blast radius of such compromises to the user's scope.

*   **Impact:**
    *   **Container Escape Privilege Escalation:** High Risk Reduction. Rootless mode fundamentally changes the privilege model within Podman, making root privilege escalation from a container significantly harder.
    *   **Host System Compromise from Container Vulnerability:** High Risk Reduction. Limits the potential damage to the user's scope when using Podman, preventing direct root access to the host.

*   **Currently Implemented:**
    *   Implemented for development and staging environments. Podman is configured in rootless mode for all developers and CI/CD pipelines using Podman.

*   **Missing Implementation:**
    *   Not fully implemented in production environment yet. Some legacy services are still running in rootful mode due to initial setup and perceived complexity of migration to rootless Podman configurations. Production migration to rootless Podman is planned for next quarter.

## Mitigation Strategy: [Resource Limits (Podman Configuration)](./mitigation_strategies/resource_limits__podman_configuration_.md)

*   **Description:**
    1.  **Define Resource Requirements:**  For each containerized application, analyze and define its resource requirements (CPU, memory, storage).
    2.  **Implement Resource Limits in Podman:** Use Podman's resource limiting flags directly in `podman run` commands or within Podman Compose files. Utilize flags like `--memory`, `--cpus`, `--storage-opt` to enforce these limits during container creation and runtime.
    3.  **Monitor Resource Usage (Podman Integration):** Integrate monitoring tools to track container resource usage as reported by Podman. This ensures limits are appropriately set and containers are not being resource-starved or excessively consuming resources within the Podman environment.
    4.  **Adjust Limits as Needed (Podman Configuration):**  Regularly review and adjust resource limits within Podman configurations based on application performance and observed resource consumption patterns reported by Podman or monitoring tools.

*   **List of Threats Mitigated:**
    *   **Denial of Service (DoS) via Resource Exhaustion (High to Medium Severity):** A compromised or poorly behaving container, if not limited by Podman, could consume excessive resources (CPU, memory), impacting the performance of the host system and other containers managed by Podman, potentially leading to a DoS.
    *   **Resource Starvation of Other Containers (Medium Severity):**  Uncontrolled resource consumption by one container managed by Podman can starve other containers on the same host managed by Podman, affecting their performance and availability.

*   **Impact:**
    *   **Denial of Service (DoS) via Resource Exhaustion:** Medium Risk Reduction. Podman's resource limits restrict the impact of a single container on host resources, making it harder to cause a host-level DoS within the Podman managed environment.
    *   **Resource Starvation of Other Containers:** High Risk Reduction. Podman's resource management prevents one container from monopolizing resources and impacting other containers managed by Podman on the same host.

*   **Currently Implemented:**
    *   Resource limits are defined in Podman Compose files for staging and development environments. Basic monitoring of resource usage of Podman containers is in place using Prometheus and Grafana.

*   **Missing Implementation:**
    *   Resource limits are not consistently enforced in production deployments using Podman configurations. More granular resource limits and QoS (Quality of Service) configurations within Podman are needed for production. Automated alerts for resource limit breaches within Podman are not fully configured.

## Mitigation Strategy: [Drop Unnecessary Capabilities (Podman Configuration)](./mitigation_strategies/drop_unnecessary_capabilities__podman_configuration_.md)

*   **Description:**
    1.  **Analyze Container Capabilities:**  For each containerized application, analyze the Linux capabilities it actually requires to function correctly within the Podman environment.
    2.  **Drop Capabilities using `--cap-drop` in Podman:**  Use the `--cap-drop` flag in `podman run` commands or Podman Compose files to drop all capabilities except those explicitly required. Start by dropping `ALL` and then selectively add back only necessary capabilities using `--cap-add` within Podman commands.
    3.  **Principle of Least Privilege (Podman):**  Apply the principle of least privilege when configuring Podman containers. Only grant containers the absolute minimum capabilities they need through Podman's capability management features.
    4.  **Document Required Capabilities (Podman Context):**  Document the required capabilities for each containerized application within the context of Podman configurations for future reference and maintenance.

*   **List of Threats Mitigated:**
    *   **Privilege Escalation within Container (Medium to High Severity):**  Unnecessary capabilities granted to a container by Podman increase the attack surface and can be exploited for privilege escalation within the container, potentially leading to container escape from the Podman environment.
    *   **Container Escape via Capability Abuse (Medium Severity):** Certain capabilities, if misused within a Podman container, can facilitate container escapes and compromise the host system. Dropping unnecessary capabilities using Podman reduces the risk of such escapes.

*   **Impact:**
    *   **Privilege Escalation within Container:** Medium Risk Reduction. Podman's capability dropping feature makes privilege escalation harder by limiting available capabilities within the container.
    *   **Container Escape via Capability Abuse:** Medium Risk Reduction. Podman's capability management reduces the attack surface for capability-based container escapes.

*   **Currently Implemented:**
    *   Partially implemented in development environment. Some containers launched by Podman have capabilities dropped, but not consistently across all services.

*   **Missing Implementation:**
    *   Not consistently implemented in staging and production environments using Podman configurations. A systematic review of required capabilities for all containerized applications running under Podman is needed. Automated enforcement of capability dropping in CI/CD pipelines using Podman is missing.

## Mitigation Strategy: [Read-only Root Filesystem (Podman Configuration)](./mitigation_strategies/read-only_root_filesystem__podman_configuration_.md)

*   **Description:**
    1.  **Enable Read-only Root Filesystem in Podman:** Use the `--read-only` flag in `podman run` commands or Podman Compose files to instruct Podman to mount the container's root filesystem as read-only.
    2.  **Writable Volumes for Data (Podman Management):**  For applications that need to write data within Podman containers, use dedicated volumes mounted at specific paths within the container. Ensure these volumes are explicitly defined and managed through Podman's volume features.
    3.  **Configuration via Volumes/Environment Variables (Podman Context):**  Configure applications running in Podman primarily through environment variables or configuration files mounted as volumes managed by Podman, rather than relying on modifying files within the read-only root filesystem.

*   **List of Threats Mitigated:**
    *   **Malware Persistence within Container (Medium Severity):** If a container managed by Podman is compromised, malware might attempt to persist by modifying files in the container's filesystem. A read-only root filesystem enforced by Podman prevents such persistence.
    *   **Unauthorized Configuration Changes (Medium Severity):**  Compromised containers or misconfigurations within Podman could lead to unauthorized changes to application configurations stored in the filesystem. Read-only root filesystem enforced by Podman prevents such modifications.
    *   **Container Image Tampering (Low Severity):** While image signing is the primary defense, read-only root filesystem in Podman adds a layer of protection against runtime tampering of the base image within a running container managed by Podman.

*   **Impact:**
    *   **Malware Persistence within Container:** Medium Risk Reduction. Podman's read-only root filesystem makes it harder for malware to establish persistence within the container.
    *   **Unauthorized Configuration Changes:** Medium Risk Reduction. Podman's read-only root filesystem prevents runtime modifications to the container's configuration files.
    *   **Container Image Tampering:** Low Risk Reduction. Minor additional protection against runtime image tampering within Podman containers.

*   **Currently Implemented:**
    *   Implemented for some stateless services in staging and development environments using Podman.

*   **Missing Implementation:**
    *   Not consistently implemented across all services managed by Podman, especially stateful applications that might require writable paths within the container. Need to refactor some applications to better utilize Podman volumes for data persistence and configuration. Production implementation using Podman is incomplete.

## Mitigation Strategy: [Network Policies (Podman Networking)](./mitigation_strategies/network_policies__podman_networking_.md)

*   **Description:**
    1.  **Define Network Segmentation (Podman Networks):**  Plan network segmentation for containerized applications managed by Podman. Group containers with similar security requirements into isolated networks created and managed by Podman.
    2.  **Implement Network Policies (Podman Networking Features):** Use Podman's network features to define network policies. These policies, configured within Podman, should specify allowed communication paths between containers and external networks.
    3.  **Default Deny Policy (Podman Networking):**  Implement a default deny network policy within Podman networking configurations. Only explicitly allow necessary network connections for Podman containers.
    4.  **Least Privilege Networking (Podman Context):**  Apply the principle of least privilege to network access within the Podman environment. Containers should only be allowed to communicate with the services they absolutely need, as configured through Podman networking.

*   **List of Threats Mitigated:**
    *   **Lateral Movement after Container Compromise (High to Medium Severity):** If one container managed by Podman is compromised, attackers could potentially use it to pivot and attack other containers or services on the same network if network segmentation and policies are not in place within the Podman environment.
    *   **Unauthorized Access to Internal Services (Medium Severity):**  Without network policies configured in Podman, containers might have unintended access to internal services or databases, increasing the risk of unauthorized data access or service disruption within the Podman managed environment.

*   **Impact:**
    *   **Lateral Movement after Container Compromise:** High Risk Reduction. Podman's network policies significantly limit the ability of an attacker to move laterally within the container environment managed by Podman after compromising a single container.
    *   **Unauthorized Access to Internal Services:** Medium Risk Reduction. Podman's network policies restrict container access to only authorized services, reducing the risk of unintended access within the Podman environment.

*   **Currently Implemented:**
    *   Basic network segmentation is in place using Podman networks for different application tiers (e.g., frontend, backend, database) in staging and development.

*   **Missing Implementation:**
    *   Fine-grained network policies are not fully implemented within Podman networking. Default deny policies and explicit allow rules are needed for production environments using Podman. Integration with more advanced Podman networking features might be required for complex production setups.

## Mitigation Strategy: [Seccomp Profiles (Podman Configuration)](./mitigation_strategies/seccomp_profiles__podman_configuration_.md)

*   **Description:**
    1.  **Analyze Container Syscalls:** For each containerized application running in Podman, analyze the system calls it actually requires to function correctly.
    2.  **Apply Seccomp Profiles using `--security-opt seccomp=profile.json` in Podman:** Create custom seccomp profiles (JSON files) that define allowed system calls for containers. Use the `--security-opt seccomp=profile.json` flag in `podman run` commands or Podman Compose files to apply these profiles to containers.
    3.  **Principle of Least Privilege (Syscalls):** Apply the principle of least privilege at the syscall level. Only allow containers to make the absolute minimum system calls they need, as defined in the seccomp profile configured in Podman.
    4.  **Test and Refine Profiles:** Thoroughly test seccomp profiles to ensure they do not break application functionality. Refine profiles iteratively based on testing and application requirements within the Podman environment.

*   **List of Threats Mitigated:**
    *   **Container Escape via Syscall Exploitation (Medium to High Severity):**  Exploiting vulnerabilities in the Linux kernel often involves specific system calls. Seccomp profiles, when configured in Podman, can restrict the syscalls available to a container, reducing the attack surface for syscall-based container escapes.
    *   **Privilege Escalation via Syscall Abuse (Medium Severity):**  Certain system calls, if misused by a compromised container within Podman, can facilitate privilege escalation. Seccomp profiles can mitigate this by disallowing risky syscalls.

*   **Impact:**
    *   **Container Escape via Syscall Exploitation:** Medium to High Risk Reduction. Podman's seccomp profiles significantly reduce the attack surface for syscall-based container escapes by limiting available syscalls.
    *   **Privilege Escalation via Syscall Abuse:** Medium Risk Reduction. Podman's seccomp profiles mitigate privilege escalation risks by disallowing potentially dangerous syscalls.

*   **Currently Implemented:**
    *   Not currently implemented in any environment. Seccomp profiles are not yet used in Podman configurations.

*   **Missing Implementation:**
    *   Missing implementation across all environments.  Requires analysis of syscall requirements for each containerized application running in Podman, creation of seccomp profiles, and integration into Podman configurations and CI/CD pipelines.

