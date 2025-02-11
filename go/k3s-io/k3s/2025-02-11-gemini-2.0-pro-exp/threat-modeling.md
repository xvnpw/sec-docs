# Threat Model Analysis for k3s-io/k3s

## Threat: [Rogue Node Joining](./threats/rogue_node_joining.md)

*   **Description:** An attacker compromises a machine and uses a stolen or guessed node token to join it to the K3s cluster as a seemingly legitimate worker node. The attacker leverages K3s's lightweight nature and simplified joining process to their advantage.
*   **Impact:**
    *   Compromise of workloads running on the rogue node.
    *   Potential for lateral movement within the cluster.
    *   Data exfiltration or manipulation.
    *   Disruption of cluster services.
*   **Affected K3s Component:**
    *   K3s Agent (specifically, the node registration process, which is streamlined in K3s).
    *   K3s Server (accepting the rogue node).
    *   Kubelet (running on the rogue node).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Use strong, randomly generated, and unique node tokens.
    *   Implement short token TTLs (Time-To-Live) and rotate tokens frequently.
    *   Monitor cluster membership for unexpected nodes.
    *   Implement network policies to restrict communication from newly joined nodes until they are verified.
    *   Consider using a node admission controller to enforce stricter node joining policies (although this adds complexity, potentially negating some of K3s's simplicity).

## Threat: [API Server Impersonation (MITM)](./threats/api_server_impersonation__mitm_.md)

*   **Description:** An attacker intercepts the TLS connection between a client and the K3s API server. The attacker presents a forged certificate. This is particularly relevant to K3s because of its focus on ease of setup, which *could* lead users to overlook proper TLS configuration.
*   **Impact:**
    *   Complete cluster compromise.
    *   Unauthorized access to all cluster resources.
    *   Data exfiltration and manipulation.
    *   Deployment of malicious workloads.
*   **Affected K3s Component:**
    *   K3s Server (API server component, including its built-in TLS handling).
    *   TLS configuration (certificates, cipher suites).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Use a trusted Certificate Authority (CA) for the API server certificate.
    *   Ensure clients are configured to verify the API server's certificate.
    *   Use strong cipher suites and TLS versions (TLS 1.3 preferred).
    *   Avoid using self-signed certificates in production (despite K3s making them easy to generate).
    *   Regularly rotate the API server certificate.
    *   Consider using a reverse proxy with strict TLS termination in front of the K3s API server.

## Threat: [K3s Binary Tampering](./threats/k3s_binary_tampering.md)

*   **Description:** An attacker gains root access to a K3s node and modifies the `k3s` binary. Because K3s is a single binary, this single point of compromise is a significant threat.
*   **Impact:**
    *   Complete node compromise.
    *   Potential for cluster-wide compromise (since the binary is the same on servers and agents).
    *   Data exfiltration and manipulation.
    *   Disruption of cluster services.
*   **Affected K3s Component:**
    *   `k3s` binary (on both server and agent nodes – the core of K3s).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Implement File Integrity Monitoring (FIM) to detect modifications to the `k3s` binary.
    *   Use a read-only root filesystem for the K3s nodes.
    *   Secure the host operating system with strong access controls.
    *   Regularly update K3s to the latest version.
    *   Consider using a minimal, hardened operating system image.

## Threat: [Configuration File Tampering](./threats/configuration_file_tampering.md)

*   **Description:**  An attacker with access to a K3s node modifies K3s configuration files (e.g., `/etc/rancher/k3s/config.yaml`). K3s's simplified configuration makes it a more concentrated target than a full Kubernetes distribution.
*   **Impact:**
    *   Weakening of cluster security.
    *   Exposure of sensitive data.
    *   Disruption of cluster services.
    *   Potential for privilege escalation.
*   **Affected K3s Component:**
    *   K3s Server and Agent (configuration files, which control core K3s behavior).
    *   Any component affected by the modified configuration.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement File Integrity Monitoring (FIM) on K3s configuration files.
    *   Use a read-only filesystem for configuration directories where possible.
    *   Secure access to the host operating system.
    *   Regularly audit K3s configuration files.
    *   Use a configuration management tool.

## Threat: [etcd Data Tampering (External etcd)](./threats/etcd_data_tampering__external_etcd_.md)

*   **Description:** If using an *external* etcd, an attacker gains direct access to the etcd data store and modifies or deletes data. This is relevant to K3s because while it *can* use an embedded SQLite database, external etcd is an option for HA setups.
*   **Impact:**
    *   Complete cluster failure or unpredictable behavior.
    *   Data loss.
    *   Potential for unauthorized access to cluster resources.
*   **Affected K3s Component:**
    *   External etcd cluster.
    *   K3s Server (interaction with etcd).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Secure the etcd cluster with TLS encryption.
    *   Implement strong authentication and authorization for etcd access.
    *   Regularly back up etcd data.
    *   Implement network policies to restrict access to the etcd cluster.
    *   Monitor etcd for unauthorized access attempts.
    *   Use etcd's built-in security features.

## Threat: [API Server DoS](./threats/api_server_dos.md)

*   **Description:** An attacker floods the K3s API server with requests.  K3s's lightweight design *might* make it more susceptible to resource exhaustion compared to a full Kubernetes distribution, depending on the underlying hardware.
*   **Impact:**
    *   Inability to manage the cluster.
    *   Disruption of cluster operations.
    *   Potential for cascading failures.
*   **Affected K3s Component:**
    *   K3s Server (API server component).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement rate limiting on the API server.
    *   Use a load balancer or ingress controller in front of the API server.
    *   Monitor API server performance.
    *   Implement network policies to restrict access to the API server.
    *   Use Kubernetes resource quotas.

## Threat: [Container Escape (Impacting K3s Control Plane)](./threats/container_escape__impacting_k3s_control_plane_.md)

*   **Description:** While container escape is a general Kubernetes threat, it's *critical* in K3s if the escape occurs from a container running a K3s control plane component (e.g., if a vulnerability exists in a system-level pod managed by K3s). This could give the attacker direct control over the `k3s` binary.
*   **Impact:**
    *   Complete node and potentially cluster compromise.
    *   Access to all data and resources on the host.
*   **Affected K3s Component:**
    *   Container runtime (e.g., containerd, as used by K3s).
    *   Linux kernel.
    *   Kubelet.
    *   Potentially the `k3s` binary itself if the escape occurs from a K3s-managed container.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Keep the container runtime and Linux kernel up to date.
    *   Use a container runtime that provides strong isolation (e.g., gVisor, Kata Containers).
    *   Use Kubernetes Pod Security Policies (or Pod Security Admission).
    *   Implement security hardening measures on the host operating system.
    *   Use seccomp profiles.
    *   Use AppArmor or SELinux.

