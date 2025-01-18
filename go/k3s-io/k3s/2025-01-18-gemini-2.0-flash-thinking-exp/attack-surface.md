# Attack Surface Analysis for k3s-io/k3s

## Attack Surface: [Exposed K3s API Server without Proper Authentication/Authorization:](./attack_surfaces/exposed_k3s_api_server_without_proper_authenticationauthorization.md)

*   **Description:** The Kubernetes API server in K3s, if exposed without strong authentication (like TLS client certificates or a robust authentication webhook) and authorization (RBAC), allows attackers to gain full control of the K3s cluster.
    *   **How K3s Contributes:** K3s, aiming for simplicity, might have default configurations that are less secure if not explicitly hardened, such as relying solely on the initial join token for authentication if not rotated or properly secured.
    *   **Example:** An attacker scans the network, finds the K3s API server port, and, without proper authentication, uses `kubectl` to deploy a malicious container that compromises the underlying nodes in the K3s cluster.
    *   **Impact:** Full K3s cluster compromise, including the ability to deploy malicious workloads, steal secrets, and disrupt services.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Enable TLS Authentication for the K3s API server.
        *   Implement Robust Authentication Webhooks for the K3s API server.
        *   Implement Strong RBAC Configuration within the K3s cluster.
        *   Secure Kubeconfig files used to access the K3s cluster.
        *   Implement network segmentation to isolate the K3s control plane network.

## Attack Surface: [K3s Agent Node Join Token Compromise:](./attack_surfaces/k3s_agent_node_join_token_compromise.md)

*   **Description:** The node join token used by worker nodes to authenticate and join the K3s cluster. If this token is leaked or easily guessable, unauthorized nodes can join the K3s cluster.
    *   **How K3s Contributes:** K3s uses a simple token mechanism for node joining. If not handled carefully during K3s setup, this token can be inadvertently exposed.
    *   **Example:** An attacker gains access to a configuration file or script containing the K3s node join token and uses it to add a malicious node to the K3s cluster.
    *   **Impact:** Introduction of malicious nodes into the K3s cluster, potentially leading to resource abuse, data theft, or further compromise.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Securely store the K3s node join token and restrict access.
        *   Regularly rotate the K3s node join token.
        *   Implement Node Authorization within the K3s cluster.
        *   Implement network segmentation to limit network access to the K3s control plane from untrusted networks.

## Attack Surface: [Vulnerabilities in Embedded etcd (if used by K3s):](./attack_surfaces/vulnerabilities_in_embedded_etcd__if_used_by_k3s_.md)

*   **Description:** K3s can use an embedded etcd database to store cluster state. Vulnerabilities in this embedded etcd can lead to data loss or K3s cluster compromise.
    *   **How K3s Contributes:** By default, K3s uses an embedded etcd, increasing the attack surface of the K3s control plane.
    *   **Example:** An attacker exploits a known vulnerability in the embedded etcd of a K3s cluster to gain read access to the cluster's secrets.
    *   **Impact:** Data loss within the K3s cluster, K3s cluster instability, and potential exposure of sensitive information.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Keep K3s updated to patch known vulnerabilities in the embedded etcd.
        *   Secure access to the embedded etcd within the K3s cluster with proper TLS configuration.
        *   Consider using an external, hardened etcd cluster instead of the embedded one for production K3s deployments.
        *   Implement regular backups of the etcd data in the K3s cluster.

## Attack Surface: [Kubelet API Exposure on Worker Nodes in K3s:](./attack_surfaces/kubelet_api_exposure_on_worker_nodes_in_k3s.md)

*   **Description:** The Kubelet API on worker nodes in a K3s cluster allows management of containers on that node. If exposed without proper authentication and authorization, it can be exploited.
    *   **How K3s Contributes:** While K3s aims for secure defaults, misconfigurations or overly permissive firewall rules could expose the Kubelet API on K3s worker nodes.
    *   **Example:** An attacker gains access to the Kubelet API on a K3s worker node and uses it to execute arbitrary commands within a container or even on the host.
    *   **Impact:** Container compromise within the K3s cluster, potential node compromise, and the ability to disrupt workloads on that specific K3s worker node.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Disable anonymous authentication to the Kubelet API on K3s worker nodes.
        *   Enable proper authentication and authorization mechanisms for the Kubelet API on K3s worker nodes.
        *   Restrict network access to the Kubelet API port on K3s worker nodes from untrusted networks.

## Attack Surface: [Container Escape Vulnerabilities in K3s:](./attack_surfaces/container_escape_vulnerabilities_in_k3s.md)

*   **Description:** Vulnerabilities in the container runtime (containerd in K3s) or the underlying kernel can allow a container within a K3s cluster to escape its isolation and gain access to the host system.
    *   **How K3s Contributes:** K3s relies on containerd. Vulnerabilities in containerd directly impact the security of containers within the K3s environment.
    *   **Example:** An attacker exploits a vulnerability in containerd within a K3s cluster to break out of a container and gain root access to the worker node.
    *   **Impact:** Full compromise of the worker node in the K3s cluster, potentially affecting other containers running on the same node.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Keep K3s updated to get the latest versions of containerd with security patches.
        *   Harden container images used in the K3s cluster and scan them for vulnerabilities.
        *   Implement Security Contexts for pods within the K3s cluster to restrict container capabilities and access.
        *   Consider using Seccomp and AppArmor/SELinux to further restrict container actions within the K3s environment.
        *   Regularly patch the operating system of the worker nodes in the K3s cluster.

