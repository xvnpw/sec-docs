# Attack Surface Analysis for k3s-io/k3s

## Attack Surface: [Exposed K3s API Server](./attack_surfaces/exposed_k3s_api_server.md)

**Description:** The Kubernetes API server is the central point of interaction for managing the cluster. If exposed without proper authentication and authorization, it allows unauthorized users to control the cluster.

**How K3s Contributes:** K3s, by default, might listen on `0.0.0.0` making the API server accessible on all network interfaces of the server node. While convenient for single-node setups, this can be a risk in multi-node or networked environments if not secured.

**Example:** An attacker gains network access to the K3s server node and uses `kubectl` to deploy malicious workloads, create privileged containers, or extract sensitive information from the cluster.

**Impact:** Full cluster compromise, including the ability to run arbitrary code on nodes, access secrets, and disrupt services.

**Risk Severity:** Critical

**Mitigation Strategies:**
- Configure network firewalls to restrict access to the API server port (default 6443) to only trusted networks or specific IP addresses.
- Implement strong authentication mechanisms like TLS client certificates or OIDC.

## Attack Surface: [Unprotected Access to Embedded etcd](./attack_surfaces/unprotected_access_to_embedded_etcd.md)

**Description:** etcd is the key-value store that holds the state of the Kubernetes cluster. Unauthorized access to etcd allows attackers to directly manipulate the cluster state, leading to complete control.

**How K3s Contributes:** K3s uses an embedded etcd by default. While convenient, if the etcd client port (typically 2379 or 2380) is exposed or accessible without proper authentication, it becomes a direct entry point.

**Example:** An attacker connects to the etcd client port and uses `etcdctl` to modify critical cluster configurations, delete namespaces, or retrieve secrets stored in etcd.

**Impact:** Complete cluster takeover, data loss, and potential service disruption.

**Risk Severity:** Critical

**Mitigation Strategies:**
- Ensure the etcd client port is not exposed to the network. Restrict access to the local host or trusted internal networks only.
- Configure TLS client authentication for etcd to ensure only authorized clients can connect.

## Attack Surface: [Exposed Kubelet API on Agent Nodes](./attack_surfaces/exposed_kubelet_api_on_agent_nodes.md)

**Description:** The Kubelet is the agent running on each node that manages containers. Its API, if accessible, can be used to control containers and retrieve information about the node.

**How K3s Contributes:** While K3s aims for simplicity, the Kubelet API is still present on agent nodes. Default configurations might not strictly limit access to this API.

**Example:** An attacker gains access to a K3s agent node and exploits the Kubelet API to execute commands within containers, retrieve container logs, or access node-level information.

**Impact:** Compromise of individual nodes, potential container escapes, and access to sensitive data within containers.

**Risk Severity:** High

**Mitigation Strategies:**
- Ensure the Kubelet API is not publicly accessible. Restrict access through network firewalls.
- Enable Kubelet authentication and authorization to control access to its API.
- Consider using the `--kubelet-read-only-port=0` flag to disable the read-only Kubelet API.

## Attack Surface: [Misconfigured Embedded Load Balancer (Traefik)](./attack_surfaces/misconfigured_embedded_load_balancer__traefik_.md)

**Description:** K3s includes Traefik as an embedded ingress controller. Misconfigurations can lead to vulnerabilities allowing unauthorized access or bypassing security measures.

**How K3s Contributes:** K3s's default setup includes Traefik. Incorrectly configured Ingress resources or Traefik's own settings can create security holes.

**Example:** An incorrectly configured Ingress rule allows external access to internal services that should not be publicly exposed. An open Traefik dashboard exposes sensitive information about the cluster's routing.

**Impact:** Exposure of internal services, potential data breaches, and the ability to manipulate routing within the cluster.

**Risk Severity:** High

**Mitigation Strategies:**
- Carefully review and validate all Ingress resource configurations.
- Secure the Traefik dashboard with authentication and restrict access.
- Follow security best practices for configuring ingress controllers, including TLS termination and secure headers.

## Attack Surface: [Vulnerabilities in Embedded Components (containerd, Flannel, etc.)](./attack_surfaces/vulnerabilities_in_embedded_components__containerd__flannel__etc__.md)

**Description:** K3s bundles several components like containerd (container runtime) and Flannel (CNI). Vulnerabilities in these components can be exploited.

**How K3s Contributes:** By including these components, K3s inherits their potential vulnerabilities.

**Example:** A known vulnerability in containerd allows for container escape, granting an attacker access to the host system.

**Impact:** Container escapes, node compromise, and potential cluster-wide impact.

**Risk Severity:** Varies (can be High to Critical depending on the vulnerability)

**Mitigation Strategies:**
- Keep K3s updated to the latest version to benefit from security patches for its embedded components.
- Monitor security advisories for containerd and other embedded components.

