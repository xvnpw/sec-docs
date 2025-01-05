# Threat Model Analysis for k3s-io/k3s

## Threat: [Control Plane Compromise](./threats/control_plane_compromise.md)

**Description:** An attacker gains unauthorized access to the K3s server node (control plane) through exploiting vulnerabilities in the underlying OS, brute-forcing SSH credentials, or compromising administrative tools. Once in, they can manipulate the cluster state, deploy malicious workloads, or exfiltrate sensitive data directly managed by K3s.

**Impact:** Complete cluster takeover, deployment of malicious applications orchestrated by K3s, data breaches of secrets and configuration data managed by K3s, denial of service by shutting down critical K3s components.

**Affected Component:** K3s Server (Control Plane Node), including kube-apiserver, kube-scheduler, kube-controller-manager, etcd (as the K3s embedded datastore).

**Risk Severity:** Critical

## Threat: [API Server Unauthorized Access](./threats/api_server_unauthorized_access.md)

**Description:** An attacker bypasses authentication or authorization mechanisms to access the K3s API server (kube-apiserver). This could be due to weak authentication configurations within K3s, misconfigured RBAC within K3s, or exploiting vulnerabilities in the K3s-provided API server. The attacker can then perform actions they are not authorized for, such as creating, modifying, or deleting resources managed by K3s.

**Impact:** Privilege escalation within the K3s cluster, deployment of malicious workloads through the K3s API, data breaches by accessing sensitive resources exposed via the K3s API, denial of service by manipulating critical resources managed by K3s.

**Affected Component:** kube-apiserver API endpoint provided by K3s, authentication and authorization modules within K3s.

**Risk Severity:** High

## Threat: [etcd Data Breach](./threats/etcd_data_breach.md)

**Description:** An attacker gains unauthorized access to the etcd datastore, which holds the K3s cluster's state and sensitive information like secrets. This could happen due to weak access controls on the etcd instance embedded within K3s, exploiting vulnerabilities in etcd itself, or compromising the control plane node where etcd runs.

**Impact:** Exposure of all cluster secrets managed by K3s, including database credentials, API keys, and other sensitive information. Potential for data corruption or manipulation leading to K3s cluster instability or application failures.

**Affected Component:** etcd datastore embedded within K3s, access control mechanisms for etcd within K3s.

**Risk Severity:** Critical

## Threat: [kubelet Compromise on Agent Node](./threats/kubelet_compromise_on_agent_node.md)

**Description:** An attacker compromises the kubelet process running on a K3s agent node. This could be through exploiting vulnerabilities in the kubelet binary provided by K3s, container escape facilitated by kubelet weaknesses, or compromising the underlying OS of the agent node. Once compromised, the attacker can control containers managed by that kubelet, access local resources, or potentially pivot to other nodes managed by K3s.

**Impact:** Container takeover on nodes managed by K3s, execution of arbitrary code on the agent node managed by K3s, data exfiltration from containers or the node itself within the K3s cluster, potential lateral movement within the K3s cluster.

**Affected Component:** kubelet process on agent nodes managed by K3s, node API exposed by kubelet.

**Risk Severity:** High

## Threat: [Container Runtime Vulnerability (containerd/CRI-O)](./threats/container_runtime_vulnerability__containerdcri-o_.md)

**Description:** An attacker exploits a vulnerability in the container runtime (containerd or CRI-O) used by K3s. This could allow for container escape, where the attacker breaks out of the container sandbox and gains access to the underlying node managed by K3s.

**Impact:** Host OS compromise on nodes managed by K3s, access to sensitive data on the node, potential for further attacks on other containers or the K3s cluster infrastructure.

**Affected Component:** Container runtime (containerd or CRI-O) integrated with K3s.

**Risk Severity:** High

## Threat: [Network Policy Bypass](./threats/network_policy_bypass.md)

**Description:** An attacker bypasses configured Kubernetes Network Policies within the K3s cluster, allowing unauthorized network traffic between pods or to external services. This could be due to misconfigurations in network policies enforced by K3s's CNI plugin or vulnerabilities in the specific CNI plugin integrated with K3s.

**Impact:** Unauthorized access to sensitive services within the K3s cluster, potential data breaches, lateral movement within the K3s cluster, and exposure of internal services to external threats.

**Affected Component:** CNI plugin (e.g., Flannel, Calico) integrated with K3s, kube-proxy managed by K3s, network policy enforcement mechanisms within K3s.

**Risk Severity:** Medium <!-- Downgraded as it's often configuration related, but can be high if a CNI vulnerability is exploited -->

## Threat: [Misconfigured RBAC Leading to Privilege Escalation](./threats/misconfigured_rbac_leading_to_privilege_escalation.md)

**Description:** Incorrectly configured Role-Based Access Control (RBAC) rules within the K3s cluster grant excessive permissions to users or service accounts. An attacker exploiting a vulnerability in an application or gaining access to a compromised service account could leverage these excessive permissions to perform actions they shouldn't be able to within the K3s environment.

**Impact:** Ability to deploy malicious workloads within the K3s cluster, access sensitive resources managed by K3s, modify cluster configurations, and potentially take over the entire K3s cluster.

**Affected Component:** RBAC API within K3s, authorization modules within K3s.

**Risk Severity:** High

## Threat: [Risky K3s Upgrades](./threats/risky_k3s_upgrades.md)

**Description:** The process of upgrading K3s introduces risks if not performed carefully. A failed upgrade can lead to K3s cluster instability or downtime. Vulnerabilities in the K3s upgrade process itself could be exploited.

**Impact:** K3s cluster downtime, data loss if the upgrade process corrupts data, potential introduction of new vulnerabilities if the upgrade process is flawed or if the new K3s version has unforeseen issues.

**Affected Component:** K3s upgrade process, k3s binary and related components.

**Risk Severity:** Medium <!-- Downgraded as direct exploitation during upgrade is less common than instability -->

