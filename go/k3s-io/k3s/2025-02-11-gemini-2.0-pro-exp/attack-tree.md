# Attack Tree Analysis for k3s-io/k3s

Objective: Gain unauthorized control over the K3s cluster and, consequently, the hosted application(s), potentially leading to data exfiltration, service disruption, or lateral movement within the network.

## Attack Tree Visualization

```
                                     [Gain Unauthorized Control of K3s Cluster]
                                                    |
          -------------------------------------------------------------------------------------------------
          |                                                                                 |
  [***Compromise K3s Control Plane***] (HIGH)                                   [Exploit K3s Worker Node Vulnerabilities]
          |                                                                                 |
  ---------------------                                                         -----------------------------------
  |                                                                                 |                 |
[***API Server***] (HIGH)                                                      [Container Runtime]
  |                                                                                 |                 |
1.1(HIGH), 1.3(HIGH)                                                              4.1(HIGH), 4.2(HIGH)
          |
          ---------------------
          |                                         
  [Abuse K3s Network Policies/Configuration]
          |
  ---------------------
          |
        [Weak/Default]
          |
       6.1(HIGH)
```

## Attack Tree Path: [1. Compromise K3s Control Plane (HIGH) -> [***API Server***] (HIGH)](./attack_tree_paths/1__compromise_k3s_control_plane__high__-__api_server___high_.md)

*   **Critical Node:** The API Server is the central control point for the entire K3s cluster. Compromising it grants near-total control.

*   **Attack Vectors:**

    *   **1.1. Unauthenticated/Weakly Authenticated Access (HIGH):**
        *   **Description:** The attacker gains access to the API server due to missing or weak authentication mechanisms (e.g., a leaked or default token).
        *   **Likelihood:** Medium (High if defaults are not changed or secrets are leaked)
        *   **Impact:** High (Full cluster control)
        *   **Effort:** Low (Simple API calls if unauthenticated)
        *   **Skill Level:** Low
        *   **Detection Difficulty:** Medium (Requires monitoring API server logs and authentication events)
        *   **Mitigation:**
            *   Always use strong, randomly generated tokens.
            *   Rotate tokens regularly.
            *   Implement RBAC to limit token permissions.
            *   Consider client certificates or OIDC.
            *   Audit API server access logs.

    *   **1.3. Exploiting Misconfigured RBAC (HIGH):**
        *   **Description:** The attacker leverages overly permissive RBAC roles or bindings to escalate privileges within the cluster, potentially gaining control after an initial, lower-privileged compromise.
        *   **Likelihood:** Medium (Common in poorly managed clusters)
        *   **Impact:** Medium to High (Depends on the level of privilege escalation)
        *   **Effort:** Low to Medium (Depends on the misconfiguration complexity)
        *   **Skill Level:** Low to Medium (Requires understanding of Kubernetes RBAC)
        *   **Detection Difficulty:** Medium (Requires auditing RBAC and monitoring for suspicious activity)
        *   **Mitigation:**
            *   Follow the principle of least privilege.
            *   Carefully define roles and role bindings.
            *   Regularly audit RBAC configurations.
            *   Use tools like `kube-bench`.

## Attack Tree Path: [2. Exploit K3s Worker Node Vulnerabilities -> [Container Runtime]](./attack_tree_paths/2__exploit_k3s_worker_node_vulnerabilities_-__container_runtime_.md)

*   **Important Node:** The Container Runtime (containerd) is responsible for running containers.  Vulnerabilities here can lead to container escapes.

*   **Attack Vectors:**

    *   **4.1. Container Escape Vulnerabilities (HIGH):**
        *   **Description:** The attacker exploits a vulnerability in the container runtime (containerd) to break out of the container's isolation and gain access to the underlying host operating system.
        *   **Likelihood:** Low to Medium (Less frequent, but high impact)
        *   **Impact:** High (Host-level control)
        *   **Effort:** High (Requires significant exploit development)
        *   **Skill Level:** High (Deep understanding of container internals)
        *   **Detection Difficulty:** High (Requires advanced intrusion detection)
        *   **Mitigation:**
            *   Keep K3s (and containerd) up-to-date.
            *   Monitor for CVEs.
            *   Use security profiles (AppArmor, Seccomp).
            *   Consider container-optimized OS.

    *   **4.2. Misconfigured Container Runtime (HIGH):**
        *   **Description:** The attacker leverages misconfigurations in the container runtime (e.g., running containers as root, with host network access, or with excessive capabilities) to gain elevated privileges or access to the host.
        *   **Likelihood:** Medium (Common if best practices are not followed)
        *   **Impact:** Medium to High (Depends on the misconfiguration)
        *   **Effort:** Low (Exploiting existing misconfigurations)
        *   **Skill Level:** Low to Medium (Requires understanding of container security)
        *   **Detection Difficulty:** Medium (Requires auditing container configurations)
        *   **Mitigation:**
            *   Review containerd configuration.
            *   Avoid running containers as root.
            *   Use Pod Security Policies (or Admission Controller).

## Attack Tree Path: [3. Abuse K3s Network Policies/Configuration -> Weak/Default Network Policies](./attack_tree_paths/3__abuse_k3s_network_policiesconfiguration_-_weakdefault_network_policies.md)

*  **Attack Vectors:**
    *   **6.1. No Network Policies (HIGH):**
        *   **Description:**  The absence of network policies allows any pod to communicate with any other pod within the cluster, enabling easy lateral movement for an attacker who compromises any single pod.
        *   **Likelihood:** Medium to High (Common in development/poorly managed clusters)
        *   **Impact:** Medium to High (Allows lateral movement)
        *   **Effort:** Low (Exploiting the lack of restrictions)
        *   **Skill Level:** Low
        *   **Detection Difficulty:** Low (Easy to identify with audits)
        *   **Mitigation:**
            *   Implement network policies.
            *   Start with a default-deny policy.
            *   Explicitly allow necessary traffic.

