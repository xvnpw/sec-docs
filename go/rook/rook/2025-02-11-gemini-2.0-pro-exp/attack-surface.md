# Attack Surface Analysis for rook/rook

## Attack Surface: [1. Privileged Operator Compromise](./attack_surfaces/1__privileged_operator_compromise.md)

*   **Description:** The Rook operator runs with elevated Kubernetes privileges to manage storage resources.  This is inherent to Rook's design.
    *   **How Rook Contributes:** Rook *requires* these elevated privileges to function, creating a high-value target *within* the Rook codebase and deployment.  The vulnerability exists *because* of Rook's operational model.
    *   **Example:** An attacker exploits a vulnerability in the Rook operator *container image itself* (e.g., a code injection flaw in the operator's logic) to gain shell access to the operator pod.
    *   **Impact:** Complete control over the cluster's storage managed by *that specific Rook instance*, including data access, modification, deletion, and potential privilege escalation within the Kubernetes cluster (depending on the operator's RBAC).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Least Privilege:**  Use the most restrictive RBAC roles possible for the Rook operator's service account.  Avoid granting cluster-admin level access. Grant *only* the specific permissions needed for the chosen storage provider and *nothing* more.  This is the single most important mitigation.
        *   **Pod Security:** Implement strict Pod Security Policies (or use an admission controller like Kyverno or Gatekeeper) to limit the operator pod's capabilities.  Prevent:
            *   `hostNetwork: true`
            *   `privileged: true`
            *   `allowPrivilegeEscalation: true`
            *   Mounting sensitive host paths (`hostPath`).
            *   Running as root user (use a non-root user with a specific UID).
        *   **Image Scanning:** Regularly scan Rook operator container images for vulnerabilities *before deployment* and apply updates promptly. Use a trusted image registry and verify image signatures.
        *   **Auditing:**  Enable and monitor Kubernetes audit logs, focusing *specifically* on actions performed by the Rook operator's service account.  Set up alerts for suspicious activity.
        *   **Network Policies:** Restrict network access to the operator pod, allowing only necessary communication with the Kubernetes API server and Rook agents.  Block all other ingress and egress.

## Attack Surface: [2. CRD Manipulation](./attack_surfaces/2__crd_manipulation.md)

*   **Description:** Attackers with permissions to modify Rook Custom Resource Definitions (CRDs) can alter storage configurations *managed by Rook*.
    *   **How Rook Contributes:** Rook's core functionality is driven by CRDs.  The attack surface exists *because* Rook uses CRDs as its primary control mechanism.
    *   **Example:** An attacker with `create` permissions on `CephCluster` CRDs creates a new Ceph cluster with weak authentication *through Rook's API*.
    *   **Impact:** Unauthorized storage creation, modification of existing storage configurations (e.g., disabling encryption, reducing replication), denial of service, data exposure – all *within the scope of what Rook manages*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **RBAC Restrictions:**  *Strictly* limit access to Rook CRDs using RBAC.  Only authorized users/service accounts should have `create`, `update`, `patch`, or `delete` permissions.  This is a *cluster-wide* setting, but its impact is directly on Rook's functionality.
        *   **Admission Control:** Implement admission control webhooks (e.g., using OPA Gatekeeper or Kyverno) to validate Rook CRD configurations *before* they are applied to the cluster.  This is *crucial* and should be considered mandatory.  Define policies to:
            *   Enforce naming conventions (prevent conflicts).
            *   Restrict resource limits (prevent DoS).
            *   Validate storage provider-specific settings (e.g., Ceph authentication type, encryption settings).
            *   Prevent unauthorized modifications to existing CRDs (e.g., prevent changing critical settings on a running cluster).
            *   *Reject* any CRD that doesn't meet the defined security policies.
        *   **Auditing:** Monitor Kubernetes audit logs for *all* changes to Rook CRDs.  Alert on unauthorized or suspicious modifications.

## Attack Surface: [3. Agent Compromise](./attack_surfaces/3__agent_compromise.md)

*   **Description:** Rook agents running on each node perform storage-related tasks and could be compromised. This is a direct attack on a Rook component.
    *   **How Rook Contributes:** Rook *relies* on these agents for distributed storage management. The vulnerability exists because of Rook's agent-based architecture.
    *   **Example:** An attacker exploits a vulnerability in the `rook-ceph-agent` *container image* to gain access to a node and manipulate storage devices *that Rook is managing*.
    *   **Impact:** Manipulation of storage devices managed by Rook, data corruption, potential node compromise (if the agent has excessive privileges), denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Least Privilege:** Run Rook agents with the *absolute minimum* necessary privileges. Avoid granting them excessive permissions on the host system. Use a dedicated service account with narrowly scoped RBAC.
        *   **Secure Communication:** Ensure secure communication (e.g., using mutually authenticated TLS) between the Rook operator and agents. This prevents eavesdropping and man-in-the-middle attacks *on Rook's internal communication*.
        *   **Image Scanning:** Regularly scan Rook agent container images for vulnerabilities *before deployment*. Use a trusted image registry.
        *   **Network Policies:** Restrict network access to the agent pods. Allow only communication with the Rook operator and necessary storage provider components. Block all other traffic.
        *   **Pod Security:** Apply Pod Security Policies (or equivalent) to limit agent capabilities, similar to the operator (prevent host access, privileged mode, etc.).

