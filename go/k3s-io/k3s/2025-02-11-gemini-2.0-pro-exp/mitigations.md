# Mitigation Strategies Analysis for k3s-io/k3s

## Mitigation Strategy: [Externalize and Secure etcd (K3s-Specific Focus)](./mitigation_strategies/externalize_and_secure_etcd__k3s-specific_focus_.md)

*   **Description:**
    1.  **Provision External etcd:** Set up a separate, highly-available etcd cluster.
    2.  **Configure etcd Authentication:** Enable client certificate authentication for etcd. Generate client certificates.
    3.  **Configure etcd RBAC:** Implement RBAC within etcd.
    4.  **Configure K3s:** Use `--datastore-endpoint`, `--etcd-certfile`, `--etcd-keyfile`, and `--etcd-cafile` flags when starting the K3s *server* to connect to the external etcd. This is the *K3s-specific* step.
    5.  **Network Isolation:** Isolate etcd communication.
    6.  **Backup and Restore:** Implement etcd backup/restore.

*   **Threats Mitigated:**
    *   **etcd Compromise via K3s (Severity: Critical):**  Compromising the K3s server, which by default has direct access to the embedded etcd, grants full cluster control. Externalizing breaks this direct link.
    *   **Single Point of Failure (K3s Default) (Severity: High):** K3s's default single-node setup with embedded etcd is a single point of failure.
    *   **Unauthorized etcd Access (Severity: High):**

*   **Impact:**
    *   **etcd Compromise via K3s:** Significantly reduces impact. K3s server compromise no longer grants *automatic* etcd access.
    *   **Single Point of Failure (K3s Default):** Eliminates the single point of failure of the default K3s configuration.
    *   **Unauthorized etcd Access:** Prevents unauthorized access.

*   **Currently Implemented:** (Example: "External etcd provisioned. K3s configured to use it. etcd RBAC is pending.")

*   **Missing Implementation:** (Example: "etcd RBAC needs implementation. Network isolation review needed.")

## Mitigation Strategy: [Rotate and Secure K3s Server Token](./mitigation_strategies/rotate_and_secure_k3s_server_token.md)

*   **Description:**
    1.  **Initial Secure Storage:** Immediately store the K3s server token (`/var/lib/rancher/k3s/server/token`) in a secrets management solution.
    2.  **Automated Rotation:** Implement a script/process to:
        *   Retrieve the current token (if needed).
        *   Delete the token file: `rm /var/lib/rancher/k3s/server/token`. This is a *K3s-specific* file.
        *   Restart the K3s server: `systemctl restart k3s`. This generates a new token, a *K3s-specific* action.
        *   Store the *new* token securely.
    3.  **Secure Retrieval:** Retrieve the token from secrets management for agent joins.
    4.  **File Permissions:** Restrictive permissions on `/var/lib/rancher/k3s/server/token` (e.g., `chmod 600`). This is a *K3s-specific* file.

*   **Threats Mitigated:**
    *   **Unauthorized Node Joining (K3s Specific) (Severity: High):** A leaked K3s server token allows unauthorized nodes to join the *K3s* cluster.
    *   **Token Exposure (Severity: High):**

*   **Impact:**
    *   **Unauthorized Node Joining (K3s Specific):** Reduces risk by limiting the validity of a compromised K3s token.
    *   **Token Exposure:** Minimizes exposure.

*   **Currently Implemented:** (Example: "Token stored in Vault. Rotation script under development.")

*   **Missing Implementation:** (Example: "Automated rotation. File permission verification.")

## Mitigation Strategy: [Secure Agent Token Handling (K3s-Specific Focus)](./mitigation_strategies/secure_agent_token_handling__k3s-specific_focus_.md)

*   **Description:**
    1.  **Avoid Hardcoding:** Never hardcode the K3s agent token.
    2.  **Secrets Management:** Store the K3s agent token in secrets management.
    3.  **Secure Environment Variables (Caution):** If used, ensure they are set *only* for the K3s agent process, not logged, and deleted after use. This is relevant because the K3s *agent* uses the token.
    4.  **Automated Provisioning:** Use infrastructure-as-code to inject the K3s agent token securely during provisioning.

*   **Threats Mitigated:**
    *   **Unauthorized Node Joining (K3s Specific) (Severity: High):** A leaked K3s agent token allows unauthorized nodes to join.
    *   **Token Exposure (Severity: High):**

*   **Impact:**
    *   **Unauthorized Node Joining (K3s Specific):** Reduces risk.
    *   **Token Exposure:** Minimizes risk.

*   **Currently Implemented:** (Example: "Token retrieved from Vault during provisioning.")

*   **Missing Implementation:** (Example: "Review scripts for hardcoded tokens.")

## Mitigation Strategy: [Secure Auto-Deploying Manifests Directory (K3s-Specific)](./mitigation_strategies/secure_auto-deploying_manifests_directory__k3s-specific_.md)

*   **Description:**
    1.  **Restrictive Permissions:** Strict permissions on `/var/lib/rancher/k3s/server/manifests` (e.g., `chmod 700`). This is a *K3s-specific* directory.
    2.  **GitOps Workflow:** Manage manifests via GitOps, not direct file modification.
    3.  **Monitoring and Alerting:** Monitor changes to `/var/lib/rancher/k3s/server/manifests`. This is a *K3s-specific* directory.
    4.  **AppArmor/SELinux (for K3s):** Confine the *K3s process* to prevent it from writing outside expected directories, even with permission errors. This targets the K3s process specifically.

*   **Threats Mitigated:**
    *   **Unauthorized Workload Deployment (K3s Specific) (Severity: Critical):** Attackers with write access to this *K3s-specific* directory can deploy malicious workloads via K3s's auto-deployment feature.
    *   **Tampering (Severity: High):**

*   **Impact:**
    *   **Unauthorized Workload Deployment (K3s Specific):** Significantly reduces risk.
    *   **Tampering:** Reduces risk.

*   **Currently Implemented:** (Example: "Permissions set to 700. GitOps partially implemented.")

*   **Missing Implementation:** (Example: "Full GitOps. Monitoring. AppArmor/SELinux profile for K3s.")

## Mitigation Strategy: [Secure Traefik Configuration (K3s Default Ingress)](./mitigation_strategies/secure_traefik_configuration__k3s_default_ingress_.md)

*   **Description:**
    1.  **Review Default Config:** Examine the default Traefik configuration *deployed by K3s*.
    2.  **TLS Termination:** Configure TLS.
    3.  **Request Limits:** Configure request/rate limiting.
    4.  **Authentication:** Secure the Traefik dashboard (if used) *as deployed by K3s*.
    5.  **Logging:** Configure detailed logging.
    6.  **Updates:** Keep Traefik updated *as part of the K3s update process* or through a controlled method if you've customized it.
    7.  **WAF:** Consider a WAF.

*   **Threats Mitigated:**
    *   **Ingress Controller Vulnerabilities (K3s Default) (Severity: High):** Vulnerabilities in Traefik, *as the K3s default*, can be exploited.
    *   **DoS Attacks (Severity: Medium):**
    *   **Unauthorized Dashboard Access (Severity: Medium):**

*   **Impact:**
    *   **Ingress Controller Vulnerabilities (K3s Default):** Reduces risk.
    *   **DoS Attacks:** Mitigates impact.
    *   **Unauthorized Dashboard Access:** Prevents unauthorized access.

*   **Currently Implemented:** (Example: "TLS configured. Request limits partially implemented.")

*   **Missing Implementation:** (Example: "Full config review. WAF consideration. Secure dashboard.")

## Mitigation Strategy: [Regular K3s Updates](./mitigation_strategies/regular_k3s_updates.md)

*   **Description:**
    1.  **Monitor Releases:** Subscribe to K3s releases.
    2.  **Test Updates:** Test K3s updates in a non-production environment.
    3.  **Automated Updates (Caution):** Consider tools like `system-upgrade-controller` (often used with K3s), but with testing and rollbacks.
    4.  **Rollback Plan:** Have a rollback plan.
    5.  **Update Frequency:** Establish a regular K3s update schedule.

*   **Threats Mitigated:**
    *   **K3s Vulnerabilities (Severity: Variable):** Unpatched vulnerabilities in *K3s itself* can be exploited.

*   **Impact:**
    *   **K3s Vulnerabilities:** Significantly reduces risk.

*   **Currently Implemented:** (Example: "Manual updates quarterly. Testing environment exists.")

*   **Missing Implementation:** (Example: "Automated updates considered. Rollback plan documentation.")

