# Attack Surface Analysis for k3s-io/k3s

## Attack Surface: [API Server Exposure](./attack_surfaces/api_server_exposure.md)

*   **Description:** The Kubernetes API server, packaged and configured by K3s, is the primary control point and a high-value target.
    *   **How K3s Contributes:** K3s manages the API server's lifecycle and configuration, making deployment easier but also introducing potential K3s-specific misconfigurations or delays in patching upstream vulnerabilities.
    *   **Example:** An attacker exploits a zero-day vulnerability in the Kubernetes API server (before a K3s patch is available) to gain cluster admin privileges. Or, a K3s-specific configuration flag (`--kube-apiserver-arg`) is misconfigured, exposing an insecure port.
    *   **Impact:** Complete cluster compromise, data breach, denial of service, resource manipulation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Immediate K3s Updates:** Apply K3s updates *immediately* upon release to patch API server vulnerabilities. Monitor K3s release notes and CVE feeds diligently.
        *   **Strict RBAC:** Implement rigorous Role-Based Access Control (RBAC) to minimize permissions for users and service accounts. Avoid cluster-admin privileges unless absolutely necessary.
        *   **Network Segmentation (Control Plane):** Isolate K3s control plane nodes from untrusted networks using firewalls and network policies. Restrict access to the API server port (default 6443).
        *   **Secure K3s Configuration:** Thoroughly review and harden the API server configuration flags managed by K3s. Avoid exposing insecure ports or using weak TLS settings. Enforce strong authentication.
        *   **Audit Logging:** Enable and actively monitor Kubernetes audit logs to detect suspicious API activity.
        *   **Admission Controllers:** Utilize admission controllers (e.g., PodSecurityPolicy (deprecated), Open Policy Agent) to enforce security policies and prevent deployment of insecure configurations.

## Attack Surface: [Agent (Kubelet) Compromise](./attack_surfaces/agent__kubelet__compromise.md)

*   **Description:** The `k3s agent` (containing the Kubelet) runs on worker nodes. Vulnerabilities in the agent or Kubelet, as packaged and managed by K3s, can lead to node compromise.
    *   **How K3s Contributes:** K3s simplifies agent deployment and management, but vulnerabilities in the K3s-packaged agent or Kubelet are directly exploitable.
    *   **Example:** An attacker exploits a vulnerability in the K3s-packaged Kubelet to escape a container and gain root access to the host node, then pivots to other nodes or the control plane.
    *   **Impact:** Node compromise, container escape, lateral movement, potential control plane access.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Immediate K3s Updates:** Prioritize prompt K3s updates to patch agent and Kubelet vulnerabilities.
        *   **Node OS Hardening:** Harden the underlying operating system of worker nodes. Use OS-level security best practices (SELinux, AppArmor, minimal software).
        *   **Secure Container Runtime:** Employ a secure container runtime (e.g., containerd with security profiles).
        *   **Network Segmentation (Workers):** Isolate worker nodes from each other and the control plane using network policies.
        *   **Limit K3s Agent Privileges:** Ensure the `k3s agent` runs with the *absolute minimum* necessary privileges. Avoid running as root if possible.
        *   **Node Monitoring:** Actively monitor node logs and resource usage for signs of compromise.

## Attack Surface: [Embedded Datastore Vulnerabilities (etcd - High Risk Only)](./attack_surfaces/embedded_datastore_vulnerabilities__etcd_-_high_risk_only_.md)

*   **Description:** K3s can use an embedded etcd instance. Vulnerabilities in this embedded etcd, as managed by K3s, directly impact the cluster.
    *   **How K3s Contributes:** The embedded nature, facilitated by K3s, means etcd vulnerabilities are K3s vulnerabilities.
    *   **Example:** An attacker exploits a vulnerability in the K3s-embedded etcd to read all cluster secrets (service account tokens, TLS certificates).
    *   **Impact:** Data breach (secrets), data corruption, denial of service, complete cluster compromise.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Immediate K3s Updates:** Prioritize K3s updates to patch embedded etcd vulnerabilities.
        *   **External Datastore (Strongly Recommended):** For production, use an external, highly available etcd cluster *managed separately* from K3s. This allows independent security hardening and patching.
        *   **Data Encryption at Rest:** If using embedded etcd, *ensure* data is encrypted at rest. K3s supports etcd encryption; enable it.
        *   **Network Isolation (etcd):** Restrict network access to the etcd port (default 2379) to *only* the K3s server nodes.
        *   **Regular Backups:** Implement a robust backup and recovery strategy for the cluster datastore.
        *   **etcd Monitoring:** Monitor etcd logs and resource usage.

## Attack Surface: [Ingress Controller (Traefik) Exploitation](./attack_surfaces/ingress_controller__traefik__exploitation.md)

*   **Description:** K3s includes Traefik as a default Ingress controller. Vulnerabilities in this K3s-bundled Traefik can expose applications.
    *   **How K3s Contributes:** K3s bundles and configures Traefik, making it the default entry point for external traffic.  Vulnerabilities are directly exploitable.
    *   **Example:** An attacker exploits a path traversal or request smuggling vulnerability in the K3s-bundled Traefik to access unauthorized data or execute code.
    *   **Impact:** Unauthorized application access, data breaches, denial of service, potential remote code execution.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Immediate K3s Updates:**  Prioritize K3s updates to patch Traefik vulnerabilities.
        *   **Secure Traefik Configuration (K3s-Specific):** Review and harden the Traefik configuration *as deployed by K3s*. Avoid exposing unnecessary ports or using default credentials.
        *   **Web Application Firewall (WAF):**  Strongly consider a WAF in front of Traefik to protect against web application attacks.
        *   **Application-Level Input Validation:** Ensure applications behind Traefik rigorously validate and sanitize all input.
        *   **Limit Ingress Exposure:** Only expose necessary services. Use network policies to restrict access to internal services.
        *   **Alternative Ingress Controllers:** Evaluate other Ingress controllers (e.g., Nginx Ingress Controller) for different security features.

## Attack Surface: [Supply Chain Attacks](./attack_surfaces/supply_chain_attacks.md)

*   **Description:** The risk of compromised K3s binaries or dependencies.  This is a direct risk because K3s is distributed as a single binary.
    *   **How K3s Contributes:** K3s's single-binary nature simplifies deployment but creates a single, critical point of failure for supply chain attacks.
    *   **Example:** An attacker compromises the K3s build pipeline, injecting malicious code into the K3s binary. Users downloading the compromised binary deploy a compromised cluster.
    *   **Impact:** Complete cluster compromise, data breach, denial of service – attacker-controlled behavior.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Checksum Verification:** *Always* verify the checksum of the downloaded K3s binary against the official checksums from the K3s project.
        *   **Trusted Download Sources:** Only download K3s binaries from the official K3s GitHub releases page or other explicitly trusted sources.
        *   **Software Bill of Materials (SBOM):** If available, use an SBOM to understand K3s dependencies and their vulnerabilities.
        *   **Air-Gapped Deployments (High-Security Environments):** For highly sensitive environments, consider air-gapped deployments with manual binary transfer after thorough security checks.

