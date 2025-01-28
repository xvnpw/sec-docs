# Attack Surface Analysis for k3s-io/k3s

## Attack Surface: [Unsecured K3s API Server](./attack_surfaces/unsecured_k3s_api_server.md)

*   **Description:** Exposure of the K3s API server without proper authentication and authorization mechanisms.
*   **How K3s Contributes to Attack Surface:** K3s's focus on simplified deployment can lead to users overlooking security hardening steps for the API server. Default configurations might not be sufficiently secure for production environments, especially in resource-constrained or edge deployments where security might be initially deprioritized.
*   **Example:** An attacker discovers a publicly accessible K3s API server endpoint (port 6443) and, due to misconfigured RBAC or disabled authentication, gains administrative access to the cluster. They can then deploy malicious containers, steal secrets, or disrupt services.
*   **Impact:** Full cluster compromise, data breach, denial of service, control over all applications running on the cluster.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Enable and Enforce RBAC:** Implement Role-Based Access Control to restrict API access to authorized users and services only.
    *   **Enable Authentication:** Configure strong authentication methods (e.g., TLS client certificates, OIDC, Webhook tokens) and disable anonymous authentication.
    *   **Network Segmentation:** Restrict network access to the API server to only authorized networks or IP ranges using firewalls or network policies.
    *   **Regular Security Audits:** Periodically audit RBAC configurations and authentication settings to ensure they are correctly implemented and maintained.
    *   **Minimize Public Exposure:** If possible, avoid exposing the API server directly to the public internet. Use VPNs or bastion hosts for secure access.

## Attack Surface: [Kubelet API Exposure](./attack_surfaces/kubelet_api_exposure.md)

*   **Description:** Direct access to the Kubelet API on nodes, potentially allowing unauthorized actions on containers and nodes.
*   **How K3s Contributes to Attack Surface:** While K3s aims to minimize direct kubelet interaction, default configurations or network setups might inadvertently leave Kubelet API ports (10250, 10255) accessible.
*   **Example:** An attacker gains network access to a K3s node and exploits an open Kubelet API port (e.g., 10250) with anonymous authentication enabled. They use the Kubelet API to execute commands within containers, retrieve container logs containing sensitive information, or even compromise the node itself.
*   **Impact:** Container compromise, node compromise, information disclosure, potential lateral movement within the cluster.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Disable Anonymous Kubelet Authentication:** Ensure anonymous authentication is disabled for the Kubelet API.
    *   **Restrict Kubelet API Access:** Use network policies or firewalls to restrict access to Kubelet API ports (10250, 10255) to only the API server and authorized components.
    *   **Minimize Node Exposure:** Limit direct network access to K3s nodes from external networks.
    *   **Regular Security Audits:** Check Kubelet configuration and network policies to ensure proper restrictions are in place.

## Attack Surface: [Compromise of Embedded etcd/SQLite Data Store](./attack_surfaces/compromise_of_embedded_etcdsqlite_data_store.md)

*   **Description:** Unauthorized access or compromise of the data store (etcd or SQLite) where K3s stores cluster state and sensitive information.
*   **How K3s Contributes to Attack Surface:** K3s's default use of embedded etcd (single-server) or SQLite (even lighter) makes the data store more directly accessible on the server node. This increases the risk if the server node itself is compromised, as the data store is co-located and potentially easier to access.
*   **Example:** An attacker compromises the K3s server node through an OS vulnerability or SSH brute-forcing. They gain file system access and directly access the embedded etcd or SQLite database files. They extract sensitive information like secrets, service account tokens, and cluster configurations, leading to full cluster control.
*   **Impact:** Full cluster compromise, data breach, loss of cluster integrity, potential for long-term persistent access.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Secure Server Node:** Harden the K3s server node operating system, apply security patches, and restrict access to the node.
    *   **File System Permissions:** Ensure appropriate file system permissions are set on the etcd/SQLite data directory to restrict access to only the K3s process.
    *   **Encryption at Rest (if possible):** Explore options for encrypting the data store at rest, depending on the chosen storage backend and underlying infrastructure.
    *   **Regular Backups and Secure Storage:** Implement regular backups of the data store and store backups in a secure, offsite location.
    *   **Consider External etcd (for larger setups):** For larger or more security-sensitive deployments, consider using an external, hardened etcd cluster instead of embedded etcd to increase separation and security.

## Attack Surface: [Traefik Ingress Controller Vulnerabilities and Misconfigurations](./attack_surfaces/traefik_ingress_controller_vulnerabilities_and_misconfigurations.md)

*   **Description:** Exploiting vulnerabilities in the default Traefik ingress controller or misconfiguring it to expose unintended services or create security loopholes.
*   **How K3s Contributes to Attack Surface:** K3s includes Traefik as the default ingress controller, making it a readily available and commonly used component. This default inclusion means Traefik's security directly impacts the K3s deployment's overall security posture.
*   **Example:** A known vulnerability in a specific version of Traefik is discovered. If the K3s cluster is running a vulnerable version and Traefik is exposed to the internet, an attacker could exploit this vulnerability to bypass authentication, gain access to backend services, or perform other malicious actions. Alternatively, misconfigured ingress rules could unintentionally expose sensitive internal services to the public internet.
*   **Impact:** Application compromise, data breach, denial of service, potential for lateral movement if backend services are compromised.
*   **Risk Severity:** **High** to **Critical** (depending on vulnerability and exposure)
*   **Mitigation Strategies:**
    *   **Keep Traefik Updated:** Regularly update Traefik to the latest stable version to patch known vulnerabilities.
    *   **Secure Traefik Dashboard (if enabled):** If the Traefik dashboard is enabled, secure it with strong authentication and restrict access. Consider disabling it in production if not strictly necessary.
    *   **Careful Ingress Rule Configuration:** Thoroughly review and test ingress rules to ensure they only expose intended services and paths, and that routing is secure.
    *   **Web Application Firewall (WAF):** Consider deploying a WAF in front of Traefik to provide an additional layer of security against web-based attacks.
    *   **Regular Security Audits:** Periodically audit Traefik configurations and ingress rules for potential misconfigurations or vulnerabilities.

