# Threat Model Analysis for k3s-io/k3s

## Threat: [Default Traefik Ingress Controller Vulnerabilities](./threats/default_traefik_ingress_controller_vulnerabilities.md)

*   **Threat:** Default Traefik Ingress Controller Vulnerabilities
*   **Description:** An attacker could exploit known or zero-day vulnerabilities in the default Traefik ingress controller, which is deployed by k3s. This could involve sending crafted requests to bypass authentication, gain unauthorized access to backend services, or cause a denial of service. Attackers might also leverage misconfigurations in Traefik to redirect traffic or expose sensitive information.
*   **Impact:**  Application compromise, data breach, denial of service, unauthorized access to internal services.
*   **Affected K3s Component:**  Traefik Ingress Controller (deployed by default by k3s)
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Regularly update Traefik to the latest stable version.
    *   Implement a Web Application Firewall (WAF) in front of Traefik.
    *   Harden Traefik configuration following security best practices (TLS, rate limiting, authentication).
    *   Consider replacing Traefik with a hardened ingress controller if suitable for your security requirements.
    *   Implement regular vulnerability scanning for Traefik and its dependencies.

## Threat: [Embedded etcd Security Weaknesses](./threats/embedded_etcd_security_weaknesses.md)

*   **Threat:** Embedded etcd Security Weaknesses
*   **Description:** If the k3s server node is compromised, an attacker gains direct access to the embedded etcd data store, which is a core component of k3s.  They can then extract sensitive information like secrets, configuration data, and potentially manipulate the cluster state, leading to full cluster compromise.  Attackers might also exploit vulnerabilities in etcd itself if it's not updated.
*   **Impact:** Full cluster compromise, data breach (secrets, configurations), control plane disruption, application downtime.
*   **Affected K3s Component:** Embedded etcd data store (used by default in k3s), k3s server node
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Strongly secure the k3s server node operating system and access controls.
    *   Use external etcd cluster for production environments to isolate the data store from the k3s server process.
    *   Enable etcd authentication and authorization.
    *   Encrypt etcd data at rest and in transit.
    *   Regularly update k3s and etcd to patch vulnerabilities.
    *   Implement robust monitoring and alerting for etcd health and access.

## Threat: [Automatic Manifest Deployment Vulnerabilities](./threats/automatic_manifest_deployment_vulnerabilities.md)

*   **Threat:** Automatic Manifest Deployment Vulnerabilities
*   **Description:** An attacker who gains write access to the `/var/lib/rancher/k3s/server/manifests` directory (or similar) on the k3s server node can deploy malicious manifests. This is a specific feature of k3s for simplified deployments. These manifests could create backdoors, deploy malicious containers, or disrupt applications running in the cluster.
*   **Impact:** Cluster compromise, malicious application deployment, denial of service, data exfiltration.
*   **Affected K3s Component:**  k3s server, Manifest deployment mechanism (specific to k3s)
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Strictly control access to the k3s server node and the manifests directory using file system permissions.
    *   Implement file integrity monitoring for the manifests directory.
    *   Disable automatic manifest deployment if not essential and use a secure CI/CD pipeline instead.
    *   Implement code review and security scanning for all manifests before deployment.

