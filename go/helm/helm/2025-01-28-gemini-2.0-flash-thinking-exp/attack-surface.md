# Attack Surface Analysis for helm/helm

## Attack Surface: [Malicious Helm Charts](./attack_surfaces/malicious_helm_charts.md)

*   **Description:** Helm charts can contain malicious code, vulnerable application images, or Kubernetes manifests that create backdoors, escalate privileges, or deploy malicious workloads.
*   **How Helm Contributes:** Helm is the mechanism for deploying and managing these charts within Kubernetes. It facilitates the execution of manifests and deployment of images defined in the chart.
*   **Example:** A chart from an untrusted repository contains a Kubernetes Deployment that pulls a backdoored container image. When deployed via Helm, this backdoored application runs within the cluster, allowing attackers to gain unauthorized access.
*   **Impact:** Cluster compromise, data breach, denial of service, resource hijacking.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Use Trusted Chart Repositories:** Only use charts from well-known, reputable, and verified repositories.
    *   **Chart Signing and Verification:** Implement and enforce chart signing and verification to ensure chart integrity and origin.
    *   **Static Chart Analysis:** Perform static analysis of charts before deployment to identify potential security issues in manifests and templates.
    *   **Image Scanning:** Scan container images referenced in charts for known vulnerabilities before deployment.
    *   **Security Audits:** Conduct security audits of charts, especially those from external sources, before deploying them in production environments.

## Attack Surface: [Compromised Helm Repositories](./attack_surfaces/compromised_helm_repositories.md)

*   **Description:** Helm repositories can be compromised, leading to the distribution of malicious or outdated charts to users who trust the repository.
*   **How Helm Contributes:** Helm relies on repositories to discover and download charts. If a repository is compromised, Helm users are directly exposed to malicious content.
*   **Example:** An attacker compromises a public Helm repository and replaces a popular chart with a malicious version. Users unknowingly download and deploy this malicious chart using Helm.
*   **Impact:** Wide-scale deployment of malicious charts, cluster compromise across multiple users, supply chain attack.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Use Reputable Repositories:** Prioritize using well-established and reputable chart repositories with strong security practices.
    *   **Repository Signing and Verification:**  If available, utilize repository signing and verification mechanisms to ensure the integrity and authenticity of charts from the repository.
    *   **Private/Curated Repositories:** Consider hosting private, curated Helm repositories for internal use, controlling the charts available and their security posture.
    *   **Regular Repository Audits:** Periodically audit the security of used Helm repositories and their infrastructure.

## Attack Surface: [Overly Permissive Kubernetes RBAC for Helm](./attack_surfaces/overly_permissive_kubernetes_rbac_for_helm.md)

*   **Description:** Granting Helm excessive permissions in Kubernetes RBAC broadens the attack surface. If Helm's service account is compromised, the attacker inherits these excessive permissions.
*   **How Helm Contributes:** Helm requires Kubernetes API access, and misconfiguration of RBAC roles for Helm can lead to excessive privileges.
*   **Example:** Helm is granted cluster-admin privileges in Kubernetes RBAC. If Helm's service account is compromised, an attacker gains full control over the entire Kubernetes cluster.
*   **Impact:** Full cluster compromise, unauthorized access to all resources, data breach, denial of service.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Least Privilege RBAC:** Implement the principle of least privilege when configuring RBAC roles for Helm service accounts. Grant only the necessary permissions for Helm to function correctly.
    *   **Regular RBAC Audits:** Regularly review and audit Kubernetes RBAC configurations, ensuring that Helm and other service accounts have appropriate and minimal permissions.
    *   **Role Separation:** Consider using separate service accounts for different Helm operations or namespaces to further limit the impact of a potential compromise.

