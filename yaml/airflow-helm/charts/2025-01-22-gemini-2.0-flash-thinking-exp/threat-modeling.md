# Threat Model Analysis for airflow-helm/charts

## Threat: [Excessive RBAC Permissions](./threats/excessive_rbac_permissions.md)

*   **Description:** Attacker exploits overly permissive RBAC roles assigned by the Helm chart to Airflow components. Compromising a component (e.g., Webserver) allows them to use its service account to access Kubernetes resources beyond Airflow's intended scope, such as secrets, other namespaces, or even the control plane.
*   **Impact:** Privilege escalation within the Kubernetes cluster, data breaches by accessing sensitive Kubernetes secrets, cluster disruption by modifying critical resources, potential control plane compromise.
*   **Affected Component:** Kubernetes RBAC configuration within the Helm chart, Service Accounts for Webserver, Scheduler, Workers, Flower, StatsD.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Minimize RBAC role permissions defined in the chart to adhere to the principle of least privilege.
    *   Provide configuration options for users to further restrict RBAC roles during chart installation.
    *   Regularly review and audit RBAC configurations in the deployed cluster.

## Threat: [Default Secrets Management](./threats/default_secrets_management.md)

*   **Description:** Attacker gains access to default secrets (e.g., database passwords, API keys) if the Helm chart relies on them and they are not properly managed or rotated after deployment. This could be through accessing Kubernetes Secrets or exploiting vulnerabilities to retrieve embedded secrets.
*   **Impact:** Unauthorized access to Airflow components, databases (PostgreSQL, Redis), and sensitive data, potentially leading to data breaches, data manipulation, or system compromise.
*   **Affected Component:** Secrets management within the Helm chart, default secret generation scripts, configuration of database connections and API keys.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Avoid default secrets in the chart design.
    *   Strongly encourage and facilitate the use of external secret management solutions (Kubernetes Secrets, HashiCorp Vault, cloud provider secret managers) within the chart documentation and configuration options.
    *   Provide clear documentation and configuration options for users to inject their own secrets securely during chart installation.
    *   If default secrets are unavoidable for initial setup, ensure they are randomly generated and users are strongly encouraged to rotate them immediately after deployment, with clear warnings in documentation.

## Threat: [Vulnerable Dependencies in Container Images](./threats/vulnerable_dependencies_in_container_images.md)

*   **Description:** Attacker exploits known vulnerabilities in outdated system libraries or Python packages within the container images used by the Helm chart for Airflow components. This can be achieved by targeting publicly exposed services or through other attack vectors if a component is reachable.
*   **Impact:** Component compromise, data breaches, denial of service, potential for further exploitation within the Kubernetes cluster.
*   **Affected Component:** Dockerfiles and container images for Webserver, Scheduler, Workers, Flower, StatsD, Databases (PostgreSQL, Redis) used by the Helm chart.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Regularly update base images and dependencies in the Dockerfiles used to build Airflow component images.
    *   Implement automated vulnerability scanning of container images (e.g., using tools like Trivy, Clair) as part of the chart release process.
    *   Address identified vulnerabilities promptly by rebuilding and releasing updated container images and chart versions.
    *   Clearly document the base images and dependencies used in the chart and encourage users to use the latest chart versions.

## Threat: [Chart Repository Compromise (Supply Chain Attack)](./threats/chart_repository_compromise__supply_chain_attack_.md)

*   **Description:** Attacker compromises the Helm chart repository itself and injects malicious code or backdoors into the chart. Users unknowingly download and deploy the compromised chart, leading to widespread system compromise.
*   **Impact:** Deployment of compromised Airflow applications across numerous installations, potentially leading to large-scale data breaches, malware installation, complete system compromise, and long-term persistence of attackers.
*   **Affected Component:** The Helm chart repository itself (`https://github.com/airflow-helm/charts`).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Chart Maintainers:** Implement robust security measures for the chart repository, including strong access control, multi-factor authentication, regular vulnerability scanning, and rigorous code review processes. Implement chart signing to ensure chart integrity and authenticity.
    *   **Users:** Use trusted and official chart repositories. Verify the integrity and authenticity of the chart source if possible, especially by using chart signing and verification mechanisms if provided. Monitor for any unusual activity or changes in the chart repository.

## Threat: [Chart Tampering](./threats/chart_tampering.md)

*   **Description:** Attacker intercepts and modifies the Helm chart after it is downloaded from the repository but before it is deployed into the Kubernetes cluster. They inject malicious code or alter configurations to compromise the deployed Airflow application.
*   **Impact:** Deployment of compromised Airflow applications, potentially leading to data breaches, malware installation, and system compromise within the user's environment.
*   **Affected Component:** Downloaded Helm chart package after retrieval from the repository but before deployment.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Download charts from trusted sources over secure channels (HTTPS).
    *   Implement checksum verification or chart signing verification if available to ensure chart integrity before deployment.
    *   Store downloaded charts securely and control access to prevent unauthorized modification before deployment. Use automation and infrastructure-as-code practices to minimize manual chart handling and potential tampering opportunities.

