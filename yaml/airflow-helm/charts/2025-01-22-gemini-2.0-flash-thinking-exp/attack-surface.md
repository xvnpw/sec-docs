# Attack Surface Analysis for airflow-helm/charts

## Attack Surface: [Exposed Airflow Webserver to Public Internet](./attack_surfaces/exposed_airflow_webserver_to_public_internet.md)

*   **Description:** The Airflow Webserver, providing the user interface, is made directly accessible from the public internet due to chart configurations.
*   **Chart Contribution:** The chart allows configuring the Webserver Service as `LoadBalancer` or `NodePort` by default, which, without further network restrictions, can expose it publicly. The chart's configuration options directly influence network exposure.
*   **Example:**  Deploying Airflow using the chart with default Service type `LoadBalancer` in a cloud environment without implementing additional network policies or firewall rules results in the Webserver being publicly accessible.
*   **Impact:** Unauthorized access to the Airflow Webserver, leading to data breaches, workflow manipulation, malicious DAG injection, and potential control over the Airflow environment.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Configure Ingress with Authentication in Chart:**  Utilize the chart's Ingress configuration options and ensure strong authentication (e.g., OAuth 2.0, OpenID Connect, LDAP) is configured within the Ingress definition in `values.yaml`.
    *   **Set Service Type to ClusterIP in Chart:**  Modify the `webserver.service.type` value in `values.yaml` to `ClusterIP` to restrict access to within the Kubernetes cluster by default. Public access should then be explicitly managed via Ingress or VPN.
    *   **Implement Network Policies (Kubernetes):** While not directly in the chart, users should implement Kubernetes Network Policies to restrict access to the Webserver Service, complementing chart configurations.

## Attack Surface: [Default Secrets and Passwords](./attack_surfaces/default_secrets_and_passwords.md)

*   **Description:** The chart relies on or facilitates the use of default secrets or passwords for components, creating a significant vulnerability.
*   **Chart Contribution:** The chart might pre-populate `values.yaml` with default secrets for databases (Postgres/MySQL, Redis) or initial Airflow admin credentials as placeholders, encouraging users to deploy without changing them if not explicitly careful.
*   **Example:**  A user deploys Airflow using the chart and overlooks changing the default database passwords provided as examples in `values.yaml`. An attacker exploiting default credentials gains unauthorized database access.
*   **Impact:** Unauthorized access to databases, message brokers, or Airflow itself, leading to data breaches, data manipulation, and system compromise.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Force Secret Overrides in Chart Configuration:** The chart should be configured (or ideally, improved) to *require* users to explicitly provide strong secrets and *prevent* deployment with default placeholder values.
    *   **Document Secure Secret Generation in Chart Documentation:**  The chart documentation should prominently guide users on how to generate and securely provide strong, random secrets during deployment.
    *   **Utilize External Secrets Management via Chart Configuration:** The chart should offer clear integration points and configuration options for using external secret management solutions (e.g., HashiCorp Vault) to avoid storing secrets directly in `values.yaml` or Kubernetes Secrets.

## Attack Surface: [Secrets Stored in ConfigMaps (Chart Misconfiguration Risk)](./attack_surfaces/secrets_stored_in_configmaps__chart_misconfiguration_risk_.md)

*   **Description:** Due to chart misconfiguration or incorrect customization, sensitive information is unintentionally stored in Kubernetes ConfigMaps instead of Secrets.
*   **Chart Contribution:** While the chart *intends* to use Secrets, errors in chart templates or user modifications to `values.yaml` or templates could lead to secrets being placed in ConfigMaps. The chart's templating logic and configuration structure can contribute to this risk if not carefully managed.
*   **Example:** A user customizing the chart's templates makes a mistake and inadvertently configures the database password to be sourced from a ConfigMap instead of a Secret.
*   **Impact:** Exposure of sensitive credentials, leading to unauthorized access to systems and data breaches.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Review Chart Templates for Secret Handling:** Developers and users should carefully review the chart's templates to ensure that all sensitive data is correctly handled as Kubernetes Secrets and not ConfigMaps.
    *   **Validate Secret Usage in Chart Customizations:** When customizing the chart, rigorously validate that any changes do not inadvertently lead to secrets being stored in ConfigMaps.
    *   **Chart Linting and Security Scanning:** Implement chart linting and security scanning tools in the development/deployment pipeline to automatically detect potential misconfigurations that could lead to secrets in ConfigMaps.

## Attack Surface: [Outdated Component Images with Vulnerabilities (Chart Defaults)](./attack_surfaces/outdated_component_images_with_vulnerabilities__chart_defaults_.md)

*   **Description:** The Helm chart defaults to using outdated container images for Airflow and its dependencies, which may contain known security vulnerabilities.
*   **Chart Contribution:** The chart's `values.yaml` or templates specify default container image tags. If these tags are not regularly updated to the latest secure versions by the chart maintainers, deployments using the chart will inherit these vulnerabilities.
*   **Example:** A user deploys Airflow using an older version of the chart. This chart version defaults to outdated Airflow and Redis container images that have known, publicly disclosed vulnerabilities.
*   **Impact:** System compromise, data breaches, denial of service, and potential lateral movement within the Kubernetes cluster due to exploitable vulnerabilities in outdated images.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Regular Chart Updates by Maintainers:** Chart maintainers must prioritize regularly updating the default container image tags in the chart to the latest stable and secure versions.
    *   **Image Version Overrides in Chart Configuration:** Users should be strongly encouraged and provided clear instructions in the chart documentation on how to override default image tags in `values.yaml` to use the latest versions they have validated.
    *   **Chart Versioning and Release Notes:** Chart releases should clearly document the versions of container images used and highlight any security-related updates or image upgrades.

