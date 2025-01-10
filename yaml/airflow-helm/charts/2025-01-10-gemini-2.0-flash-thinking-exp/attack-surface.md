# Attack Surface Analysis for airflow-helm/charts

## Attack Surface: [Exposed Webserver without Strong Authentication](./attack_surfaces/exposed_webserver_without_strong_authentication.md)

*   **Description:** The Airflow webserver, providing the UI, is exposed externally without proper authentication mechanisms in place or with easily guessable default credentials.
    *   **How Charts Contributes to the Attack Surface:** The chart can configure a Kubernetes Service of type `LoadBalancer` or `NodePort` to directly expose the webserver to the internet or node network. It might not enforce strong authentication configurations by default.
    *   **Example:** A user deploys the chart with the default settings, and the webserver is accessible via a public IP address. Attackers can try default usernames and passwords or brute-force login attempts.
    *   **Impact:** Unauthorized access to the Airflow UI allows attackers to view sensitive DAG information, trigger arbitrary DAG runs, modify DAGs, access connection details, and potentially gain control over the entire Airflow deployment.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Enforce Strong Authentication:** Configure robust authentication mechanisms like OAuth 2.0, OpenID Connect, or Kerberos within the Airflow configuration.
        *   **Disable Default Accounts:** Ensure default administrator accounts have strong, unique passwords or are disabled entirely.
        *   **Restrict Access:** Use network policies or Ingress configurations to restrict access to the webserver to specific IP ranges or authenticated users.
        *   **Enable TLS/SSL:** Ensure HTTPS is enabled for all webserver traffic to protect credentials in transit.

## Attack Surface: [Insecure Default Secrets and Configuration](./attack_surfaces/insecure_default_secrets_and_configuration.md)

*   **Description:** The chart deploys Airflow components with default, well-known, or weak secrets (e.g., for Redis, database connections) or insecure default configurations.
    *   **How Charts Contributes to the Attack Surface:** The chart might include default secret values in its `values.yaml` or rely on environment variables with insecure defaults for internal component communication.
    *   **Example:** The chart deploys Airflow with a default password for the Redis broker. An attacker who gains access to the Kubernetes cluster network can potentially connect to Redis and access sensitive task queue information.
    *   **Impact:**  Compromise of internal components, unauthorized access to sensitive data stored in the broker or database, potential for privilege escalation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Override Default Secrets:**  Always override default secrets in the `values.yaml` with strong, randomly generated values. Utilize Kubernetes Secrets for managing sensitive information.
        *   **Secure Configuration Management:** Use secure methods for managing configuration, such as Kubernetes ConfigMaps with appropriate permissions or external secret management solutions.
        *   **Regularly Rotate Secrets:** Implement a process for regularly rotating secrets used by Airflow components.

## Attack Surface: [Overly Permissive RBAC Roles for Airflow Components](./attack_surfaces/overly_permissive_rbac_roles_for_airflow_components.md)

*   **Description:** The Kubernetes service accounts used by Airflow pods (e.g., scheduler, worker) are granted excessive permissions within the cluster.
    *   **How Charts Contributes to the Attack Surface:** The chart defines the RBAC roles and role bindings for the deployed components. If these are overly broad, they can grant unnecessary privileges.
    *   **Example:** Worker pods are granted `get`, `list`, `watch`, `create`, `delete` permissions on all Kubernetes Secrets in the namespace. A compromised worker could potentially access sensitive information from other applications.
    *   **Impact:** Lateral movement within the Kubernetes cluster, potential for accessing or modifying resources beyond the scope of the Airflow application, privilege escalation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Apply Principle of Least Privilege:**  Review and restrict the RBAC roles and role bindings to grant only the necessary permissions for each component to function.
        *   **Use Namespaced Roles:**  Prefer using namespaced roles and role bindings to limit the scope of permissions within the Airflow namespace.
        *   **Regularly Audit RBAC:** Periodically review and audit the RBAC configurations to ensure they remain appropriate.

## Attack Surface: [Vulnerabilities in Container Images Used by the Chart](./attack_surfaces/vulnerabilities_in_container_images_used_by_the_chart.md)

*   **Description:** The container images used for Airflow components (webserver, scheduler, worker, etc.) contain known vulnerabilities that could be exploited.
    *   **How Charts Contributes to the Attack Surface:** The chart specifies the container image tags to be used. If these tags point to outdated or vulnerable images, the deployed application will inherit those vulnerabilities.
    *   **Example:** The chart uses an older version of the official Airflow image that has a known security vulnerability in one of its Python dependencies.
    *   **Impact:**  Container compromise, potential for code execution within the container, data breaches, denial of service.
    *   **Risk Severity:** Varies (can be Critical or High depending on the vulnerability)
    *   **Mitigation Strategies:**
        *   **Use Up-to-Date Images:**  Ensure the chart is configured to use the latest stable and patched versions of the official Airflow container images or build your own hardened images.
        *   **Regularly Scan Images:** Implement a process for regularly scanning container images for vulnerabilities using tools like Trivy or Clair.
        *   **Automated Image Updates:** Explore strategies for automating the update of container images to incorporate security patches.

## Attack Surface: [Storing Secrets in `values.yaml` or Environment Variables](./attack_surfaces/storing_secrets_in__values_yaml__or_environment_variables.md)

*   **Description:** Sensitive information like database credentials or API keys are stored directly in the `values.yaml` file or as plain text environment variables.
    *   **How Charts Contributes to the Attack Surface:** The chart might provide examples or instructions that inadvertently encourage storing secrets in this manner.
    *   **Example:** Database connection details, including the password, are directly embedded in the `values.yaml` file, which is then committed to a version control system.
    *   **Impact:** Exposure of sensitive credentials, potential for unauthorized access to external resources or internal databases.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use Kubernetes Secrets:**  Utilize Kubernetes Secrets to securely store and manage sensitive information.
        *   **External Secret Management:** Integrate with external secret management solutions like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.
        *   **Avoid Committing Secrets:** Never commit sensitive information directly to version control systems.

