# Attack Surface Analysis for airflow-helm/charts

## Attack Surface: [Exposed Airflow Webserver and Flower UI](./attack_surfaces/exposed_airflow_webserver_and_flower_ui.md)

**Description:**  The Airflow webserver and Flower monitoring UI are exposed to the network, potentially publicly, increasing the attack surface for unauthorized access and information disclosure.
*   **Chart Contribution:** The Helm chart, by default, can create Kubernetes Services of type `LoadBalancer` or `NodePort` for the webserver and Flower, making them accessible from outside the Kubernetes cluster.  Ingress configurations within the chart can also expose these services.
*   **Example:** Deploying the chart with default `service.webserver.type: LoadBalancer` and `service.flower.type: LoadBalancer` without further network restrictions directly exposes the webserver and Flower UI to the internet.
*   **Impact:** Unauthorized access to the Airflow webserver can lead to DAG manipulation, data exfiltration, and potentially command execution on worker nodes. Exposed Flower UI can reveal sensitive information about Airflow tasks, infrastructure, and potentially credentials if logs are not properly sanitized.
*   **Risk Severity:** **High** to **Critical** (Critical if publicly exposed without authentication hardening).
*   **Mitigation Strategies:**
    *   **Restrict Service Type:** Use `ClusterIP` for webserver and Flower services and expose them through a secure Ingress controller with proper authentication and authorization mechanisms (e.g., OAuth2, OpenID Connect).
    *   **Network Policies:** Implement Kubernetes Network Policies to restrict access to the webserver and Flower services to only authorized sources within the cluster or specific IP ranges.
    *   **Webserver Authentication Hardening:** Enforce strong authentication methods for the Airflow webserver (e.g., using Fernet-based authentication with a strong, rotated key, or integrating with external identity providers).
    *   **Flower Authentication:** Enable and configure authentication for Flower UI. Consider disabling Flower if not strictly necessary.

## Attack Surface: [Default Fernet Key and Secrets](./attack_surfaces/default_fernet_key_and_secrets.md)

**Description:**  Using default or weak `fernet_key` for encryption or default database passwords weakens security significantly, allowing attackers to decrypt sensitive data or gain unauthorized database access.
*   **Chart Contribution:** The Helm chart might use a default `fernet_key` if not explicitly overridden during installation.  Older versions or misconfigurations could potentially lead to default or weak database passwords for chart-managed databases.
*   **Example:** Deploying the chart without specifying a custom `fernet_key` in `values.yaml` or via `--set` will result in using the default key, which is publicly known.
*   **Impact:**  Compromise of the `fernet_key` allows decryption of sensitive data stored in Airflow's metadata database, including connections and variables. Default database passwords can lead to direct unauthorized access to the Airflow metadata database.
*   **Risk Severity:** **Critical**.
*   **Mitigation Strategies:**
    *   **Generate and Set Strong `fernet_key`:**  Generate a cryptographically strong, random `fernet_key` and provide it during Helm installation using `fernet_key` value or Kubernetes Secrets.
    *   **Securely Manage Database Credentials:** Ensure strong, randomly generated passwords are used for databases.  Utilize Kubernetes Secrets to manage database credentials and avoid hardcoding them in `values.yaml`.
    *   **Rotate Secrets Regularly:** Implement a process for regular rotation of the `fernet_key` and database passwords.

## Attack Surface: [Improper Secrets Management (Chart Configuration)](./attack_surfaces/improper_secrets_management__chart_configuration_.md)

**Description:**  Storing secrets in insecure locations due to chart configuration choices (e.g., ConfigMaps) increases the risk of secret exposure and compromise.
*   **Chart Contribution:** While the chart *supports* Kubernetes Secrets, misconfigurations or user error in `values.yaml` or during Helm installation can lead to unintentionally storing sensitive information in ConfigMaps or other less secure methods.
*   **Example:**  Accidentally configuring database passwords or the `fernet_key` to be sourced from ConfigMaps instead of Kubernetes Secrets through incorrect `values.yaml` settings.
*   **Impact:** Exposure of sensitive credentials, leading to unauthorized access to databases, APIs, or other systems.
*   **Risk Severity:** **High** to **Critical**.
*   **Mitigation Strategies:**
    *   **Enforce Kubernetes Secrets:**  Strictly use Kubernetes Secrets for all sensitive data configuration within the `values.yaml` and Helm installation process.
    *   **Validate Secret Sources:**  Thoroughly review `values.yaml` and Helm commands to ensure all sensitive values are correctly sourced from Kubernetes Secrets and not from ConfigMaps or plain text.
    *   **Secret Management Best Practices:** Follow general secret management best practices, including avoiding storing secrets in Git and implementing secret rotation.

## Attack Surface: [Insecure HostPath Mounts (Chart Customization)](./attack_surfaces/insecure_hostpath_mounts__chart_customization_.md)

**Description:**  Using `hostPath` volume mounts in the chart configuration, especially without careful consideration, can introduce security risks by allowing containers to access the host filesystem, potentially leading to container escape or access to sensitive data on Kubernetes nodes.
*   **Chart Contribution:** While the default chart configuration might not use `hostPath` mounts extensively, customizations to `values.yaml` or custom templates can introduce them.
*   **Example:**  Modifying the chart to use `hostPath` mounts to share sensitive data or configurations directly from the Kubernetes node filesystem into Airflow containers via custom `values.yaml` or template overrides.
*   **Impact:** Container escape, access to sensitive data on Kubernetes nodes, and potential node compromise.
*   **Risk Severity:** **High** to **Critical** (depending on the specific `hostPath` mount configuration).
*   **Mitigation Strategies:**
    *   **Avoid `hostPath` Mounts:** Minimize or completely avoid the use of `hostPath` volume mounts in chart customizations. Explore alternative volume types like `PersistentVolumeClaims`, `emptyDir`, or `configMap` / `secret` volumes.
    *   **Restrict `hostPath` Usage:** If `hostPath` mounts are absolutely necessary in customizations, carefully restrict the paths being mounted and ensure they are read-only whenever possible.
    *   **Security Contexts:**  Use Kubernetes Security Contexts to further restrict container capabilities and access to host resources, even when using `hostPath` mounts in custom configurations.

