# Threat Model Analysis for airflow-helm/charts

## Threat: [Helm Chart Tampering (Supply Chain Attack)](./threats/helm_chart_tampering__supply_chain_attack_.md)

*   **Description:** An attacker compromises the Helm chart repository or intercepts the chart download process. They modify the chart to include malicious code or configurations that will be deployed to the user's cluster.  This could involve injecting malicious sidecar containers, altering environment variables to disable security features, or modifying the entrypoint of existing containers to execute arbitrary code upon deployment. The attacker's goal is to gain control of the Airflow deployment *through* the compromised chart.
    *   **Impact:** Deployment of a completely compromised Airflow instance.  The attacker gains full control over Airflow operations, can steal data (credentials, DAG data, etc.), and potentially uses the compromised Airflow instance as a launchpad for further attacks within the Kubernetes cluster or connected systems.
    *   **Affected Component:** All Airflow components deployed via the compromised chart (scheduler, worker, webserver, etc.). The Helm deployment process itself is the attack vector.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use *only* the official Airflow Helm chart repository. Avoid using unofficial or mirrored repositories.
        *   Verify the chart's integrity using checksums (if provided by the official repository) or provenance files. This helps ensure the downloaded chart hasn't been tampered with.
        *   Use Helm's `--verify` flag during `helm install` or `helm upgrade` to verify the chart's digital signature (if the chart is signed by the Airflow maintainers). This provides strong assurance of authenticity.
        *   Pin the chart version to a specific, known-good version (e.g., `helm install airflow airflow-helm/airflow --version 8.5.0`).  Do *not* use floating tags (like `latest`) that could automatically pull in a compromised version.
        *   Implement a formal process for regularly reviewing and updating the pinned chart version, including security assessments of new releases.

## Threat: [`values.yaml` Configuration Manipulation](./threats/_values_yaml__configuration_manipulation.md)

*   **Description:** An attacker gains access to the `values.yaml` file, which is *central* to the Helm chart's deployment configuration. This access could be through a compromised Git repository where the `values.yaml` is stored, a compromised CI/CD pipeline that processes the file, or direct access to the Kubernetes cluster (if the file is stored insecurely). The attacker modifies security-relevant settings within the `values.yaml`, such as:
            *   Disabling authentication for the Airflow webserver.
            *   Injecting malicious environment variables that are used by Airflow components.
            *   Changing resource limits to cause a denial of service.
            *   Modifying the image repository or tag to point to a malicious container image.
            *   Disabling securityContext settings that restrict pod capabilities.
    *   **Impact:**  Significantly weakened security posture of the Airflow deployment.  This can lead to data breaches (credentials, DAG data), unauthorized access to the Airflow UI and API, denial of service, and the potential for execution of arbitrary code within the Airflow environment. The specific impact depends on the nature of the configuration changes.
    *   **Affected Component:** All Airflow components, as the `values.yaml` file governs the overall deployment configuration and settings for all parts of Airflow.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Store the `values.yaml` file in a *secure*, private Git repository with strict access controls (e.g., requiring multi-factor authentication, limiting access to specific users/groups). Enable audit logging for all repository access.
        *   Implement a GitOps workflow (using tools like Argo CD or Flux CD) to manage deployments. This ensures that all changes to the `values.yaml` are tracked, reviewed (via pull requests), and approved before being applied to the cluster.  This provides a strong audit trail and prevents unauthorized modifications.
        *   Incorporate automated security checks into your CI/CD pipeline to validate the `values.yaml` file *before* deployment. These checks could include:
            *   Linting the YAML syntax.
            *   Scanning for known insecure configurations (e.g., using a tool like `kube-score` or a custom script).
            *   Validating that sensitive values are *not* hardcoded in the `values.yaml` but are instead referenced from Kubernetes Secrets or a secrets management system.
        *   Use Kubernetes Secrets or a dedicated secrets management solution (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) to store *all* sensitive configuration values (passwords, API keys, database credentials).  *Never* include these directly in the `values.yaml` file.
        *   Regularly audit the *deployed* configuration against the *intended* configuration (the version-controlled `values.yaml`). Tools like `kube-diff` can help identify discrepancies.

