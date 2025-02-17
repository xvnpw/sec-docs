# Attack Surface Analysis for airflow-helm/charts

## Attack Surface: [1. Ingress Exposure](./attack_surfaces/1__ingress_exposure.md)

*   **Description:** Unintentional or overly permissive exposure of Airflow web interfaces (Webserver, Flower) or other services due to misconfigured Ingress resources.
    *   **Chart Contribution:** The chart provides *direct* configuration options for Ingress resources (`ingress.enabled`, `ingress.hosts`, `ingress.tls`, `ingress.annotations`, etc.) and Service types (`service.type`).  These settings *directly* control the exposure of Airflow services.
    *   **Example:** Setting `ingress.enabled: true` with a wildcard hostname (`*`) and no TLS configuration (`ingress.tls` empty or misconfigured) exposes the Airflow Webserver to the public internet without encryption.  Using `service.type: LoadBalancer` without proper cloud provider security groups also creates direct exposure.
    *   **Impact:** Unauthorized access to the Airflow UI, potentially leading to DAG manipulation, credential theft, and execution of arbitrary code.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers/Users:**
            *   Always enable TLS (`ingress.tls`) with valid certificates and strong ciphers.
            *   Use specific, fully qualified domain names (FQDNs) in `ingress.hosts` instead of wildcards.
            *   Configure Network Policies to restrict access to the Ingress controller and Airflow pods.
            *   Use a Web Application Firewall (WAF) in front of the Ingress controller.
            *   Prefer `ClusterIP` Service type for internal services. If `LoadBalancer` is required, ensure proper cloud provider security group configurations and firewall rules are in place.  Avoid `NodePort` unless absolutely necessary and with strict network policies.

## Attack Surface: [2. Default Credentials and Secrets](./attack_surfaces/2__default_credentials_and_secrets.md)

*   **Description:** Using default or easily guessable passwords, Fernet keys, or other secrets provided as default values within the chart.
    *   **Chart Contribution:** The chart *may* provide default values for sensitive configurations (e.g., `airflow.secret.fernetKey`, `postgresql.postgresqlPassword`, `redis.password`, database connection strings).  Failing to override these is a *direct* result of using the chart's defaults.
    *   **Example:** Deploying the chart without overriding the default `postgresql.postgresqlPassword` allows anyone with access to the PostgreSQL service (which might be exposed via misconfigured Ingress or Service, as above) to connect with the default credentials.
    *   **Impact:** Unauthorized access to the Airflow metadata database, Redis, or other components, leading to data breaches, system compromise, and denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers/Users:**
            *   *Always* override *all* default secrets with strong, randomly generated values.  This is a non-negotiable best practice.
            *   Use a secrets management solution (e.g., Kubernetes Secrets, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) to store and manage secrets securely.
            *   Never commit secrets to version control (e.g., Git).
            *   Use a GitOps approach with encrypted secrets (e.g., SOPS, Sealed Secrets) to manage secrets declaratively and securely.

## Attack Surface: [3. Insecure `airflow.config` Overrides](./attack_surfaces/3__insecure__airflow_config__overrides.md)

*   **Description:** Misconfiguring Airflow settings via the `airflow.config` option, leading to security vulnerabilities.
    *   **Chart Contribution:** The chart provides the `airflow.config` section as a *direct* mechanism to override *any* Airflow configuration setting.  This is a powerful feature that can easily introduce vulnerabilities if misused.
    *   **Example:** Setting `airflow.config.webserver__authenticate: "False"` via the chart's `values.yaml` disables authentication for the Airflow Webserver, allowing anyone to access it (especially dangerous in combination with Ingress misconfiguration).  Other examples include disabling CSRF protection or enabling insecure logging.
    *   **Impact:** Varies depending on the misconfigured setting. Can range from information disclosure to complete system compromise.  The impact is directly tied to the specific Airflow configuration being altered.
    *   **Risk Severity:** High to Critical (depending on the specific configuration)
    *   **Mitigation Strategies:**
        *   **Developers/Users:**
            *   Thoroughly review the official Airflow documentation for *each* configuration option *before* modifying it via `airflow.config`.
            *   Follow the principle of least privilege: only enable features and configurations that are absolutely necessary.
            *   Avoid disabling security features (authentication, authorization, CSRF protection, etc.) unless there is a very strong, well-understood, and documented reason to do so.
            *   Regularly audit the Airflow configuration (as expressed in the chart's `values.yaml` and the resulting running configuration) to identify potential misconfigurations.

## Attack Surface: [4. Insecure GitSync for DAGs](./attack_surfaces/4__insecure_gitsync_for_dags.md)

*   **Description:** Using an insecurely configured Git repository for DAG synchronization, allowing attackers to inject malicious DAGs.
    *   **Chart Contribution:** The chart provides the `dags.gitSync` section as a *direct* mechanism to configure automatic DAG synchronization from a Git repository. The security of this feature is *entirely* dependent on the configuration provided through the chart.
    *   **Example:** Using `dags.gitSync.enabled: true` with a public Git repository and no authentication, or using weak HTTP basic authentication with credentials stored in plain text in the `values.yaml` file.
    *   **Impact:** Execution of arbitrary code within the Airflow environment (as the DAGs are Python code), potentially leading to data breaches, system compromise, and lateral movement within the Kubernetes cluster.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers/Users:**
            *   Use a *private* Git repository for storing DAGs.
            *   Use strong authentication (SSH keys *strongly* preferred over username/password) for the Git repository.
            *   Regularly review the repository's contents and access controls to ensure only authorized users can modify DAGs.
            *   Consider using a dedicated service account (with limited permissions) for Git Sync, rather than personal credentials.
            *   Implement code review and approval processes for all DAG changes before they are deployed.

## Attack Surface: [5. Insufficient RBAC Permissions](./attack_surfaces/5__insufficient_rbac_permissions.md)

*   **Description:** Airflow service accounts having excessive permissions within the Kubernetes cluster.
    *   **Chart Contribution:** The chart provides options for configuring RBAC (`rbac.create`, `rbac.pspEnabled`, etc.). This directly controls the permissions of the created service accounts.
    *   **Example:** Deploying with `rbac.create: false`, which may result in pods running with default service accounts that have broad cluster access. Or, creating custom roles with overly permissive rules.
    *   **Impact:** A compromised Airflow component could escalate privileges and gain control over other resources in the cluster, potentially compromising the entire cluster.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers/Users:**
            *   Always enable RBAC (`rbac.create: true`).
            *   Carefully review and minimize the permissions granted to the Airflow service accounts. Define custom roles with the least necessary privileges.
            *   Follow the principle of least privilege.
            *   Use a dedicated namespace for Airflow.
            *   Regularly audit RBAC configurations using Kubernetes auditing tools or third-party security tools.

