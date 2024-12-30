### Key Helm Attack Surface List (High & Critical, Direct Helm Involvement)

Here's an updated list of key attack surfaces that directly involve Helm, focusing on those with high and critical risk severity.

*   **Attack Surface: Malicious Chart Content**
    *   **Description:** Helm charts from untrusted sources may contain malicious code within templates, hooks, or referenced container images.
    *   **How Helm Contributes to the Attack Surface:** Helm facilitates the installation and execution of these charts within the Kubernetes cluster. It doesn't inherently validate the safety of the chart's contents.
    *   **Example:** A chart containing a post-install hook that executes a reverse shell on the Kubernetes node, or a template that creates a privileged pod with access to sensitive data.
    *   **Impact:** Full compromise of the Kubernetes node or cluster, data exfiltration, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use trusted and verified chart repositories.
        *   Implement chart scanning.
        *   Review chart contents before deploying.
        *   Principle of least privilege for chart execution.

*   **Attack Surface: Supply Chain Attacks via Chart Dependencies**
    *   **Description:** Helm charts may depend on vulnerable container images or other external resources. If these dependencies are compromised, the deployed application becomes vulnerable.
    *   **How Helm Contributes to the Attack Surface:** Helm manages the deployment of these dependencies as defined in the chart. It doesn't inherently ensure the security of the referenced resources.
    *   **Example:** A chart referencing an outdated container image with a known security vulnerability, or pulling a dependency from a compromised registry.
    *   **Impact:** Application compromise, data breach, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Regularly update chart dependencies.
        *   Implement container image scanning.
        *   Use private or trusted registries.
        *   Implement Software Bill of Materials (SBOM).

*   **Attack Surface: Server-Side Template Injection (SSTI)**
    *   **Description:** If user-provided values are not properly sanitized and are directly injected into Helm templates, attackers can exploit SSTI vulnerabilities to execute arbitrary code within the templating engine.
    *   **How Helm Contributes to the Attack Surface:** Helm uses Go templates to generate Kubernetes manifests. Improper handling of user-provided values during template rendering can create this vulnerability.
    *   **Example:** A malicious user providing a value like `{{ .Capabilities.KubeVersion.Version }}` which, if not properly handled, could reveal sensitive cluster information or potentially execute arbitrary code.
    *   **Impact:** Information disclosure, potential for arbitrary code execution within the Helm rendering process, leading to the generation of malicious Kubernetes manifests.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Sanitize and validate user-provided values.
        *   Use Helm's built-in functions for escaping.
        *   Minimize the use of complex template logic.
        *   Regularly audit templates.

*   **Attack Surface: Exposure of Sensitive Information in Values**
    *   **Description:** Sensitive information like passwords, API keys, or database credentials might be stored directly in `values.yaml` or passed through command-line arguments during Helm deployment.
    *   **How Helm Contributes to the Attack Surface:** Helm uses these values to configure the deployed application. If not handled securely, this information can be exposed.
    *   **Example:** Storing a database password in plain text within `values.yaml` which is then committed to a version control system or accessible to unauthorized users.
    *   **Impact:** Data breaches, unauthorized access to systems.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use Kubernetes Secrets.
        *   Avoid storing secrets in `values.yaml`.
        *   Use external secret management solutions.
        *   Securely manage Helm command history.

*   **Attack Surface: Insufficient RBAC Permissions for Helm (Helm v3+)**
    *   **Description:** If the service account or user used by Helm has excessive permissions within the Kubernetes cluster, attackers who compromise this account could perform unauthorized actions.
    *   **How Helm Contributes to the Attack Surface:** Helm v3 relies on the Kubernetes API server's Role-Based Access Control (RBAC). The permissions granted to the Helm client directly impact its potential attack surface.
    *   **Example:** A Helm service account having cluster-admin privileges, allowing an attacker who compromises this account to manage any resource in the cluster.
    *   **Impact:** Full cluster compromise, data deletion, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Apply the principle of least privilege.
        *   Regularly review and audit RBAC roles.
        *   Use namespace-scoped roles.