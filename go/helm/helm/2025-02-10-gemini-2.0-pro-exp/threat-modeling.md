# Threat Model Analysis for helm/helm

## Threat: [Malicious Chart Injection from Untrusted Repository](./threats/malicious_chart_injection_from_untrusted_repository.md)

*   **Description:** An attacker publishes a malicious chart to a public or compromised Helm repository. A user, using the `helm install` command, downloads and deploys this chart without verifying its source or integrity. The malicious chart contains code that exploits the cluster upon deployment.  Helm's chart fetching and installation mechanism is the direct vector.
*   **Impact:** Complete cluster compromise, data exfiltration, denial of service, resource hijacking, lateral movement, backdoor deployment.
*   **Affected Helm Component:** `helm install` command, Chart repository interaction (HTTP/HTTPS client), Chart loading and unpacking mechanism.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Use only trusted, verified Helm repositories.
    *   Verify chart integrity using provenance files and digital signatures (`helm verify`).
    *   Implement strict repository access controls.
    *   Use a private chart repository.
    *   Employ a policy engine (OPA Gatekeeper) for repository restrictions.

## Threat: [Supply Chain Attack via Compromised Subchart](./threats/supply_chain_attack_via_compromised_subchart.md)

*   **Description:** A seemingly legitimate chart includes a malicious subchart as a dependency.  Helm's dependency management system (`helm dependency update`, `helm install`) automatically fetches and includes this compromised subchart. The attacker leverages the trust in the parent chart to introduce malicious code via the subchart, which Helm then deploys.
*   **Impact:** Cluster compromise, data theft, denial of service – similar to direct chart injection, but potentially harder to detect.
*   **Affected Helm Component:** Chart dependency resolution (`requirements.yaml` or `Chart.yaml` dependencies), `helm dependency update`, `helm install`, Chart fetching mechanism.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Pin subchart versions to specific, known-good versions (avoid ranges or `latest`).
    *   Regularly update and audit subchart dependencies.
    *   Vendor subcharts for greater control.
    *   Use SBOM tools to track dependencies.
    *   Verify subchart provenance and integrity.

## Threat: [Secrets Exposure via Unencrypted Values (Helm Release History)](./threats/secrets_exposure_via_unencrypted_values__helm_release_history_.md)

*   **Description:** An attacker gains access to the Helm release history (stored as ConfigMaps or Secrets within the cluster, depending on the Helm version).  Helm stores the values used for each release. If secrets are included directly in `values.yaml` or custom values files *without encryption*, they are stored in plain text in the release history, which Helm manages. The attacker retrieves these secrets from the history.
*   **Impact:** Credential leakage, unauthorized access to sensitive systems and data.
*   **Affected Helm Component:** `helm install`, `helm upgrade`, Helm release history storage mechanism (ConfigMaps or Secrets), values file processing.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Never** store secrets directly in `values.yaml` or unencrypted files.
    *   Use Kubernetes Secrets objects.
    *   Integrate a dedicated secrets management solution with Helm.
    *   Use Helm plugins like `helm-secrets` (with SOPS) to encrypt secrets *before* Helm stores them.
    *   Limit the number of historical releases stored by Helm (`--history-max`).

## Threat: [Malicious Rollback to Vulnerable Version (via Helm)](./threats/malicious_rollback_to_vulnerable_version__via_helm_.md)

*   **Description:** An attacker gains the ability to execute Helm commands (e.g., compromised client, CI/CD access). The attacker uses the `helm rollback` command *directly* to revert a deployment to a previous, known-vulnerable version of the chart. This reintroduces the vulnerability, which the attacker can then exploit.  The attack vector is the `helm rollback` functionality itself.
*   **Impact:** Reintroduction of known vulnerabilities, service disruption, potential for data breaches or cluster compromise.
*   **Affected Helm Component:** `helm rollback` command, Helm release history management.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Restrict access to the `helm rollback` command using RBAC.
    *   Implement multi-factor authentication for Helm operations, especially rollbacks.
    *   Audit Helm history regularly.
    *   Use a policy engine to prevent rollbacks to known-vulnerable versions.
    *   Limit the number of historical releases.

## Threat: [Code Injection via Unvalidated Values (Helm Templating)](./threats/code_injection_via_unvalidated_values__helm_templating_.md)

*   **Description:** A Helm chart template uses user-supplied values without proper sanitization. An attacker provides a crafted value (via a custom values file or `--set`) that contains malicious code.  When Helm *renders the template*, this malicious code is injected into the resulting Kubernetes resources. This is a direct exploitation of Helm's templating engine.
*   **Impact:** Code injection, command execution within containers, configuration manipulation, potential cluster compromise.
*   **Affected Helm Component:** Helm templating engine (Go templating), values file processing, `helm install`, `helm upgrade`.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement strict input validation and sanitization for all user-provided values.
    *   Use a schema to define and validate value structure and types.
    *   Treat all user-provided values as untrusted.
    *   Use Helm's built-in template functions (e.g., `quote`, `b64enc`) for safe handling.
    *   Avoid using `tpl` function with user input directly.

## Threat: [Tiller (Helm 2) Compromise](./threats/tiller__helm_2__compromise.md)

* **Description:** (Helm 2 Specific) Tiller, the server-side component of Helm 2, runs with cluster-admin privileges. If an attacker compromises Tiller, they gain full control over the Kubernetes cluster. This is a direct compromise of a core Helm 2 component.
    * **Impact:** Complete cluster compromise.
    * **Affected Helm Component:** Tiller (Helm 2 only).
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Upgrade to Helm 3.** Helm 3 removed Tiller.
        * If using Helm 2 is unavoidable:
            *  Restrict Tiller's permissions using RBAC (complex and error-prone).
            *  Use network policies to limit access to Tiller.
            *  Implement strong authentication and authorization for Tiller.
            *  Regularly audit Tiller's activity.

