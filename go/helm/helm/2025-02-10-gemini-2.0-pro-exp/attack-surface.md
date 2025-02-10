# Attack Surface Analysis for helm/helm

## Attack Surface: [Malicious Charts from Untrusted Repositories](./attack_surfaces/malicious_charts_from_untrusted_repositories.md)

*   **Description:** Attackers publish malicious charts to public or compromised private repositories, containing harmful Kubernetes resources or configurations.
*   **How Helm Contributes:** Helm provides the mechanism for easily installing charts from repositories, making it simple to unknowingly deploy malicious code *via its core functionality*.
*   **Example:** A chart named "popular-database" is published to a public repository. It claims to deploy a database but actually contains a deployment that runs a cryptominer and exfiltrates data.
*   **Impact:** Complete cluster compromise, data exfiltration, resource hijacking, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:** Carefully vet any external dependencies. Sign and verify your own charts. Follow secure coding practices within chart templates.
    *   **Users:** Only use trusted chart repositories (official, well-vetted community, or internal). Verify chart provenance (signatures) before installation. Manually review chart source code, especially `values.yaml` and templates. Use vulnerability scanners that can analyze Helm charts.

## Attack Surface: [Repository Compromise](./attack_surfaces/repository_compromise.md)

*   **Description:** An attacker gains control of a chart repository and replaces legitimate charts with malicious ones or modifies existing charts.
*   **How Helm Contributes:** Helm *relies* on chart repositories as its primary distribution mechanism. A compromised repository directly undermines Helm's trust model.
*   **Example:** An attacker gains access to a private chart repository and replaces a legitimate application chart with a version that includes a backdoor.
*   **Impact:** Deployment of malicious code, cluster compromise, data breaches.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers/Repository Maintainers:** Use strong authentication (MFA) for repository access. Regularly monitor access logs. Use immutable repositories where possible. Implement robust change management processes.
    *   **Users:** Verify chart provenance (signatures) before installation. Use a trusted repository.

## Attack Surface: [Chart Manipulation (MITM)](./attack_surfaces/chart_manipulation__mitm_.md)

*   **Description:** An attacker intercepts and modifies a chart during download from a repository.
*   **How Helm Contributes:** Helm *downloads charts from remote repositories*, making it susceptible to MITM attacks if the connection is insecure or certificate validation is flawed. This is a direct function of Helm's operation.
*   **Example:** An attacker intercepts the download of a chart over HTTP and injects malicious code into the `templates/` directory.
*   **Impact:** Deployment of malicious code, cluster compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Users:** Always use HTTPS for chart repositories. Ensure Helm is configured to validate TLS certificates. Verify chart provenance (signatures).

## Attack Surface: [Template Injection in Charts](./attack_surfaces/template_injection_in_charts.md)

*   **Description:** User-provided input is improperly handled within a chart's templates, allowing attackers to inject malicious code.
*   **How Helm Contributes:** Helm's *templating engine*, a core component, is the direct enabler of this vulnerability if misused.
*   **Example:** A chart takes a user-provided domain name as input and directly embeds it into a Kubernetes Ingress resource without sanitization. An attacker could inject malicious configuration directives.
*   **Impact:** Manipulation of deployed resources, potential for code execution within the cluster, privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** Follow secure coding practices for Helm templates. Use Helm's built-in functions for safe string manipulation and escaping. Avoid directly embedding user input without sanitization. Use linters and static analysis tools.
    *   **Users:** Review chart templates for potential injection vulnerabilities before deployment.

## Attack Surface: [Dependency Confusion/Supply Chain Attacks (Subcharts)](./attack_surfaces/dependency_confusionsupply_chain_attacks__subcharts_.md)

*   **Description:** A chart depends on untrusted subcharts, making it vulnerable to supply chain attacks.
*   **How Helm Contributes:** Helm *supports chart dependencies (subcharts)* as a core feature, which can introduce vulnerabilities if not carefully managed. The dependency management is a direct Helm function.
*   **Example:** A chart depends on a subchart from a less-trusted repository. The subchart is compromised, leading to the compromise of the main application.
*   **Impact:** Deployment of malicious code through the compromised subchart, cluster compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** Carefully vet all chart dependencies. Use trusted repositories for subcharts. Pin subchart versions. Regularly update and audit dependencies. Consider vendoring.
    *   **Users:** Be aware of chart dependencies and their sources.

