# Attack Surface Analysis for openfaas/faas

## Attack Surface: [Gateway Denial of Service (DoS)](./attack_surfaces/gateway_denial_of_service__dos_.md)

*   **Description:**  Attackers flood the OpenFaaS Gateway with requests, making it unavailable to legitimate users.
*   **How FaaS Contributes:** The Gateway is the *central* point of entry for *all* function invocations in OpenFaaS, making it a prime target. OpenFaaS's auto-scaling, while helpful, can be overwhelmed or have misconfigured limits *specific to the OpenFaaS deployment*.
*   **Example:**  An attacker sends millions of HTTP requests to the Gateway's `/function/` endpoint, exhausting resources allocated *specifically to the OpenFaaS Gateway deployment*, preventing legitimate API calls.
*   **Impact:**  Service unavailability; legitimate users cannot access *any* OpenFaaS functions.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** Implement rate limiting and request throttling using OpenFaaS annotations (e.g., `com.openfaas.scale.min`, `com.openfaas.scale.max`, `com.openfaas.requests.concurrency`). These are *OpenFaaS-specific* configurations.
    *   **Users/Operators:** Configure appropriate resource limits (CPU, memory) for the *OpenFaaS Gateway deployment* itself.  Set up auto-scaling with appropriate thresholds *within the OpenFaaS configuration*. Monitor OpenFaaS Gateway metrics (request latency, error rates, queue depth) *as exposed by OpenFaaS*.

## Attack Surface: [Unauthorized Function Invocation](./attack_surfaces/unauthorized_function_invocation.md)

*   **Description:**  Attackers bypass authentication/authorization mechanisms to execute functions without proper credentials.
*   **How FaaS Contributes:** OpenFaaS *relies on the Gateway* for authentication, and misconfigurations or vulnerabilities *within the OpenFaaS authentication process* can allow unauthorized access. The *distributed nature of functions managed by OpenFaaS* makes consistent authorization enforcement challenging.
*   **Example:**  An attacker discovers a function endpoint that lacks proper authentication checks *within the OpenFaaS configuration* and invokes it directly, bypassing the Gateway's authentication *as implemented by OpenFaaS*. Or, an attacker exploits a vulnerability in the Gateway's OAuth 2.0 implementation *specific to OpenFaaS*.
*   **Impact:**  Data breaches, unauthorized actions, resource abuse, potential lateral movement within the OpenFaaS-managed environment.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:**  Implement robust authentication at the *OpenFaaS Gateway* (API keys, OAuth 2.0, OpenID Connect), leveraging *OpenFaaS's configuration options*. Use *OpenFaaS's built-in secrets management* for credentials. *Always* validate authorization within the function code itself, even if the *OpenFaaS Gateway* performs authentication.
    *   **Users/Operators:**  Configure strong authentication mechanisms *for the OpenFaaS Gateway*. Implement RBAC in Kubernetes *to control access to OpenFaaS functions*. Regularly audit authentication and authorization configurations *within OpenFaaS*.

## Attack Surface: [Container Escape (within the context of OpenFaaS)](./attack_surfaces/container_escape__within_the_context_of_openfaas_.md)

*   **Description:** Attackers exploit vulnerabilities in function code or container runtime to escape the container and access the host. While not *unique* to FaaS, the context is important.
*   **How FaaS Contributes:** OpenFaaS *mandates* the use of containers for function execution. The *focus on rapid deployment and short-lived functions in OpenFaaS* might lead to less rigorous container hardening *compared to traditional, long-running applications*.
*   **Example:** A function deployed *via OpenFaaS* has a vulnerability allowing arbitrary file writes. The attacker uses this to overwrite a system file and gain root access to the host, impacting the *OpenFaaS worker node*.
*   **Impact:** Full control of the host system (where the OpenFaaS worker is running), access to all resources, potential compromise of the entire cluster *hosting OpenFaaS*.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:** Write secure code, avoiding vulnerabilities that could lead to escape. Run functions as non-root *within the containers deployed by OpenFaaS*.
    *   **Users/Operators:** Use security profiles (Seccomp, AppArmor) to restrict container capabilities *of OpenFaaS-deployed functions*. Keep the container runtime (used by OpenFaaS) up-to-date. Use Kubernetes security contexts to enforce restrictions on Pods *created by OpenFaaS* (e.g., `runAsNonRoot`, `readOnlyRootFilesystem`). Implement network segmentation to limit the blast radius of an escape *from an OpenFaaS function*.

## Attack Surface: [Improper Secrets Management (within OpenFaaS)](./attack_surfaces/improper_secrets_management__within_openfaas_.md)

*   **Description:** Sensitive information (API keys, credentials) are handled insecurely.
*   **How FaaS Contributes:** Functions deployed *via OpenFaaS* often require secrets. OpenFaaS *provides specific mechanisms* for secrets management, but *improper use of these OpenFaaS features* leads to exposure.
*   **Example:** A function deployed *through OpenFaaS* has a hardcoded database password. An attacker gains access to the function's code or a compromised container *managed by OpenFaaS* and extracts the password.
*   **Impact:** Unauthorized access to sensitive resources, data breaches, potential compromise of other systems *accessible from the OpenFaaS environment*.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:** *Use OpenFaaS's built-in secrets management* (Kubernetes Secrets, accessed via OpenFaaS's mechanisms). *Never* hardcode secrets. Avoid environment variables if possible; if necessary, ensure they are encrypted at rest *using OpenFaaS-supported methods*.
    *   **Users/Operators:** Enforce policies requiring the use of *OpenFaaS's secrets management features*. Rotate secrets regularly. Consider a dedicated secrets solution (e.g., Vault) for advanced scenarios, *integrating it with OpenFaaS*.

## Attack Surface: [Provider Vulnerabilities (e.g., faas-netes)](./attack_surfaces/provider_vulnerabilities__e_g___faas-netes_.md)

*   **Description:** Vulnerabilities in the OpenFaaS provider itself (e.g., faas-netes for Kubernetes) are exploited.
*   **How FaaS Contributes:** The provider is a *core, essential component of OpenFaaS*, responsible for managing function deployments and scaling *within the OpenFaaS architecture*. Vulnerabilities *in the provider* have a direct and wide-ranging impact *on the entire OpenFaaS deployment*.
*   **Example:** A vulnerability in faas-netes allows an attacker to create arbitrary Kubernetes resources, gaining control of the cluster *specifically through the OpenFaaS control plane*.
*   **Impact:** Compromise of the *entire OpenFaaS deployment*, access to the underlying infrastructure, potential control of the entire cluster *managed by OpenFaaS*.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** (For OpenFaaS provider developers) Follow secure coding practices. Conduct regular security audits and penetration testing *of the OpenFaaS provider code*.
    *   **Users/Operators:** Keep the *OpenFaaS provider* and its dependencies up-to-date with the latest security patches. Follow security best practices for the underlying infrastructure (e.g., Kubernetes security best practices). Regularly audit the *OpenFaaS provider's* configuration and access controls. Use RBAC to limit the *OpenFaaS provider's* permissions.

