# Attack Surface Analysis for openfaas/faas

## Attack Surface: [Unauthenticated Gateway API Access](./attack_surfaces/unauthenticated_gateway_api_access.md)

*   **Description:** The OpenFaaS Gateway API, which controls function deployment, invocation, and platform management, is accessible without proper authentication and authorization.
*   **How FaaS Contributes to Attack Surface:** The Gateway is the central control plane of OpenFaaS. By design, it exposes an API for management and function interaction. Lack of authentication on this API directly exposes the entire platform.
*   **Example:** An attacker, without any credentials, uses `faas-cli` or direct API calls to deploy a malicious function that mines cryptocurrency or exfiltrates data, gaining unauthorized code execution within the OpenFaaS environment.
*   **Impact:** **Critical**. Complete compromise of the OpenFaaS platform. Attackers can deploy and manage functions, access platform resources, cause denial of service, and potentially pivot to underlying infrastructure.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Mandatory Gateway Authentication:**  Enforce authentication for all Gateway API requests. Utilize OpenFaaS's built-in authentication mechanisms (API Keys, OAuth2, OpenID Connect) or integrate with external identity providers.
    *   **Role-Based Access Control (RBAC):** Implement RBAC policies to restrict API access based on user roles and permissions. Define granular permissions for function deployment, invocation, management, and platform administration.
    *   **Regular Security Audits of Authentication Configuration:** Periodically review and audit the Gateway's authentication and authorization configurations to ensure they are correctly implemented and remain effective.

## Attack Surface: [Gateway API Vulnerabilities (Injection, Authentication/Authorization Bypass)](./attack_surfaces/gateway_api_vulnerabilities__injection__authenticationauthorization_bypass_.md)

*   **Description:** Security vulnerabilities exist within the OpenFaaS Gateway API code itself, such as injection flaws (e.g., command injection, XSS), or flaws leading to authentication or authorization bypass.
*   **How FaaS Contributes to Attack Surface:** The Gateway API is a core component of OpenFaaS, responsible for request routing and platform logic. Vulnerabilities in this component directly expose the platform's security.
*   **Example:** An attacker exploits a command injection vulnerability in the function deployment endpoint of the Gateway API. By crafting a malicious function name or configuration, they execute arbitrary commands on the Gateway server, potentially gaining control of the server or the underlying cluster.
*   **Impact:** **High**. Compromise of the Gateway server, potential control over the OpenFaaS cluster, unauthorized access to platform resources, and ability to manipulate function deployments and invocations.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Secure Development Practices for Gateway:** Adhere to secure coding practices during Gateway development and maintenance. This includes rigorous input validation, output encoding, and using secure API frameworks to prevent common web vulnerabilities.
    *   **Regular Security Penetration Testing of Gateway API:** Conduct regular penetration testing and vulnerability scanning specifically targeting the Gateway API to identify and remediate potential security flaws.
    *   **Keep OpenFaaS Updated (Gateway Component):**  Maintain OpenFaaS at the latest stable version to benefit from security patches and bug fixes for the Gateway component.
    *   **Web Application Firewall (WAF) for Gateway:** Consider deploying a WAF in front of the Gateway to detect and block common web application attacks targeting the API.

## Attack Surface: [Denial of Service (DoS) Attacks against the Gateway](./attack_surfaces/denial_of_service__dos__attacks_against_the_gateway.md)

*   **Description:** Attackers target the OpenFaaS Gateway with a flood of requests or resource-intensive operations, aiming to overwhelm it and disrupt function execution and platform availability.
*   **How FaaS Contributes to Attack Surface:** The Gateway is the single entry point for all function invocations and management operations in OpenFaaS. Its availability is critical for the entire platform's functionality.
*   **Example:** An attacker launches a large-scale HTTP flood attack against the Gateway's function invocation endpoint. The Gateway becomes overloaded, unable to process legitimate requests, and effectively causing a denial of service for all functions deployed on OpenFaaS.
*   **Impact:** **High**. Platform unavailability, disruption of all function execution, inability to manage the OpenFaaS environment, and potential business disruption for applications relying on OpenFaaS.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Rate Limiting on Gateway API:** Implement rate limiting at the Gateway level to restrict the number of requests from a single source or across the platform within a given timeframe. This can mitigate brute-force attacks and excessive request floods.
    *   **Resource Limits for Gateway Component:** Configure appropriate resource limits (CPU, memory) for the Gateway deployment to prevent resource exhaustion under heavy load. Ensure sufficient resources are allocated for expected traffic peaks.
    *   **DDoS Protection Infrastructure:** Utilize DDoS mitigation services or infrastructure-level defenses (e.g., cloud provider DDoS protection) to filter out malicious traffic before it reaches the Gateway.
    *   **Scalable Gateway Deployment:** Design the Gateway infrastructure to be horizontally scalable to handle increased traffic loads and potential DoS attempts. Use load balancing and auto-scaling to distribute traffic and maintain availability.

## Attack Surface: [Function Secrets Management Vulnerabilities (Improper Use of FaaS Secrets)](./attack_surfaces/function_secrets_management_vulnerabilities__improper_use_of_faas_secrets_.md)

*   **Description:**  Developers or operators improperly manage secrets required by functions within the OpenFaaS environment, leading to exposure or insecure handling of sensitive credentials. This often involves bypassing or misusing OpenFaaS's intended secrets management mechanisms.
*   **How FaaS Contributes to Attack Surface:** OpenFaaS provides a secrets management system. However, if users circumvent or misuse this system (e.g., hardcoding secrets, using insecure environment variables directly instead of FaaS secrets), they introduce vulnerabilities within the FaaS context.
*   **Example:** Instead of using OpenFaaS secrets, a developer hardcodes an API key directly into the function code or sets it as a plain text environment variable in the function deployment manifest. This secret becomes easily accessible if an attacker gains access to the function image, container, or deployment configuration.
*   **Impact:** **High**. Exposure of sensitive credentials (API keys, database passwords, etc.), unauthorized access to external services and resources protected by these secrets, data breaches, and potential escalation of privileges.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Strictly Enforce Use of OpenFaaS Secrets:** Mandate and enforce the use of OpenFaaS's built-in secrets management for all sensitive data required by functions. Provide clear guidelines and training to developers on how to properly use FaaS secrets.
    *   **Disable or Restrict Alternative Secret Injection Methods:**  If possible, restrict or disable alternative methods of injecting secrets that bypass OpenFaaS secrets management, such as directly setting environment variables in deployment manifests.
    *   **Regular Audits of Secret Usage:** Conduct periodic audits to ensure functions are correctly using OpenFaaS secrets and not resorting to insecure secret management practices.
    *   **Secrets Scanning in Function Images:** Implement automated scanning of function images to detect potential hardcoded secrets or other insecure secret storage practices during the build process.

## Attack Surface: [Unsecured Function Registry](./attack_surfaces/unsecured_function_registry.md)

*   **Description:** The container registry used by OpenFaaS to store function images is not adequately secured, allowing unauthorized access to function images.
*   **How FaaS Contributes to Attack Surface:** OpenFaaS relies on a container registry to store and distribute function images. The security of this registry is directly tied to the security of the functions deployed on OpenFaaS. A compromised registry can lead to widespread impact across the platform.
*   **Example:** An attacker gains anonymous read access to the function registry. They download function images, reverse engineer function code, and discover vulnerabilities or embedded secrets. In a more critical scenario, they gain write access and replace legitimate function images with malicious ones, leading to supply chain attacks when users deploy functions from the compromised registry.
*   **Impact:** **High**. Information disclosure of function code and configurations, potential extraction of secrets, image tampering or poisoning leading to deployment of malicious functions across the platform, and supply chain compromise.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Strong Registry Access Control:** Implement robust access control mechanisms for the function registry. Require authentication and authorization for all access, including image pulls and pushes. Use role-based access control to manage permissions.
    *   **Private Registry Usage:** Utilize a private container registry that is not publicly accessible to store sensitive function images. Restrict network access to the registry to authorized OpenFaaS components and users.
    *   **Image Scanning and Vulnerability Management in Registry:** Integrate automated image scanning tools into the registry to scan function images for vulnerabilities before they are deployed. Implement a vulnerability management process to address identified issues.
    *   **Content Trust and Image Signing:** Implement container image signing and verification mechanisms (e.g., Docker Content Trust, Notary) to ensure the integrity and authenticity of function images pulled from the registry. This helps prevent image tampering and ensures that deployed images are from trusted sources.

