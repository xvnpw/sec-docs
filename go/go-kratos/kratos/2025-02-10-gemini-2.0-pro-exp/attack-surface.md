# Attack Surface Analysis for go-kratos/kratos

## Attack Surface: [Unencrypted or Weakly Encrypted Communication (gRPC/HTTP)](./attack_surfaces/unencrypted_or_weakly_encrypted_communication__grpchttp_.md)

*   **Description:**  Data transmitted between services or between clients and services is intercepted and read or modified by an attacker.
*   **Kratos Contribution:** Kratos supports both gRPC and HTTP. While Kratos *encourages* TLS through documentation and examples, it does *not* enforce TLS by default. The framework provides configuration options for TLS settings (cipher suites, versions), but developers must actively and correctly configure them.  The responsibility for secure transport lies with the developer using Kratos.
*   **Example:** A developer deploys a Kratos service using gRPC but forgets to enable TLS in the Kratos server configuration. An attacker on the same network uses a packet sniffer to capture sensitive data.
*   **Impact:**  Data breach, data modification, loss of confidentiality, potential for man-in-the-middle attacks.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Enforce TLS:**  *Always* use TLS for both gRPC and HTTP communication within Kratos.  Configure Kratos servers and clients to *require* TLS.  This is a non-negotiable best practice.
    *   **Use Strong Cipher Suites:**  Configure Kratos (via its configuration mechanisms) to use only strong, modern cipher suites (e.g., those recommended by NIST or industry best practices).  Explicitly disable weak or outdated ciphers.
    *   **Use TLS 1.3 (or at least 1.2):**  Configure Kratos to use the latest TLS versions.  Disable older, vulnerable versions (TLS 1.0, 1.1) in the Kratos configuration.
    *   **Validate Certificates:**  Implement proper certificate validation on both the client and server sides *within the Kratos application*.  Check for hostname mismatches, expiration, and untrusted root CAs.  Do not rely on external validation alone.
    *   **Consider mTLS:**  Use mutual TLS (mTLS) for service-to-service communication, configured *within Kratos*, to ensure both the client and server are authenticated.  Kratos provides mechanisms to support mTLS.

## Attack Surface: [Middleware Bypass or Misconfiguration](./attack_surfaces/middleware_bypass_or_misconfiguration.md)

*   **Description:**  Attackers bypass security checks (authentication, authorization, rate limiting, etc.) that are intended to be enforced by Kratos middleware.
*   **Kratos Contribution:** Kratos's core security model relies heavily on its middleware system.  The framework provides the middleware mechanism, but the *correct application and configuration* of that middleware is entirely the developer's responsibility.  Incorrect ordering, incomplete application to routes, or flaws in custom middleware are all significant risks *directly* related to Kratos usage.
*   **Example:**  A developer implements authentication middleware in Kratos but only applies it to a subset of routes due to a configuration error. An attacker accesses a protected resource on an unprotected route, bypassing authentication entirely.
*   **Impact:**  Unauthorized access to resources, data breaches, privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Apply Middleware Globally:**  Ensure middleware is applied to *all* relevant routes, ideally using Kratos's global middleware configuration options to avoid accidental omissions.
    *   **Correct Middleware Ordering:**  Carefully consider the order of middleware execution within the Kratos application.  Authentication *must* come before authorization.  Kratos's documentation should be consulted for best practices.
    *   **Thorough Testing:**  Extensively test *all* routes of the Kratos application to ensure middleware is correctly applied and functioning as expected.  Use automated testing to prevent regressions in middleware configuration.
    *   **Review Custom Middleware:**  Carefully review any custom middleware implemented for the Kratos application for security vulnerabilities.  Custom middleware is a direct extension of the Kratos attack surface.
    *   **Least Privilege:** Design Kratos middleware to enforce the principle of least privilege.

## Attack Surface: [Insecure Service Discovery Integration](./attack_surfaces/insecure_service_discovery_integration.md)

*   **Description:**  Attackers manipulate the service discovery mechanism used by Kratos to redirect traffic, inject malicious services, or disrupt service communication.
*   **Kratos Contribution:** Kratos *integrates* with various service discovery systems (e.g., Consul, etcd, Kubernetes). While Kratos doesn't *implement* these systems, its reliance on them for service resolution makes their security *critical* to the Kratos application's security.  The way Kratos *uses* the service discovery system is a key factor.
*   **Example:**  An attacker compromises the etcd server used by a Kratos application for service discovery. The attacker registers a malicious service that impersonates a legitimate Kratos service, intercepting requests and stealing data.
*   **Impact:**  Data breaches, denial of service, man-in-the-middle attacks, application compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Service Discovery:**  Secure the service discovery mechanism itself (e.g., using TLS, authentication, and authorization).  This is a prerequisite for secure Kratos operation.
    *   **Validate Service Discovery Data:** Within the Kratos application, implement checks to validate the data retrieved from the service discovery system.  Don't blindly trust the registry.  For example, verify the IP address and port of discovered services against expected values.
    *   **Least Privilege for Service Discovery Access:**  Limit the Kratos application's access to the service discovery system to only the necessary permissions (e.g., read-only access if the service only needs to discover other services).

