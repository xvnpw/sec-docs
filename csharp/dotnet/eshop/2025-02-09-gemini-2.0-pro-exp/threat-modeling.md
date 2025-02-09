# Threat Model Analysis for dotnet/eshop

## Threat: [Service Impersonation](./threats/service_impersonation.md)

*   **Threat:** Service Impersonation
    *   **Description:** An attacker crafts a malicious service or modifies an existing one to mimic a legitimate eShop microservice (e.g., `Ordering.API`, `Basket.API`). They exploit vulnerabilities in service discovery, DNS spoofing, or compromised credentials. The attacker's service receives requests intended for the real service.
    *   **Impact:**
        *   Data breaches (reading sensitive order/customer data).
        *   Fraudulent orders.
        *   Inventory data manipulation.
        *   Service disruption.
    *   **Affected Component:** All microservices, especially those using direct service-to-service calls or the API Gateway. Service discovery mechanisms (Consul, Kubernetes DNS) are targets.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Mutual TLS (mTLS):** Require mTLS for all inter-service communication.
        *   **Service Mesh:** Implement a service mesh (Istio, Linkerd) for built-in mTLS, traffic management, and observability.
        *   **JWT with Audience Validation:** Strictly validate the `aud` (audience) claim in JWTs.
        *   **Secure Service Discovery:** Secure the service discovery mechanism itself.

## Threat: [Event Bus Message Tampering](./threats/event_bus_message_tampering.md)

*   **Threat:** Event Bus Message Tampering
    *   **Description:** An attacker accesses the message broker (RabbitMQ/Azure Service Bus) and injects, modifies, or reorders messages. This could be via compromised credentials, message broker vulnerabilities, or a network attack.
    *   **Impact:**
        *   Fraudulent orders.
        *   Incorrect inventory updates.
        *   Data inconsistency.
        *   Denial of service.
        *   Potential code execution via message handler vulnerabilities.
    *   **Affected Component:** The Event Bus (RabbitMQ/Azure Service Bus) and all services that publish/subscribe to events (e.g., `Ordering.BackgroundTasks`, `IntegrationEventLogEF`).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Message Signing:** Digitally sign all messages. Subscribers verify signatures.
        *   **Message Encryption:** Encrypt sensitive message payloads.
        *   **Strong Authentication and Authorization:** Use strong credentials and RBAC for the message broker.
        *   **Idempotency:** Design message handlers to be idempotent.
        *   **Input Validation:** Strictly validate message content.
        *   **TLS for Broker Communication:** Use TLS to secure connections to the message broker.

## Threat: [API Gateway Bypass](./threats/api_gateway_bypass.md)

*   **Threat:** API Gateway Bypass
    *   **Description:** An attacker directly accesses backend microservices, bypassing the API Gateway (Ocelot). This could be through discovered internal IPs/hostnames, network misconfigurations, or vulnerabilities in the services.
    *   **Impact:**
        *   Unauthorized access to sensitive data/functionality.
        *   Bypassing of gateway authentication/authorization.
        *   Potential DoS against individual services.
    *   **Affected Component:** All backend microservices (`Catalog.API`, `Ordering.API`, `Basket.API`). Network configuration (Kubernetes network policies) is relevant.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Network Segmentation:** Use network policies to restrict access to backend services. Only the API Gateway should communicate directly.
        *   **Mutual TLS (mTLS):** Require mTLS between the API Gateway and backend services.
        *   **Internal Service Authentication:** Backend services should still require authentication, even if the gateway is bypassed.
        *   **Regular Security Audits:** Audit network configurations and service deployments.

## Threat: [Secrets Exposure](./threats/secrets_exposure.md)

*   **Threat:** Secrets Exposure
    *   **Description:** Sensitive information (database connection strings, API keys, credentials) is leaked through misconfigured services, logging, insecure storage, or secrets management vulnerabilities.
    *   **Impact:**
        *   Unauthorized access to databases and resources.
        *   Application compromise.
        *   Data breaches.
    *   **Affected Component:** All components using secrets (all microservices, API Gateway, Identity Service).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Secrets Management System:** Use a dedicated system (Azure Key Vault, HashiCorp Vault, Kubernetes Secrets).
        *   **Avoid Hardcoding:** Never hardcode secrets.
        *   **Environment Variables (Securely):** Use environment variables securely (Kubernetes Secrets).
        *   **Least Privilege:** Grant minimal permissions to access secrets.
        *   **Regular Rotation:** Rotate secrets regularly.
        *   **Audit Logging:** Enable audit logging for secret access.

## Threat: [Denial of Service (DoS) on a Specific Microservice](./threats/denial_of_service__dos__on_a_specific_microservice.md)

*   **Threat:** Denial of Service (DoS) on a Specific Microservice
    *   **Description:** An attacker floods a specific microservice (e.g., `Catalog.API`) with requests, making it unavailable. This could be targeted or a consequence of misconfiguration/compromise. Cascading failures are possible.
    *   **Impact:**
        *   Unavailability of the targeted service.
        *   Potential cascading failures.
        *   Degraded application performance.
    *   **Affected Component:** Any individual microservice (`Catalog.API`, `Ordering.API`, `Basket.API`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Rate Limiting:** Implement at the API Gateway and potentially within services.
        *   **Circuit Breakers:** Prevent cascading failures.
        *   **Bulkheads:** Isolate application parts.
        *   **Autoscaling:** Automatically increase instances under load.
        *   **Resource Quotas:** Set CPU/memory quotas per service.
        *   **DDoS Protection:** Implement at the network level.

## Threat: [gRPC Service Exploitation](./threats/grpc_service_exploitation.md)

* **Threat:** gRPC Service Exploitation
    * **Description:** An attacker exploits vulnerabilities in a gRPC service (insecure deserialization, buffer overflows, logic flaws) by sending crafted gRPC requests.
    * **Impact:**
        *   Remote code execution.
        *   Data breaches.
        *   Denial of service.
        *   Elevation of privilege.
    * **Affected Component:** Any gRPC service within eShop.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   **Input Validation:** Thoroughly validate all gRPC service input.
        *   **Secure Deserialization:** Use built-in protocol buffer deserialization.
        *   **Regular Updates:** Keep gRPC and libraries up to date.
        *   **Security Audits:** Conduct regular audits and penetration testing.
        *   **Fuzz Testing:** Use fuzz testing to find vulnerabilities.

## Threat: [Identity Service Compromise](./threats/identity_service_compromise.md)

* **Threat:** Identity Service Compromise
    * **Description:** An attacker gains control of the Identity Service (IdentityServer) through vulnerabilities, stolen credentials, or infrastructure compromise.
    * **Impact:**
        *   Complete application compromise. Impersonation of any user/client.
        *   Massive data breach.
        *   Ability to issue arbitrary tokens.
    * **Affected Component:** Identity Service (IdentityServer).
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        *   **Strong Authentication:** Strong passwords and MFA for IdentityServer administrators.
        *   **Regular Updates:** Keep IdentityServer and dependencies patched.
        *   **Secure Configuration:** Follow best practices for securing IdentityServer.
        *   **Network Segmentation:** Isolate the Identity Service.
        *   **Auditing:** Enable detailed auditing.
        *   **Penetration Testing:** Regularly test the Identity Service.

## Threat: [Insecure Direct Object Reference (IDOR) in Microservices](./threats/insecure_direct_object_reference__idor__in_microservices.md)

* **Threat:** Insecure Direct Object Reference (IDOR) in Microservices
    * **Description:** An attacker manipulates an ID (order ID, user ID) passed to a microservice to access unauthorized data. The service doesn't properly check if the requester is authorized.
    * **Impact:**
        *   Unauthorized access to sensitive data.
        *   Data modification or deletion.
    * **Affected Component:** Any microservice handling requests with IDs referencing resources (`Ordering.API`, `Basket.API`, `Catalog.API`).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   **Authorization Checks:** *Every* microservice must perform authorization checks *before* accessing/modifying data based on an ID.
        *   **Use of GUIDs/UUIDs:** Makes guessing valid IDs harder (but isn't a complete solution).
        *   **Object-Level Permissions:** Implement fine-grained permissions.

