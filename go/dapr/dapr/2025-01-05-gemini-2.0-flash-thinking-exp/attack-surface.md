# Attack Surface Analysis for dapr/dapr

## Attack Surface: [Compromised Dapr Sidecar](./attack_surfaces/compromised_dapr_sidecar.md)

*   **Description:** An attacker gains control of the Dapr sidecar process running alongside the application.
    *   **How Dapr Contributes:** The sidecar acts as a privileged agent for the application, managing service invocation, state, pub/sub, bindings, and secrets. Compromising it grants access to these functionalities.
    *   **Example:** An attacker exploits a vulnerability in the sidecar process or gains unauthorized access to the container running the sidecar.
    *   **Impact:** Full control over Dapr's capabilities for the application, leading to data breaches, service disruption, and unauthorized actions.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Keep Dapr sidecar versions up-to-date with the latest security patches.
        *   Secure the container environment where the sidecar runs.
        *   Implement strong container image security practices.
        *   Limit access to the sidecar process and its resources.
        *   Monitor sidecar logs for suspicious activity.

## Attack Surface: [Unsecured Dapr Sidecar API (HTTP/gRPC)](./attack_surfaces/unsecured_dapr_sidecar_api__httpgrpc_.md)

*   **Description:** The HTTP and gRPC APIs exposed by the Dapr sidecar are not properly secured, allowing unauthorized access.
    *   **How Dapr Contributes:** Dapr relies on these APIs for communication between the application and the sidecar. If these are open, anyone can interact with the sidecar on behalf of the application.
    *   **Example:** An attacker sends malicious requests to the sidecar's HTTP or gRPC endpoints to invoke services, manipulate state, or publish messages without proper authorization.
    *   **Impact:** Unauthorized access to application functionalities, data manipulation, and potential service disruption.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Enable and enforce authentication and authorization for Dapr API calls using features like Access Control Policies (ACPs).
        *   Utilize mutual TLS (mTLS) for secure communication between the application and the sidecar.
        *   Restrict network access to the sidecar's API ports.
        *   Regularly review and update Dapr API access control configurations.

## Attack Surface: [Exploiting Dapr Service Invocation Without Proper Authorization](./attack_surfaces/exploiting_dapr_service_invocation_without_proper_authorization.md)

*   **Description:** An attacker bypasses application-level authorization by directly invoking services through Dapr's service invocation feature without proper checks.
    *   **How Dapr Contributes:** Dapr simplifies service-to-service communication, but if not configured correctly, it can allow bypassing internal authorization mechanisms.
    *   **Example:** An attacker uses Dapr's service invocation API to call a sensitive service endpoint directly, bypassing the application's intended authentication and authorization flow.
    *   **Impact:** Unauthorized access to sensitive functionalities and data.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement robust authorization logic within the target service, regardless of how the request arrives.
        *   Utilize Dapr's Access Control Policies (ACPs) to control which services can invoke other services.
        *   Combine Dapr's authorization with application-level authorization for defense in depth.

## Attack Surface: [State Store Manipulation via Dapr API](./attack_surfaces/state_store_manipulation_via_dapr_api.md)

*   **Description:** An attacker gains unauthorized access to modify or delete application state data stored through Dapr's state management API.
    *   **How Dapr Contributes:** Dapr provides a unified API for interacting with various state stores. If access to this API is not controlled, it becomes a target for manipulation.
    *   **Example:** An attacker uses the Dapr state management API to directly modify user profiles, inventory levels, or other critical application data.
    *   **Impact:** Data corruption, data breaches, and application malfunction.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strong authorization policies for accessing and modifying state through Dapr's API.
        *   Secure the underlying state store with appropriate access controls and encryption.
        *   Utilize Dapr's features for data encryption at rest and in transit if supported by the state store.
        *   Regularly audit state store access logs.

## Attack Surface: [Secret Exposure through Dapr Secrets API](./attack_surfaces/secret_exposure_through_dapr_secrets_api.md)

*   **Description:** An attacker gains unauthorized access to secrets managed by Dapr's Secrets API.
    *   **How Dapr Contributes:** Dapr provides a unified way to access secrets from various secret stores. If access to this API is not controlled, it can leak sensitive information.
    *   **Example:** An attacker uses the Dapr Secrets API to retrieve database credentials, API keys, or other sensitive information.
    *   **Impact:** Exposure of sensitive credentials, leading to further compromise of the application and related systems.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strong authentication and authorization for accessing secrets through Dapr's API.
        *   Secure the underlying secret store with robust access controls and encryption.
        *   Follow the principle of least privilege when granting access to secrets.
        *   Regularly rotate secrets.

## Attack Surface: [Compromised Dapr Control Plane Components](./attack_surfaces/compromised_dapr_control_plane_components.md)

*   **Description:** An attacker compromises Dapr control plane components like Placement, Operator, or Sentry.
    *   **How Dapr Contributes:** These components manage the overall Dapr infrastructure and service discovery. Compromising them can have widespread impact.
    *   **Example:** An attacker gains access to the Placement service and manipulates service instance locations, redirecting traffic to malicious endpoints.
    *   **Impact:** Service disruption, data interception, and potential takeover of the Dapr infrastructure.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Secure the infrastructure where Dapr control plane components are deployed.
        *   Implement strong authentication and authorization for accessing control plane APIs.
        *   Regularly update Dapr control plane components with the latest security patches.
        *   Monitor control plane logs for suspicious activity.

