# Attack Surface Analysis for dapr/dapr

## Attack Surface: [Unauthorized API Access](./attack_surfaces/unauthorized_api_access.md)

*Description:* Direct, unauthorized invocation of Dapr's HTTP or gRPC APIs exposed by the sidecar.
*How Dapr Contributes:* Dapr exposes APIs for all its building blocks (service invocation, state management, pub/sub, etc.). These APIs are the *primary* interface for interacting with Dapr and, by extension, the application. This is a *direct* Dapr attack surface.
*Example:* An attacker discovers the Dapr sidecar's HTTP port (default 3500) is exposed without authentication. They use a tool like `curl` to directly call the `/v1.0/state/my-store` endpoint and retrieve application state data.
*Impact:* Data breaches, unauthorized state modification, triggering of unintended application logic, denial of service.
*Risk Severity:* **Critical** (if exposed publicly without authentication) / **High** (if exposed within the cluster without proper authorization).
*Mitigation Strategies:*
    *   **Authentication:** Enable API token authentication or mTLS to restrict access to authorized clients. Use strong, randomly generated API tokens.
    *   **Authorization:** Implement fine-grained authorization policies using Dapr's access control lists (ACLs) or integrate with an external authorization service (e.g., OPA). Define which applications/services can access specific Dapr APIs and resources.
    *   **Network Policies:** Use Kubernetes Network Policies (or equivalent) to restrict network access to the Dapr sidecar's ports. Only allow traffic from authorized pods/services.
    *   **Least Privilege:** Configure Dapr to listen only on the necessary network interfaces (e.g., localhost if only the application container needs access).

## Attack Surface: [Sidecar Injection/Modification Attacks](./attack_surfaces/sidecar_injectionmodification_attacks.md)

*Description:* An attacker gains control of the Kubernetes cluster and injects a malicious sidecar or modifies the configuration of an *existing Dapr sidecar*.
*How Dapr Contributes:* Dapr *relies* on the sidecar injection mechanism. If this mechanism, or the *Dapr sidecar itself*, is compromised, the entire Dapr security model can be bypassed. This is a direct attack on Dapr's operational model.
*Example:* An attacker compromises a Kubernetes node and modifies the Dapr sidecar configuration to disable mTLS and API token authentication. They can then access the Dapr APIs without authorization.
*Impact:* Complete compromise of the application and its data, ability to intercept and manipulate all Dapr-mediated communication.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Strong Kubernetes Security:** Implement robust Kubernetes security best practices (RBAC, network policies, pod security policies/standards, image scanning, etc.). *While this is a general mitigation, it's critical for preventing Dapr-specific attacks.*
    *   **Policy Enforcement:** Use a policy engine (like OPA Gatekeeper) to enforce strict rules on sidecar injection and *Dapr sidecar configuration*.
    *   **Image Integrity:** Use signed Dapr container images and verify their integrity before deployment.
    *   **Monitoring and Auditing:** Monitor for unauthorized sidecar injections or modifications *specifically targeting Dapr*.

## Attack Surface: [Secrets Exposure via Dapr](./attack_surfaces/secrets_exposure_via_dapr.md)

*Description:* Exposure of secrets managed *through Dapr's secrets API* due to misconfiguration or compromise of the secret store *or the Dapr configuration itself*.
*How Dapr Contributes:* Dapr *provides* a secrets management API.  The vulnerability arises from how Dapr is configured to *use* this API and interact with the secret store. This is a direct attack surface related to Dapr's secrets management functionality.
*Example:* Dapr is configured to use Kubernetes Secrets, but the Dapr sidecar's configuration (which specifies how to access the secrets) is exposed or compromised.
*Impact:* Exposure of sensitive information (API keys, database credentials, etc.).
*Risk Severity:* **High** / **Critical** (depending on the sensitivity of the exposed secrets).
*Mitigation Strategies:*
    *   **Secure Secret Store:** Follow security best practices for the chosen secret store.
    *   **Least Privilege (Dapr Access to Secrets):** Configure Dapr's access to the secret store with the *minimum required permissions*.
    *   **Avoid Storing Secrets in Configuration Files:** Use environment variables or Kubernetes Secrets to inject secrets into the Dapr sidecar, *avoiding direct inclusion in Dapr configuration files*.
    *   **Regular Secret Rotation:** Rotate secrets regularly.

## Attack Surface: [Control Plane Component Compromise](./attack_surfaces/control_plane_component_compromise.md)

*Description:* An attacker gains control over one of Dapr's control plane components (dapr-operator, dapr-placement, dapr-sentry, dapr-sidecar-injector).
*How Dapr Contributes:* These components are *integral* to Dapr's operation. Their compromise directly impacts Dapr's functionality and security.
*Example:* An attacker compromises the dapr-sentry component and issues rogue certificates, allowing them to impersonate legitimate services and intercept traffic.
*Impact:* Widespread disruption of Dapr-enabled applications, potential for man-in-the-middle attacks, data breaches, and complete system compromise.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Kubernetes RBAC:** Strictly limit access to the *Dapr control plane components* using Kubernetes Role-Based Access Control.
    *   **Network Policies:** Isolate the *Dapr control plane components* using network policies.
    *   **Regular Auditing:** Monitor logs and events for the *Dapr control plane components*.
    *   **Secure Sentry:** Protect the Sentry CA's private key with utmost care (e.g., using a Hardware Security Module).
    *   **Keep Dapr Updated:** Regularly update Dapr.

