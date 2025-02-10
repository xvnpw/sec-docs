# Attack Surface Analysis for signalr/signalr

## Attack Surface: [Unauthorized Hub Method Invocation](./attack_surfaces/unauthorized_hub_method_invocation.md)

*   **Description:** Attackers attempt to call SignalR Hub methods they are not authorized to access.
*   **SignalR Contribution:** SignalR *directly* exposes Hub methods as remotely callable endpoints. This is the core functionality of SignalR, and thus the primary attack vector.
*   **Example:** An attacker discovers a Hub method named `DeleteUser(int userId)` and calls it with a valid user ID, even though they lack the necessary permissions.
*   **Impact:** Data deletion, unauthorized actions, data leakage, privilege escalation.
*   **Risk Severity:** High to Critical (depending on the method's functionality).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Implement strict authorization using ASP.NET Core's `[Authorize]` attribute and policies.  Apply authorization to *every* Hub method that requires it.
        *   Use granular authorization policies (e.g., "Only Admins can call DeleteUser").
        *   Thoroughly validate *all* input parameters to Hub methods. Assume all input is malicious. Use strong typing, data annotations, and custom validation.
        *   Avoid direct use of parameters in sensitive operations (DB queries, file access) without sanitization.
        *   Consider DTOs (Data Transfer Objects) for input shape definition.

## Attack Surface: [Connection Hijacking/Impersonation](./attack_surfaces/connection_hijackingimpersonation.md)

*   **Description:** Attackers attempt to take over an existing SignalR connection or impersonate another user.
*   **SignalR Contribution:** SignalR *directly* manages connections and their associated state. The connection ID is the key to this attack, and SignalR is responsible for generating and managing it.
*   **Example:** An attacker obtains a valid connection ID and uses it to send messages as if they were the original user.
*   **Impact:** Data leakage, unauthorized actions, impersonation of legitimate users.
*   **Risk Severity:** High to Critical.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Ensure secure connection ID generation (SignalR's default behavior, but verify configuration).
        *   *Crucially*, avoid storing sensitive user data directly in `Context.Items` using the connection ID as the key. Associate data with a verified user identifier (e.g., from a claim).
        *   Implement robust authentication and authorization.
        *   Consider short-lived connection tokens.

## Attack Surface: [Cross-Site Request Forgery (CSRF) on Hub Methods](./attack_surfaces/cross-site_request_forgery__csrf__on_hub_methods.md)

*   **Description:** Attackers trick authenticated users into unknowingly executing actions on the SignalR Hub.
*   **SignalR Contribution:** SignalR Hub methods are *directly* exposed as endpoints, making them targets for CSRF if not protected.  This is a direct consequence of SignalR's design.
*   **Example:** A user, logged into an application using SignalR, visits a malicious site that submits a hidden request to the SignalR Hub's `TransferFunds` method.
*   **Impact:** Unauthorized actions, data modification, financial loss.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Implement anti-CSRF protection *specifically* for SignalR Hub methods. Integrate ASP.NET Core's anti-forgery tokens with SignalR (requires careful configuration: client sends token, hub validates).
        *   Consider JWT (JSON Web Tokens) for authentication, which can be less CSRF-prone if implemented correctly (token in header, not cookie).
        *   Ensure sensitive actions require explicit user interaction/confirmation.

