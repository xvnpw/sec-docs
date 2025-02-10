# Attack Surface Analysis for jbogard/mediatr

## Attack Surface: [Unauthorized Handler Execution](./attack_surfaces/unauthorized_handler_execution.md)

*   **1. Unauthorized Handler Execution**

    *   **Description:** Attackers trigger MediatR handlers with malicious or unexpected input, bypassing intended application logic and authorization.
    *   **How MediatR Contributes:** MediatR's core function is to route messages to handlers. This indirection is the *direct* mechanism enabling this attack if input validation and authorization within the handler are insufficient.
    *   **Example:** An application uses a `CreateUserCommand` handler. A vulnerability allows an attacker to construct and send a `CreateUserCommand` directly (bypassing API-level validation) with elevated privileges, creating an unauthorized administrator account.  MediatR *directly* executes this command.
    *   **Impact:** Unauthorized data creation/modification/deletion, privilege escalation, execution of arbitrary logic.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Validation:** Implement rigorous input validation *within each handler*. Treat the request object as untrusted. Use validation libraries.
        *   **Authorization Checks:** Perform authorization checks *within each handler*.
        *   **Principle of Least Privilege:** Ensure handlers have only minimum necessary permissions.
        *   **Request Object Design:** Design request objects to be specific and constrained.

## Attack Surface: [Malicious Notification Exploitation](./attack_surfaces/malicious_notification_exploitation.md)

*   **2. Malicious Notification Exploitation**

    *   **Description:** Attackers exploit vulnerabilities in notification handlers or the notification system to intercept messages, execute malicious code, or cause unintended side effects.
    *   **How MediatR Contributes:** MediatR's notification system (`INotification`, `INotificationHandler`) is the *direct* mechanism that allows multiple handlers to respond to a single notification.  This broadcast nature is the core contributor to the attack surface.
    *   **Example:** A notification is published when a user's password changes. A malicious handler (registered via a separate vulnerability, but executed *by MediatR*) intercepts this notification and sends the new password to an attacker.
    *   **Impact:** Data breaches, unauthorized actions, denial of service (if handlers are resource-intensive).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Handler Review:** Thoroughly review *all* notification handlers for vulnerabilities.
        *   **Limited Handler Responsibilities:** Keep notification handlers focused; avoid complex operations.
        *   **Asynchronous Notifications:** Use `PublishAsync` where appropriate to mitigate DoS.
        *   **Secure Dependency Injection:** Ensure the DI container prevents unauthorized handler registration (this is a *prerequisite* for MediatR security).
        *   **Monitoring:** Monitor notification processing.

## Attack Surface: [Pipeline Behavior Bypass](./attack_surfaces/pipeline_behavior_bypass.md)

*   **3. Pipeline Behavior Bypass**

    *   **Description:** Attackers exploit misconfigurations or vulnerabilities in pipeline behaviors to bypass security checks (validation, authorization).
    *   **How MediatR Contributes:** MediatR's pipeline behaviors (`IPipelineBehavior`) are the *direct* mechanism for implementing cross-cutting concerns.  Incorrect ordering or flawed logic *within the MediatR pipeline* creates the bypass opportunity.
    *   **Example:** A validation behavior is placed *after* a logging behavior in the *MediatR pipeline*. An attacker sends an invalid request. The logging behavior (executed *by MediatR*) logs sensitive data *before* validation fails.
    *   **Impact:** Bypassed security checks, data leakage, unauthorized actions.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Correct Behavior Ordering:** Ensure validation/authorization behaviors execute *first* in the pipeline.
        *   **Robust Exception Handling:** Implement proper exception handling in behaviors.
        *   **Defense in Depth:** Handlers should *also* perform validation/authorization (MediatR's pipeline is a *supplement*, not a replacement).
        *   **Testing:** Thoroughly test pipeline behavior interactions *within MediatR's context*.

