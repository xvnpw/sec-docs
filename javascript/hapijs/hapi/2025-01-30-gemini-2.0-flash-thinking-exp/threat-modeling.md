# Threat Model Analysis for hapijs/hapi

## Threat: [Unintended Route Exposure due to Misconfiguration](./threats/unintended_route_exposure_due_to_misconfiguration.md)

*   **Description:** Attacker accesses sensitive or unintended routes due to misconfigured route definitions in Hapi.js. For example, attacker might access development routes left enabled in production, or routes without proper authorization checks, potentially gaining access to sensitive data or functionalities.
*   **Impact:** Unauthorized access to sensitive data or functionalities, potential data breaches or system compromise.
*   **Hapi Component Affected:** `server.route()` configuration, routing logic.
*   **Risk Severity:** High to Critical (depending on the sensitivity of exposed routes).
*   **Mitigation Strategies:**
    *   Carefully review and define route paths and methods.
    *   Implement robust authorization strategies and policies for all routes.
    *   Use route prefixes and versioning to manage API endpoints effectively.
    *   Regularly audit route configurations.

## Threat: [Authentication Strategy Vulnerabilities](./threats/authentication_strategy_vulnerabilities.md)

*   **Description:** Attacker exploits vulnerabilities in custom or third-party Hapi authentication strategies. This could involve bypassing authentication logic, exploiting insecure credential handling, or leveraging misconfigurations to gain unauthorized access to protected resources managed by Hapi.
*   **Impact:** Unauthorized access to protected resources, account compromise, data breaches.
*   **Hapi Component Affected:** Hapi authentication strategies (`server.auth.strategy()`, `server.auth.default()`), authentication plugins.
*   **Risk Severity:** High to Critical (direct impact on access control).
*   **Mitigation Strategies:**
    *   Thoroughly vet and audit authentication strategies.
    *   Follow secure coding practices when developing custom strategies.
    *   Use well-established and reputable authentication strategies.
    *   Properly configure and test authentication strategies.

## Threat: [Authorization Bypass due to Strategy Misconfiguration or Logic Errors](./threats/authorization_bypass_due_to_strategy_misconfiguration_or_logic_errors.md)

*   **Description:** Attacker bypasses authorization checks due to misconfigured authorization strategies or flaws in authorization logic within Hapi.js. For example, incorrect scope definitions, logic errors in authorization functions, or routing vulnerabilities might allow unauthorized access to protected resources.
*   **Impact:** Unauthorized access to protected resources, privilege escalation, data breaches.
*   **Hapi Component Affected:** Hapi authorization mechanisms, route-level `auth` configuration, authorization strategies.
*   **Risk Severity:** High to Critical (direct impact on access control).
*   **Mitigation Strategies:**
    *   Clearly define and implement authorization policies and scopes.
    *   Thoroughly test authorization logic and configurations.
    *   Use Hapi's built-in authorization features and plugins.
    *   Regularly review and audit authorization configurations and code.

