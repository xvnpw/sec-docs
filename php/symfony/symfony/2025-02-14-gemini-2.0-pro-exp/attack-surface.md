# Attack Surface Analysis for symfony/symfony

## Attack Surface: [Debug Mode & Environment Exposure](./attack_surfaces/debug_mode_&_environment_exposure.md)

*   **Description:**  Production systems running in development mode or with debugging enabled.
*   **Symfony Contribution:** Symfony provides a `dev` environment and a debug mode (`APP_DEBUG`) for development, which expose detailed error information *by design*. This is a core framework feature.
*   **Example:**  A production server with `APP_ENV=dev` displays full stack traces and configuration details (including database credentials) to any user encountering an error.
*   **Impact:**  Exposure of sensitive information (database credentials, API keys, internal file paths, application logic), facilitating further attacks.
*   **Risk Severity:** `Critical`
*   **Mitigation Strategies:**
    *   **Developers:**  Ensure `APP_ENV` is set to `prod` and `APP_DEBUG` is `false` (or `0`) in production deployments.  Use environment variables, not hardcoded values.  *Never* commit `.env.local` or similar files containing secrets.
    *   **Users/Admins:**  Verify server configuration and environment variables after deployment.  Monitor server logs for indicators of debug mode being enabled.

## Attack Surface: [Route Parameter Injection](./attack_surfaces/route_parameter_injection.md)

*   **Description:**  Insufficient validation of user-supplied data used as route parameters.
*   **Symfony Contribution:**  Symfony's routing system *allows* dynamic parameters in routes, and it's the developer's responsibility to validate them. This is a direct consequence of using Symfony's routing.
*   **Example:**  A route `/users/{id}` where `{id}` is directly used in a database query without sanitization or type checking, leading to SQL injection.
*   **Impact:**  Data breaches, unauthorized access, data modification, potential for code execution (depending on the injection type).
*   **Risk Severity:** `High`
*   **Mitigation Strategies:**
    *   **Developers:**  Use route parameter constraints (e.g., `requirements: { id: '\d+' }`).  Use ParamConverters for automatic validation and type conversion.  *Always* validate and sanitize user input within controllers, even with route constraints.
    *   **Users/Admins:**  Cannot directly mitigate this; relies entirely on developer implementation.

## Attack Surface: [Firewall & Access Control Misconfiguration](./attack_surfaces/firewall_&_access_control_misconfiguration.md)

*   **Description:**  Incorrectly configured security firewalls or access control rules.
*   **Symfony Contribution:**  Symfony's Security component provides the firewall and access control features. Misconfiguration *within* this Symfony component is the direct cause.
*   **Example:**  A firewall rule intended to protect `/admin` accidentally allows access to `/admin/users/delete` without authentication due to a typo or incorrect pattern.
*   **Impact:**  Unauthorized access to sensitive areas, data breaches, denial of service.
*   **Risk Severity:** `High`
*   **Mitigation Strategies:**
    *   **Developers:**  Carefully define firewall patterns and access control rules.  Use a "deny-by-default" approach.  Thoroughly test security configurations using both automated and manual testing.
    *   **Users/Admins:**  Review security configurations (if accessible) and conduct penetration testing to identify misconfigurations.

## Attack Surface: [Insufficient CSRF Protection](./attack_surfaces/insufficient_csrf_protection.md)

*   **Description:**  Missing or inadequate Cross-Site Request Forgery (CSRF) protection on forms.
*   **Symfony Contribution:**  Symfony's Form component provides built-in CSRF protection, but it must be explicitly enabled and used correctly. The vulnerability arises from *not* using or misusing this Symfony feature.
*   **Example:**  A form for changing a user's email address lacks a CSRF token, allowing an attacker to trick a logged-in user into changing their email via a malicious link.
*   **Impact:**  Unauthorized actions performed on behalf of a user (account takeover, data modification, etc.).
*   **Risk Severity:** `High`
*   **Mitigation Strategies:**
    *   **Developers:**  Enable CSRF protection globally or per-form.  Use `{{ csrf_token('intention') }}` in Twig templates to include the token.  Ensure proper token validation on the server-side.
    *   **Users/Admins:**  Cannot directly mitigate this; relies entirely on developer implementation.

## Attack Surface: [DQL Injection (Doctrine)](./attack_surfaces/dql_injection__doctrine_.md)

*   **Description:**  Injection of malicious code into Doctrine Query Language (DQL) queries.
*   **Symfony Contribution:**  Symfony commonly uses Doctrine as its ORM, and while Doctrine is designed to prevent SQL injection, DQL injection is still possible with *improper usage within the Symfony/Doctrine context*.
*   **Example:**  Concatenating user input directly into a DQL query string without using prepared statements or the QueryBuilder.
*   **Impact:**  Data breaches, unauthorized data access, data modification.
*   **Risk Severity:** `High`
*   **Mitigation Strategies:**
    *   **Developers:**  Use parameterized DQL queries (with `setParameter()`).  Use the QueryBuilder for programmatic query construction.  *Never* directly concatenate user input into DQL strings.
    *   **Users/Admins:**  Cannot directly mitigate this; relies entirely on developer implementation.

## Attack Surface: [Unsafe Deserialization](./attack_surfaces/unsafe_deserialization.md)

*   **Description:** Deserializing data from untrusted sources without proper validation.
*   **Symfony Contribution:** While Symfony doesn't have a specific "deserialization component," it's the *use of PHP's deserialization capabilities within a Symfony application*, often in conjunction with user input or external data, that creates the risk. The framework doesn't prevent this, making it a potential issue.
*   **Example:** Deserializing a user-provided YAML or JSON string directly into an object without validating its structure or contents, potentially leading to the instantiation of arbitrary classes or execution of malicious code, often leveraging Symfony's autowiring or service container.
*   **Impact:** Remote Code Execution (RCE), application compromise.
*   **Risk Severity:** `Critical`
*   **Mitigation Strategies:**
        *   **Developers:** Avoid deserializing data from untrusted sources whenever possible. If deserialization is necessary, use a safe and well-vetted deserialization library. Implement strict validation and sanitization of the data *before* and *after* deserialization. Use whitelisting to allow only specific classes and properties to be deserialized.
        *   **Users/Admins:** Cannot directly mitigate this; relies entirely on developer implementation.

