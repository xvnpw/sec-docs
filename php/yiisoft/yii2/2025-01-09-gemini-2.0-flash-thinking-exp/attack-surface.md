# Attack Surface Analysis for yiisoft/yii2

## Attack Surface: [Mass Assignment Vulnerability](./attack_surfaces/mass_assignment_vulnerability.md)

*   **Description:** Attackers can modify model attributes they shouldn't have access to by including unexpected parameters in their requests.
    *   **How Yii2 Contributes:** Yii2's Active Record allows mass assignment, where attributes are populated directly from request parameters. If `safeAttributes()` are not properly defined in the model, attackers can modify unintended model attributes.
    *   **Example:** A user updating their profile sends a request with an additional `is_admin=1` parameter. If the `is_admin` attribute is not marked as unsafe and is mass-assignable, the user could potentially elevate their privileges.
    *   **Impact:** Data corruption, privilege escalation, unauthorized access.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Explicitly define safe attributes using the `safeAttributes()` method in your models. Only include attributes that should be mass-assignable. Use scenarios to define different sets of safe attributes for different actions.

## Attack Surface: [Unprotected Debug Mode in Production](./attack_surfaces/unprotected_debug_mode_in_production.md)

*   **Description:** Leaving debug mode enabled in a production environment exposes sensitive information.
    *   **How Yii2 Contributes:** Yii2's configuration allows enabling a debug mode that provides detailed error messages, internal paths, and potentially database connection details.
    *   **Example:** An error occurs on the live site, and the detailed error message reveals the application's file structure, database credentials, or internal logic.
    *   **Impact:** Information disclosure, potential for further exploitation based on revealed details.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:** Ensure debug mode is disabled in the production environment configuration. This is typically controlled by the `YII_DEBUG` constant in the entry script (`index.php`).

## Attack Surface: [Cross-Site Scripting (XSS) due to Incorrect Output Encoding](./attack_surfaces/cross-site_scripting__xss__due_to_incorrect_output_encoding.md)

*   **Description:** Attackers can inject malicious scripts into web pages viewed by other users.
    *   **How Yii2 Contributes:** While Yii2 provides helper functions for output encoding (e.g., `Html::encode()`), developers might forget to use them or use them incorrectly when displaying user-generated content or data from external sources.
    *   **Example:** A user submits a comment containing `<script>alert('XSS')</script>`. If this comment is displayed without proper encoding, the script will execute in other users' browsers.
    *   **Impact:** Session hijacking, cookie theft, redirection to malicious sites, defacement.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**  Always encode output that originates from user input or untrusted sources before displaying it in HTML. Use `Html::encode()` for plain text and other appropriate encoding functions for different contexts.

## Attack Surface: [Cross-Site Request Forgery (CSRF) Token Bypass or Missing Protection](./attack_surfaces/cross-site_request_forgery__csrf__token_bypass_or_missing_protection.md)

*   **Description:** Attackers can trick authenticated users into performing unintended actions on the web application.
    *   **How Yii2 Contributes:** Yii2 provides built-in CSRF protection. However, developers might disable it where it's needed, misconfigure it, or introduce vulnerabilities in custom implementations.
    *   **Example:** A user is logged into their bank account. An attacker sends them a link to a malicious website that contains a form submitting a money transfer request to the bank. If CSRF protection is missing or bypassed, the bank might process the request as if it came from the legitimate user.
    *   **Impact:** Unauthorized actions, data modification, financial loss.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Ensure CSRF protection is enabled globally or for relevant actions. Use Yii2's `yii\web\Controller::enableCsrfValidation` or `yii\filters\CsrfValidation` filter. Use `Html::beginForm()` to automatically include the CSRF token in forms. For AJAX requests, include the CSRF token in the request headers.

## Attack Surface: [Session Fixation or Hijacking due to Insecure Session Management](./attack_surfaces/session_fixation_or_hijacking_due_to_insecure_session_management.md)

*   **Description:** Attackers can steal or fixate user session IDs to gain unauthorized access.
    *   **How Yii2 Contributes:** While Yii2 provides session management components, developers might misconfigure session settings (e.g., using insecure cookie settings, not regenerating session IDs after login) or introduce vulnerabilities in custom session handling.
    *   **Example:** An attacker forces a user to use a known session ID (session fixation) or steals a user's session cookie (session hijacking) to impersonate them.
    *   **Impact:** Unauthorized access, account takeover.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Configure secure session cookie settings (e.g., `HttpOnly`, `Secure`). Regenerate session IDs after successful login. Consider using a secure session storage mechanism.

## Attack Surface: [Template Injection (if using external templating engines)](./attack_surfaces/template_injection__if_using_external_templating_engines_.md)

*   **Description:** Attackers can inject malicious code into template files, leading to code execution on the server.
    *   **How Yii2 Contributes:** If a developer uses a templating engine like Twig and allows user-controlled data to be directly embedded within template code without proper sanitization, Yii2's rendering process will execute this code.
    *   **Example:**  A blog allows users to customize their profile description using a templating language. An attacker injects code like `{{ system('rm -rf /') }}` (in a vulnerable template engine) which could lead to severe damage.
    *   **Impact:** Remote code execution, complete server compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:** Avoid allowing user input directly into template code. If necessary, use secure templating practices and sanitize user input rigorously. Consider using a sandboxed environment for template rendering.

