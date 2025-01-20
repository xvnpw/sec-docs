# Attack Surface Analysis for bcosca/fatfree

## Attack Surface: [Route Parameter Injection](./attack_surfaces/route_parameter_injection.md)

*   **Description:**  Malicious data is injected into URL route parameters, leading to unintended actions or information disclosure.
    *   **How Fat-Free Contributes:** FFF's flexible routing system allows defining routes with parameters (e.g., `/user/@id`). If developers don't explicitly sanitize or validate these parameters within their route handlers, the framework passes the raw input, making the application vulnerable.
    *   **Example:** A route like `/file/@filename` could be accessed with `/file/../../../../etc/passwd`, potentially exposing sensitive system files if the `@filename` parameter is used directly in file operations without validation.
    *   **Impact:** Path traversal, SQL injection (if the parameter is used in database queries), command injection (if used in system commands), information disclosure.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement robust input validation and sanitization for all route parameters within the route handler.
        *   Use whitelisting to only allow expected characters or patterns in parameters.
        *   Avoid directly using route parameters in file system operations or database queries without proper escaping or parameterized queries.
        *   Consider using FFF's input filtering capabilities if applicable.

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

*   **Description:**  Malicious code is injected into template directives, allowing attackers to execute arbitrary code on the server.
    *   **How Fat-Free Contributes:** If user-controlled data is directly embedded into FFF templates without proper escaping, the templating engine will interpret and execute the injected code.
    *   **Example:** A template like `<h1>{{ @user_input }}</h1>` where `@user_input` comes directly from a request, could be exploited by injecting `{{ system('whoami') }}` to execute a system command.
    *   **Impact:** Remote code execution, data breaches, server compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always escape user-controlled data** when rendering it in templates using FFF's escaping mechanisms. Be mindful of the output context (HTML, JavaScript, etc.).
        *   Avoid allowing users to directly control template content or directives.
        *   Consider using a templating engine with auto-escaping enabled by default (though FFF's built-in engine requires explicit escaping).

## Attack Surface: [Cross-Site Scripting (XSS) via Template Output](./attack_surfaces/cross-site_scripting__xss__via_template_output.md)

*   **Description:**  Malicious scripts are injected into web pages, allowing attackers to execute code in the context of other users' browsers.
    *   **How Fat-Free Contributes:** If developers fail to properly escape user-provided data when rendering it in FFF templates, attackers can inject JavaScript code that will be executed by the victim's browser.
    *   **Example:** A template displaying a user's comment like `<p>{{ @comment }}</p>` is vulnerable if `@comment` contains `<script>alert('XSS')</script>` and is not escaped.
    *   **Impact:** Session hijacking, cookie theft, defacement, redirection to malicious sites.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Always escape user-controlled data** when rendering it in templates using FFF's escaping mechanisms.
        *   Use context-aware escaping (e.g., escape differently for HTML, JavaScript, URLs).
        *   Implement a Content Security Policy (CSP) to restrict the sources from which the browser can load resources.

## Attack Surface: [Insecure Handling of Request Data](./attack_surfaces/insecure_handling_of_request_data.md)

*   **Description:**  Failure to properly sanitize and validate data received from HTTP requests (GET, POST, etc.).
    *   **How Fat-Free Contributes:** FFF provides access to raw request data through variables like `$_GET`, `$_POST`, and the `F3::get()` method. It's the developer's responsibility to sanitize and validate this data. If this is not done, the application is vulnerable to various injection attacks.
    *   **Example:**  A form field intended for a user's name could be used to inject SQL code if the data is directly used in a database query without sanitization.
    *   **Impact:** SQL injection, command injection, XSS, data manipulation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Always sanitize and validate all user input** before processing it.
        *   Use whitelisting to only allow expected characters or patterns.
        *   Utilize FFF's input filtering capabilities where appropriate.
        *   For database interactions, use parameterized queries or prepared statements to prevent SQL injection.

