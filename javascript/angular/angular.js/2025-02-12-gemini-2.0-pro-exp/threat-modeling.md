# Threat Model Analysis for angular/angular.js

## Threat: [Client-Side Template Injection (CSTI) / Sandbox Escape](./threats/client-side_template_injection__csti___sandbox_escape.md)

*   **Threat:** Client-Side Template Injection (CSTI) leading to AngularJS Sandbox Escape.
*   **Description:** An attacker injects malicious AngularJS expressions into the application, typically through user-supplied input that is rendered within an AngularJS template. The attacker crafts the input to bypass the AngularJS expression sandbox (which was intended to limit the scope of expressions) and execute arbitrary JavaScript code in the context of the victim's browser. This often involves using known bypass techniques that exploit weaknesses in the sandbox's implementation. For example, an attacker might inject something like: `{{constructor.constructor('alert("XSS")')()}}`.
*   **Impact:** Complete client-side application compromise. The attacker can:
    *   Steal sensitive data (cookies, local storage, session tokens).
    *   Modify the application's appearance and behavior (defacement).
    *   Redirect the user to malicious websites.
    *   Impersonate the user and perform actions on their behalf within the application.
    *   Exfiltrate data entered by the user.
    *   Potentially launch further attacks, such as cross-site scripting (XSS) against other users.
*   **Affected AngularJS Component:**
    *   Template engine (primarily double-curly brace interpolation `{{ }}` and directives like `ng-bind-html` when used with untrusted input).
    *   `$parse` service (used internally for expression evaluation).
    *   The AngularJS sandbox itself (which is flawed and has numerous known bypasses).
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Primary:** Migrate to a modern, supported framework (Angular 2+, React, Vue.js, etc.). AngularJS 1.x is no longer supported.
    *   Avoid rendering user-supplied input directly within templates.
    *   If rendering user input is unavoidable, use strict contextual escaping.
    *   Prefer `ng-bind` over `{{ }}` for simple data binding (though this is *not* a complete solution).
    *   Implement a strong Content Security Policy (CSP) to limit the execution of unauthorized scripts. Focus on restricting `script-src` and `object-src`, but be aware that AngularJS's use of `eval` and `Function` makes a truly restrictive CSP difficult.
    *   Avoid `ng-bind-html` with untrusted input. If absolutely necessary, use a *robust and actively maintained* HTML sanitizer *specifically designed for AngularJS*. The built-in `$sanitize` is insufficient.
    *   Regularly update any third-party AngularJS directives.
    *   Consider disabling the AngularJS sandbox (high-risk, high-reward; requires extreme caution).

## Threat: [DOM-Based XSS via AngularJS Directives](./threats/dom-based_xss_via_angularjs_directives.md)

*   **Threat:** DOM-Based Cross-Site Scripting (XSS) through AngularJS Directives.
*   **Description:** An attacker exploits vulnerabilities in how AngularJS directives handle user input and manipulate the Document Object Model (DOM). This doesn't necessarily involve escaping the AngularJS sandbox, but rather leverages insecure DOM manipulation within a directive. For example, a custom directive might directly insert user-provided HTML into the DOM without proper sanitization, allowing the attacker to inject malicious `<script>` tags or event handlers.
*   **Impact:** Execution of arbitrary JavaScript in the context of the victim's browser. Similar to CSTI, but the scope might be more limited depending on the specific directive and vulnerability. The attacker can:
    *   Steal cookies and session data.
    *   Modify the page content.
    *   Redirect the user.
    *   Perform actions on behalf of the user.
*   **Affected AngularJS Component:**
    *   Custom AngularJS directives that directly manipulate the DOM using user-supplied input.
    *   Built-in directives if misused (e.g., `ng-include` with a dynamically generated URL from user input).
    *   Potentially, third-party directives.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   Avoid creating custom directives that directly manipulate the DOM with untrusted input.
    *   If custom directives are necessary, *thoroughly* sanitize and escape all user input *before* inserting it into the DOM. Use appropriate DOM APIs (e.g., `createElement`, `setAttribute`, `textContent`) instead of string concatenation.
    *   Use a robust HTML sanitizer if you *must* insert HTML from user input.
    *   Audit any third-party directives for potential DOM-based XSS vulnerabilities.

