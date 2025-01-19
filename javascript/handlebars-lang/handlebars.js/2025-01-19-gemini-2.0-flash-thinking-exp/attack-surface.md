# Attack Surface Analysis for handlebars-lang/handlebars.js

## Attack Surface: [Client-Side Template Injection (CSTI)](./attack_surfaces/client-side_template_injection__csti_.md)

*   **Description:** Attackers inject malicious Handlebars expressions into data that is subsequently rendered by a Handlebars template. This can lead to arbitrary JavaScript execution in the user's browser.
    *   **How Handlebars.js Contributes:** Handlebars renders templates by evaluating expressions within `{{ }}` or `{{{ }}}`. If user-controlled data is placed within these delimiters without proper escaping, Handlebars will attempt to execute it as code.
    *   **Example:**
        *   User input: `{{constructor.constructor('alert("XSS")')()}}`
        *   Template: `<h1>Hello, {{username}}</h1>` (where `username` is the user input)
    *   **Impact:**  Full compromise of the user's browser session, including access to cookies, local storage, and the ability to perform actions on behalf of the user.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Proper Output Escaping:** Use the default `{{expression}}` which automatically HTML-escapes the output.
        *   **Avoid Unescaped Output:** Minimize the use of `{{{expression}}}` and only use it when intentionally rendering trusted HTML.
        *   **Input Validation:** Validate and sanitize user input before passing it to Handlebars templates.
        *   **Content Security Policy (CSP):** Implement a strict CSP to mitigate the impact of successful XSS attacks.

## Attack Surface: [Insecure Custom Helpers](./attack_surfaces/insecure_custom_helpers.md)

*   **Description:** Custom Handlebars helpers, being JavaScript functions, can introduce vulnerabilities if they perform insecure operations or don't properly sanitize their output.
    *   **How Handlebars.js Contributes:** Handlebars allows developers to extend its functionality with custom helpers. If these helpers are not carefully written, they can become attack vectors.
    *   **Example:**
        *   Helper: `Handlebars.registerHelper('exec', function(command) { return require('child_process').execSync(command); });`
        *   Template: `<div>Command output: {{{exec userInput}}}</div>` (where `userInput` is attacker-controlled)
    *   **Impact:**  Depending on the helper's functionality, this can lead to arbitrary code execution on the server (if used server-side), information disclosure, or client-side XSS if the helper returns unsanitized HTML.
    *   **Risk Severity:** High (can be Critical if server-side execution is possible)
    *   **Mitigation Strategies:**
        *   **Secure Helper Development:**  Thoroughly review and test custom helpers for security vulnerabilities.
        *   **Input Validation in Helpers:**  Validate and sanitize any input received by helper functions.
        *   **Principle of Least Privilege:**  Ensure helpers only have the necessary permissions and access.
        *   **Avoid Dangerous Operations:**  Avoid using helpers for operations like direct shell command execution based on user input.

## Attack Surface: [Insecure Partial Templates](./attack_surfaces/insecure_partial_templates.md)

*   **Description:** If partial templates contain vulnerabilities (like CSTI), including them in other templates can introduce those vulnerabilities.
    *   **How Handlebars.js Contributes:** Handlebars' partials feature allows for the reuse of template fragments. If these fragments are not secure, the vulnerability is propagated.
    *   **Example:**
        *   Partial `_unsafePartial.hbs`: `<div>{{{userInput}}}</div>`
        *   Main Template: `<div>{{> _unsafePartial}}</div>` (where `userInput` is attacker-controlled)
    *   **Impact:**  Similar to CSTI, leading to arbitrary JavaScript execution in the user's browser.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Secure Partial Development:** Treat partial templates with the same security considerations as full templates.
        *   **Control Partial Sources:**  Ensure partial templates come from trusted sources and are not user-controlled.
        *   **Output Escaping in Partials:**  Use proper escaping within partial templates.

