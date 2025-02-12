# Attack Surface Analysis for handlebars-lang/handlebars.js

## Attack Surface: [Template Injection (Client-Side & Server-Side)](./attack_surfaces/template_injection__client-side_&_server-side_.md)

*   **Description:** Attackers inject malicious Handlebars expressions into the *template itself*, not just the data, enabling code execution.
*   **How Handlebars.js Contributes:** Handlebars.js is the templating engine; if misused by allowing user input to *define* the template, it becomes the direct injection vector.
*   **Example:**
    *   **Vulnerable Code (Server-Side):**
        ```javascript
        const userTemplate = req.query.template; // Untrusted input!
        const compiled = Handlebars.compile(userTemplate);
        const html = compiled(data);
        res.send(html);
        ```
    *   **Attacker Input:** `{{#with (lookup this 'constructor')}}{{#with (lookup this 'constructor')}}{{#with (lookup this 'require')}} {{this.mainModule.require('child_process').execSync('whoami')}} {{/with}}{{/with}}{{/with}}` (Attempts to execute `whoami` on the server).
    *   **Vulnerable Code (Client-Side):**
        ```javascript
        const userTemplate = document.getElementById('templateInput').value; // Untrusted input!
        const compiled = Handlebars.compile(userTemplate);
        const html = compiled(data);
        document.getElementById('output').innerHTML = html;
        ```
    *   **Attacker Input:** `{{constructor.constructor('alert("XSS")')()}}` (Executes arbitrary JavaScript on the client).
*   **Impact:**
    *   **Client-Side:** Cross-Site Scripting (XSS), leading to session hijacking, data theft, defacement.
    *   **Server-Side:** Remote Code Execution (RCE), potentially leading to complete server compromise.
*   **Risk Severity:**
    *   **Client-Side:** High
    *   **Server-Side:** Critical
*   **Mitigation Strategies:**
    *   **Never** construct templates from user input. Templates should be static and treated as code.
    *   Use precompiled templates whenever possible.
    *   If dynamic template selection is absolutely necessary, use a whitelist of allowed template names/paths. Load templates from a trusted source. *Never* incorporate user input into the template string.
    *   Sanitize any data used in template *selection* (e.g., filenames) to prevent path traversal.

## Attack Surface: [Unsafe Helper Usage (Leading to RCE or XSS)](./attack_surfaces/unsafe_helper_usage__leading_to_rce_or_xss_.md)

*   **Description:** Custom or built-in Handlebars helpers are implemented or used in a way that allows for code execution or unescaped output.  This focuses on the *most severe* helper-related issues.
*   **How Handlebars.js Contributes:** Handlebars.js provides the helper mechanism, and the vulnerability arises from the *code within the helper* or *how the helper's output is handled*.
*   **Example:**
    *   **Vulnerable Custom Helper (RCE):**
        ```javascript
        Handlebars.registerHelper('executeCommand', function(command) {
          // EXTREMELY DANGEROUS - DO NOT USE
          return require('child_process').execSync(command).toString();
        });
        ```
        Template: `{{{executeCommand userInput}}}` (where `userInput` is untrusted).
    *   **Vulnerable Custom Helper (XSS):**
        ```javascript
        Handlebars.registerHelper('unsafeOutput', function(input) {
          return input; // No escaping!
        });
        ```
        Template: `{{{unsafeOutput userData}}}` (where `userData` is untrusted).
    * **Vulnerable built-in helper usage (XSS):**
        ```html
        {{{userData}}}
        ```
        Where `userData` contains `<script>alert('xss')</script>`.
*   **Impact:**
    *   Remote Code Execution (RCE) if helpers execute arbitrary code.
    *   Cross-Site Scripting (XSS) if helpers output unescaped user data.
*   **Risk Severity:** High to Critical (depending on the helper's functionality).
*   **Mitigation Strategies:**
    *   **Never use `eval` or `Function`** within helpers.
    *   **Strict Input Validation and Sanitization:** All custom helpers *must* rigorously validate and sanitize their inputs *before* performing any operations.
    *   **Avoid Unsafe Operations:** Do not allow helpers to execute shell commands, access the file system, or perform other potentially dangerous actions without extreme caution and strict input validation.
    *   **Use Double Braces:** Always use double-braced expressions (`{{ ... }}`) for outputting data unless raw HTML output is *absolutely required* and the data source is *completely trusted*.
    *   **`SafeString` with Extreme Caution:** Only use `Handlebars.SafeString` or triple-braced expressions (`{{{ ... }}}`) when you *absolutely* need to output raw HTML, and *only* with data from a trusted source.  Never use them with user-supplied data.
    *   **Regularly audit all custom helpers.

## Attack Surface: [Precompiled Template Issues (Supply Chain - Compromised Source)](./attack_surfaces/precompiled_template_issues__supply_chain_-_compromised_source_.md)

*   **Description:** The *source files* used to generate precompiled Handlebars templates are compromised, leading to malicious code being injected into the precompiled templates. This is a *direct* threat because it affects the Handlebars templates themselves.
*   **How Handlebars.js Contributes:** Handlebars.js's precompilation feature is used, but the vulnerability lies in the *compromise of the input to that feature*.
*   **Example:** An attacker gains access to the developer's machine or the build server and modifies the `.hbs` files *before* they are precompiled. The resulting precompiled JavaScript file will then contain the attacker's malicious code.
*   **Impact:** Remote Code Execution (RCE) on the server or Cross-Site Scripting (XSS) on the client, depending on where the precompiled template is used. The attacker's code runs whenever the compromised template is rendered.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Secure Build Process:** Protect the template source files (.hbs) and the build environment with the *same level of security as any other critical code*. This includes:
        *   Strict access controls.
        *   Code signing.
        *   Regular security audits and vulnerability scanning.
        *   Secure development practices (e.g., principle of least privilege).
    *  **Treat precompiled templates as trusted code.**

