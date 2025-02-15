# Attack Surface Analysis for pallets/jinja

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

*   **Description:** Attackers inject malicious Jinja2 syntax into the template, leading to code execution on the server. This is the most severe vulnerability associated with templating engines.
*   **How Jinja2 Contributes:** Jinja2's powerful features, including access to Python built-ins and potentially imported modules, provide the attacker with a wide range of capabilities if injection is successful. The template engine itself is the *direct* attack vector.
*   **Example:**
    *   User input field: `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`
    *   This attempts to access the `os` module and execute the `id` command, revealing server user information.
*   **Impact:**
    *   Remote Code Execution (RCE)
    *   Information Disclosure (sensitive data, configuration, source code)
    *   Denial of Service (DoS)
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Validate all user input against a whitelist of allowed characters/patterns. Reject anything that doesn't conform.
    *   **Context-Aware Escaping (Autoescaping):** Ensure autoescaping is enabled (default in many frameworks). Understand its limitations and contexts (HTML, JS, etc.).
    *   **Sandboxing (`SandboxedEnvironment`):** Use Jinja2's `SandboxedEnvironment` to restrict available functions and attributes within the template. This significantly limits the attacker's power.
    *   **Least Privilege:** Run the application with minimal necessary privileges.
    *   **Avoid `|safe`:** Minimize the use of the `|safe` filter. Only use it when absolutely necessary and you are certain the input is safe.
    *   **Avoid Exposing Sensitive Objects:** Do not directly expose objects like `config` in templates.
    *   **Regular Security Audits & Penetration Testing:** Specifically test for template injection.

## Attack Surface: [Cross-Site Scripting (XSS) - *Through Direct Jinja2 Misuse*](./attack_surfaces/cross-site_scripting__xss__-_through_direct_jinja2_misuse.md)

*   **Description:** While Jinja2's autoescaping aims to prevent XSS, *direct* misuse, such as disabling autoescaping or using the wrong escaping context *within the template itself*, can lead to vulnerabilities. This distinguishes it from general XSS, focusing on the Jinja2-specific aspect.
*   **How Jinja2 Contributes:** The vulnerability arises from *directly* misusing Jinja2's escaping features *within the template*. Jinja2's output mechanism, when improperly configured *by the developer within the template*, is the direct cause.
*   **Example:**
    *   `{{ user_input | safe }}` - Directly disabling autoescaping for user input.
    *   Using `{{ ... }}` in a JavaScript context without proper JavaScript escaping (even if HTML escaping is on). This is a *direct* misuse of Jinja2's output in the wrong context.
*   **Impact:**
    *   Execution of arbitrary JavaScript in the victim's browser.
    *   Session hijacking.
    *   Phishing attacks.
    *   Website defacement.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Rely on Autoescaping:** Use Jinja2's autoescaping as the primary defense. Understand the different escaping contexts (HTML, JS, CSS, URL).
    *   **Avoid `|safe` (Crucially):** Minimize its use. Only use it when absolutely necessary and you are certain the input is safe.
    *   **Context-Aware Output:** Ensure that the output of Jinja2 expressions is used in the correct context (e.g., HTML, JavaScript, CSS) and that the appropriate escaping is applied *automatically* by Jinja2.
    *   **Content Security Policy (CSP):** Implement a strong CSP as a defense-in-depth measure (although this is a broader mitigation, not solely Jinja2-specific).

