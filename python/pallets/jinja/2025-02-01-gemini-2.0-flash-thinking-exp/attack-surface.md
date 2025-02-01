# Attack Surface Analysis for pallets/jinja

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

*   **Description:** Attackers inject malicious code into Jinja templates, leading to arbitrary code execution on the server.
*   **Jinja Contribution:** Jinja's core functionality of evaluating expressions (`{{ ... }}`) and executing statements (`{% ... %}`) within templates, when combined with unsanitized user input, directly enables SSTI.
*   **Example:**
    *   **Vulnerable Code:** `render_template_string('Hello {{ user_input }}', user_input=request.args.get('name'))`
    *   **Attack Payload:** `{{ ''.__class__.__mro__[2].__subclasses__()[408]('whoami',shell=True,stdout=-1).communicate()[0].strip() }}` (Example payload to execute system commands - specific payload may vary)
    *   **Explanation:** This payload leverages Jinja's access to Python's object model to bypass intended template logic and execute arbitrary Python code, in this case, running the `whoami` command on the server.
*   **Impact:** Remote Code Execution (RCE), full server compromise, data breach, denial of service, and complete application takeover.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strict Input Sanitization:** **Never directly embed unsanitized user input into Jinja templates.**  Treat all user input as untrusted.
    *   **Parameterized Templates:**  Separate data from template logic. Pass data as variables to the template context instead of embedding user input directly within template strings.
    *   **Secure Templating Context (Jinja Environment):**  Restrict access to dangerous built-in functions and global variables within the Jinja environment. Create a sandboxed or minimal context, limiting available objects and functions.
    *   **Content Security Policy (CSP):** While not a direct SSTI mitigation, CSP can limit the damage of successful exploitation by restricting actions an attacker can take after injecting code (e.g., prevent loading external scripts or executing inline JavaScript).
    *   **Web Application Firewall (WAF):**  Deploy a WAF to detect and block common SSTI payloads and malicious patterns in user input before it reaches the application.

## Attack Surface: [Cross-Site Scripting (XSS) via Inadequate Output Escaping](./attack_surfaces/cross-site_scripting__xss__via_inadequate_output_escaping.md)

*   **Description:** Attackers inject malicious JavaScript code into web pages rendered by Jinja, which is then executed in users' browsers, leading to client-side attacks.
*   **Jinja Contribution:** While Jinja has autoescape enabled by default for HTML, developers can disable it globally, locally using `{% autoescape false %}`, or bypass it using the `| safe` filter. Incorrect or intentional disabling of autoescape, or misuse of `| safe`, directly contributes to XSS vulnerabilities.
*   **Example:**
    *   **Vulnerable Template:** `<div>{{ untrusted_user_content | safe }}</div>`
    *   **Malicious Input:** `<script>alert('XSS Vulnerability!')</script>`
    *   **Explanation:** The `| safe` filter instructs Jinja to render `untrusted_user_content` without any HTML escaping. If this content contains malicious JavaScript, it will be executed in the user's browser.
*   **Impact:** Account hijacking, session theft, defacement of websites, redirection to malicious sites, theft of sensitive user information, and other client-side attacks.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Maintain Autoescape Enabled:** Ensure Jinja's autoescape feature is enabled globally for HTML, XML, and other relevant output formats. **Avoid disabling autoescape unless absolutely necessary and with extreme caution.**
    *   **Avoid `| safe` Filter:** **Minimize and critically evaluate the use of the `| safe` filter.** Only use it when you are absolutely certain the content is safe and has been rigorously sanitized *before* being passed to the template.
    *   **Context-Aware Escaping:**  While Jinja's autoescape is HTML-focused, be mindful of other output contexts (JavaScript, CSS, URLs). Manually escape for these contexts if needed, or use Jinja extensions that provide context-aware escaping.
    *   **Content Security Policy (CSP):**  Implement a strict CSP to significantly reduce the impact of XSS attacks by controlling the sources from which the browser can load resources and restricting inline script execution.
    *   **Input Validation and Sanitization (for allowed HTML):** If you must allow users to input some HTML, use a robust and well-vetted HTML sanitization library (like Bleach in Python) to parse, clean, and remove potentially harmful HTML tags and attributes *before* rendering it with Jinja, even if using `| safe`.

