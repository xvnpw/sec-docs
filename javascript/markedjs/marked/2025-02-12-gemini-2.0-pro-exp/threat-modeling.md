# Threat Model Analysis for markedjs/marked

## Threat: [Cross-Site Scripting (XSS) via Malicious Markdown](./threats/cross-site_scripting__xss__via_malicious_markdown.md)

*   **Description:** An attacker crafts malicious Markdown input containing JavaScript code.  The goal is to have this code executed in the browser of another user viewing the rendered Markdown.  The attacker leverages `marked`'s processing of the input to inject the malicious script.  This relies on either a bypass of `marked`'s sanitization (even when enabled) or a vulnerability in a custom renderer/extension.
*   **Impact:**
    *   **Session Hijacking:** Stealing user session cookies.
    *   **Data Theft:** Accessing and stealing sensitive data.
    *   **Website Defacement:** Modifying page content.
    *   **Phishing:** Redirecting users to fake websites.
    *   **Malware Distribution:** Distributing malware.
*   **Affected Component:**
    *   `marked.parse()` (and aliases) - The core Markdown-to-HTML conversion function.
    *   `Lexer` and `Parser` modules - Internal components handling tokenization and parsing; potential bypasses exist here.
    *   Custom renderers (if used and improperly implemented) - A major source of XSS if not carefully sanitized.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **`sanitize: true` (Mandatory):**  Ensure this option is *always* enabled in your `marked` configuration.
    *   **DOMPurify (Post-Processing - Essential):**  Use DOMPurify *after* `marked` to sanitize the HTML. This is a crucial second layer of defense.
    *   **Content Security Policy (CSP):** Implement a strict CSP, focusing on the `script-src` directive.
    *   **Input Validation (Pre-Processing - Supplementary):** Basic validation *before* `marked` to reject obvious patterns (e.g., `<script>`). Not a primary defense.
    *   **Keep `marked` Updated:**  Always use the latest version to benefit from security patches.
    *   **Monitor for Vulnerabilities:**  Stay informed about known `marked` vulnerabilities.

## Threat: [Regular Expression Denial of Service (ReDoS)](./threats/regular_expression_denial_of_service__redos_.md)

*   **Description:** An attacker crafts a specific Markdown input designed to exploit vulnerabilities in `marked`'s regular expressions.  The attacker's aim is to cause excessive CPU consumption on the server, leading to a denial of service. This directly targets `marked`'s internal parsing logic.
*   **Impact:**
    *   **Service Unavailability:** The application becomes unresponsive.
    *   **Resource Exhaustion:** Server CPU and memory are consumed.
    *   **Potential Financial Costs:** Increased costs on cloud platforms.
*   **Affected Component:**
    *   `Lexer` module - This module relies heavily on regular expressions for tokenization. Vulnerable regexes within the `Lexer` are the direct target.
    *    Custom extensions (if they introduce vulnerable regexes)
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Keep `marked` Updated:**  Update to the latest version to address known ReDoS vulnerabilities.
    *   **Input Length Limits:**  Enforce reasonable limits on the length of Markdown input.
    *   **Timeout Mechanisms:**  Implement timeouts for Markdown processing (e.g., 1-2 seconds). Terminate processing if it exceeds the limit.
    *   **Web Application Firewall (WAF):**  Use a WAF that can detect and block ReDoS attacks.
    *   **Monitor CPU Usage:**  Monitor server CPU usage and set up alerts.
    *   **Audit Custom Extensions:** Carefully audit any custom extensions that use regular expressions.

