# Threat Model Analysis for erusev/parsedown

## Threat: [Cross-Site Scripting (XSS) via Malicious Markdown](./threats/cross-site_scripting__xss__via_malicious_markdown.md)

*   **Description:** An attacker crafts malicious Markdown input containing JavaScript code. If Parsedown's sanitization fails (due to a bug or, less likely with `setSafeMode`, a bypass), the injected script executes in the browser of users viewing the rendered output. The attacker leverages Markdown features (links, images, etc.) and potentially HTML entities or other tricks to evade sanitization.
*   **Impact:**
    *   Theft of user cookies and session tokens (account takeover).
    *   Webpage content modification (defacement).
    *   Redirection to phishing sites.
    *   Execution of arbitrary actions on behalf of the user.
    *   Keylogging and sensitive data capture.
*   **Affected Parsedown Component:**
    *   Core parsing engine (`Parsedown::text()` and related internal functions).
    *   Specifically, code handling HTML entities, escaping, and HTML tag filtering.
    *   Custom `block` or `inline` handlers (if any).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Update Parsedown:** *Always* use the latest version. This is paramount.
    *   **Enable `setSafeMode(true)`:** This is *mandatory* and disables raw HTML, enforcing stricter sanitization.
    *   **Output Encoding:** Apply context-appropriate output encoding *after* Parsedown (e.g., HTML entity encoding).
    *   **Content Security Policy (CSP):** Implement a strong CSP to limit the impact of successful XSS.
    *   **Regular Security Audits:** Include Parsedown in penetration testing, focusing on XSS.

## Threat: [Regular Expression Denial of Service (ReDoS)](./threats/regular_expression_denial_of_service__redos_.md)

*   **Description:** An attacker provides crafted Markdown input designed to exploit vulnerabilities in Parsedown's regular expressions. This input causes excessive CPU consumption, leading to a denial of service. The attacker uses nested quantifiers or complex regex patterns.
*   **Impact:**
    *   Application unresponsiveness, denying service to legitimate users.
    *   Potential server crashes due to resource exhaustion.
*   **Affected Parsedown Component:**
    *   Internal functions using regular expressions for Markdown parsing (throughout the codebase, especially in `block` and `inline` logic).
    *   Custom `block` or `inline` handlers using regular expressions (if any).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Update Parsedown:** Newer versions often contain ReDoS fixes.
    *   **Input Length Limits:** Strictly limit the maximum length of Markdown input.
    *   **Timeouts:** Implement timeouts for the Parsedown parsing process.
    *   **Web Application Firewall (WAF):** Some WAFs can detect and block ReDoS attempts.
    *   **Monitoring:** Monitor CPU usage and response times.

