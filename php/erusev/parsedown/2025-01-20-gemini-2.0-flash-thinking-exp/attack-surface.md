# Attack Surface Analysis for erusev/parsedown

## Attack Surface: [Cross-Site Scripting (XSS) via Malicious Markdown](./attack_surfaces/cross-site_scripting__xss__via_malicious_markdown.md)

* **Description:** An attacker injects malicious scripts into the application by crafting specific Markdown input that, when processed by Parsedown, results in the generation of HTML containing the malicious script. This script then executes in the victim's browser.
    * **How Parsedown Contributes:** Parsedown, by default, converts certain Markdown syntax into HTML. If not configured to sanitize or escape potentially harmful HTML tags and attributes, it can inadvertently generate malicious code.
    * **Example:**  A user submits the following Markdown: `[Click me](javascript:alert('XSS'))` or `<img src="x" onerror="alert('XSS')">`. Parsedown might render this as `<a href="javascript:alert('XSS')">Click me</a>` or `<img src="x" onerror="alert('XSS')">`, leading to script execution.
    * **Impact:**  Full compromise of the user's session, including stealing cookies, redirecting to malicious sites, or performing actions on behalf of the user.
    * **Risk Severity:** **Critical**
    * **Mitigation Strategies:**
        * **Developers:**
            * **Configure Parsedown's `setBreaksEnabled` and `setSafeMode` options appropriately.**  `setSafeMode(true)` is a crucial step to disable potentially dangerous HTML tags.
            * **Implement output encoding/escaping on the application side.** Even with `setSafeMode`, additional encoding can provide a defense-in-depth.

## Attack Surface: [Bypass of Content Security Policy (CSP) through Parsedown's HTML Generation](./attack_surfaces/bypass_of_content_security_policy__csp__through_parsedown's_html_generation.md)

* **Description:** Even with a strong CSP in place, vulnerabilities in Parsedown's HTML generation could allow attackers to bypass these policies by injecting HTML that circumvents the CSP restrictions.
    * **How Parsedown Contributes:** If Parsedown allows the generation of HTML constructs that are not explicitly blocked by the CSP, attackers can leverage these to inject malicious content. For example, allowing inline event handlers even if `unsafe-inline` is blocked for script sources.
    * **Example:**  Markdown like `<details open ontoggle=alert('CSP Bypass')>` might be rendered in a way that triggers script execution despite CSP rules against inline scripts.
    * **Impact:**  Circumvention of security controls designed to prevent XSS, leading to potential user compromise.
    * **Risk Severity:** **High**
    * **Mitigation Strategies:**
        * **Developers:**
            * **Strictly configure Parsedown to disallow HTML tags and attributes that can be used for CSP bypasses.**  Focus on removing event handlers and potentially problematic tags like `<details>`, `<object>`, `<embed>`, and `<iframe>` if not absolutely necessary.
            * **Thoroughly test the application's CSP in conjunction with Parsedown's output to ensure no bypasses exist.**

