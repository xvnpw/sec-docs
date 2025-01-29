# Threat Model Analysis for ampproject/amphtml

## Threat: [XSS in AMP Components](./threats/xss_in_amp_components.md)

**Threat:** Cross-Site Scripting (XSS) in AMP Components
*   **Description:** Attackers exploit vulnerabilities within the code of AMP components (like `amp-carousel`, `amp-list`, or custom AMP components). By providing malicious data or exploiting flaws in component rendering, they can inject and execute arbitrary JavaScript code within a user's browser when viewing an AMP page. This malicious script runs in the context of the AMP page's origin.
*   **Impact:**
    *   **High:** Account takeover by stealing session cookies or credentials, redirection to external malicious websites, theft of sensitive user data displayed on the AMP page, defacement of the AMP page content, and potential for further attacks leveraging the compromised user session.
*   **Affected AMPHTML Component:** Specific AMP components (e.g., `amp-carousel`, `amp-list`, `amp-bind`, custom components), and potentially the core AMP JS library if the vulnerability lies within shared utility functions.
*   **Risk Severity:** **High** to **Critical** (depending on the component's functionality and exploitability)
*   **Mitigation Strategies:**
    *   **Prioritize regular updates of the AMP JS library:** Ensure the application always uses the latest stable version of the AMP JS library to benefit from the most recent security patches and bug fixes for AMP components.
    *   **Implement strict input validation and sanitization within custom AMP components:** If developing custom AMP components, rigorously validate and sanitize all data inputs and outputs to prevent injection vulnerabilities. Follow secure coding practices specific to web component development.
    *   **Utilize Content Security Policy (CSP):** Implement a robust CSP header to limit the sources from which scripts can be loaded and restrict the actions that inline scripts can perform, reducing the impact of successful XSS exploitation.
    *   **Conduct thorough security audits of custom AMP components:**  Perform regular security audits and penetration testing specifically targeting custom AMP components to identify and remediate potential XSS vulnerabilities before deployment.

## Threat: [AMP Validation Bypass leading to Malicious HTML/JS Injection](./threats/amp_validation_bypass_leading_to_malicious_htmljs_injection.md)

**Threat:** AMP Validation Bypass leading to Malicious HTML/JS Injection
*   **Description:** Attackers discover and exploit weaknesses or bugs in the AMP validator itself. This allows them to craft AMP pages that deceptively pass validation checks, despite containing HTML or JavaScript code that violates AMP's security policies and should be blocked.  Successful bypass allows injection of arbitrary, non-AMP compliant code into pages served as AMP.
*   **Impact:**
    *   **Critical:** Complete circumvention of AMP's security guarantees, enabling injection of arbitrary JavaScript and HTML. This can lead to all forms of XSS attacks, including account takeover, data theft, malware distribution, and bypassing other client-side security measures enforced by AMP.
*   **Affected AMPHTML Component:** AMP Validator (both client-side browser validator and server-side validator tools), core AMP validation logic within the AMP JS library.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Always use the official AMP validator:** Rely exclusively on the official AMP validator provided by the AMP Project for validating AMP pages. Avoid using unofficial or outdated validators.
    *   **Stay informed about AMP validator updates and security advisories:** Monitor the AMP Project's security channels and release notes for updates to the validator and any reported vulnerabilities. Promptly update validation tools and processes when new versions are released.
    *   **Implement server-side AMP validation as a critical security control:**  Perform AMP validation on the server-side before serving AMP pages, especially when serving from caches or high-traffic environments. This adds a crucial layer of defense against validator bypass attempts.
    *   **Report suspected validator bypasses to the AMP Project:** If you identify a potential bypass of the AMP validator, immediately report it to the AMP Project security team to contribute to the overall security of the AMP ecosystem.

