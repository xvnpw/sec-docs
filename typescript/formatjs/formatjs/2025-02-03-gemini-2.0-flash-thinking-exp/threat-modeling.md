# Threat Model Analysis for formatjs/formatjs

## Threat: [Input Injection via Format Strings](./threats/input_injection_via_format_strings.md)

**Description:** An attacker can inject malicious format directives into format strings if user-controlled data is directly embedded without proper parameterization. By crafting specific format string syntax, the attacker could potentially manipulate the output, disclose sensitive information, or in specific contexts, achieve client-side code execution. This is achieved by exploiting the format string parsing logic within `formatjs`.

**Impact:**
* Information Disclosure: Exposure of sensitive data through manipulated output.
* Client-Side Code Execution (in specific contexts):  Potentially execute arbitrary JavaScript code in the user's browser if the output is interpreted as code.
* Application Malfunction:  Unexpected application behavior due to manipulated formatting.

**Affected Component:** `formatMessage`, `intl-messageformat` module (core formatting logic).

**Risk Severity:** High

**Mitigation Strategies:**
* **Parameterize Format Strings:**  Always use placeholders and pass dynamic data as arguments to formatting functions instead of directly concatenating user input into format strings.
* **Input Validation:** Validate user input before using it in formatting, although parameterization is the primary defense.
* **Content Security Policy (CSP):** Implement a strong CSP to mitigate the impact of potential client-side injection vulnerabilities.

## Threat: [Cross-Site Scripting (XSS) via Formatted Output](./threats/cross-site_scripting__xss__via_formatted_output.md)

**Description:** If the output of `formatjs` is rendered in a web page without proper output encoding, and the formatting process incorporates user-controlled data or untrusted locale data, an attacker can inject malicious HTML or JavaScript. This can lead to XSS if the formatted output is directly inserted into the DOM without sanitization. The attacker leverages the application's trust in the formatted output to inject malicious content.

**Impact:**
* Client-Side Code Execution:  Execute arbitrary JavaScript code in the user's browser.
* Session Hijacking: Steal user session cookies and impersonate the user.
* Defacement: Modify the content of the web page.
* Data Theft: Access sensitive data accessible to the user.

**Affected Component:** Output of formatting functions (`formatMessage`, etc.) when rendered in HTML.

**Risk Severity:** High

**Mitigation Strategies:**
* **Output Encoding/Escaping:**  Always properly encode or escape the output of `formatjs` before rendering it in HTML, especially when it includes user-provided data or data from untrusted sources. Use context-aware escaping (e.g., HTML escaping for HTML context).
* **Content Security Policy (CSP):** Implement a strong CSP to further mitigate XSS risks.

