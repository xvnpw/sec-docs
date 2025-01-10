# Threat Model Analysis for formatjs/formatjs

## Threat: [Client-Side Message Formatting Injection (XSS)](./threats/client-side_message_formatting_injection__xss_.md)

**Description:** An attacker injects malicious code (e.g., JavaScript) into user-controlled data that is subsequently used within a `formatjs` message string. When this formatted message is rendered in a web browser, the injected script executes. The attacker might steal cookies, redirect the user to a malicious site, deface the application, or perform actions on behalf of the user.

**Impact:** Account compromise, data theft, malware distribution, website defacement, denial of service.

**Affected Component:** `formatjs` message formatting functions (e.g., `format`, `formatMessage`), specifically when processing user-provided data within message placeholders.

**Risk Severity:** High

**Mitigation Strategies:**
* Sanitize and encode user-provided data before using it in `formatjs` messages. Use HTML escaping for data displayed in the browser.
* Avoid directly embedding user input into message strings. Use placeholders and pass data as arguments.
* Implement Content Security Policy (CSP) to restrict the sources from which the browser can load resources, mitigating the impact of injected scripts.
* Regularly review and update `formatjs` to patch potential vulnerabilities.

