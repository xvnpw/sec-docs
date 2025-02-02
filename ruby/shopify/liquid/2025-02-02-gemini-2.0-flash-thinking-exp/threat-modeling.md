# Threat Model Analysis for shopify/liquid

## Threat: [Server-Side Template Injection (SSTI)](./threats/server-side_template_injection__ssti_.md)

**Description:** An attacker injects malicious Liquid code into template input or data processed by Liquid. This code, when rendered by the Liquid engine, executes on the server. Attackers might achieve this by exploiting input fields, URL parameters, or database entries that are directly used in Liquid templates without proper sanitization.

**Impact:**  Full server compromise, arbitrary code execution, data breaches, unauthorized access to sensitive data, denial of service, website defacement.

**Affected Liquid Component:**  Liquid Engine (core parsing and rendering process), Input Handling (data passed to templates).

**Risk Severity:** Critical

**Mitigation Strategies:**

*   Input Sanitization:  Strictly sanitize and validate all user-provided data before using it in Liquid templates.
*   Template Source Control:  Ensure templates are loaded from trusted sources and are not modifiable by untrusted users.
*   Regular Updates: Keep the Liquid library updated to the latest version to patch known vulnerabilities.
*   Content Security Policy (CSP): Implement a strong CSP to limit the capabilities of rendered pages, reducing the impact of successful SSTI.
*   Sandboxing (if feasible): Explore sandboxing options for Liquid execution, although Liquid is designed with security in mind.
*   Custom Filter/Tag Audits:  Thoroughly audit custom Liquid filters and tags for potential security flaws that could bypass built-in protections.

## Threat: [Information Disclosure via Template Context](./threats/information_disclosure_via_template_context.md)

**Description:**  Liquid templates unintentionally expose sensitive information present in the application's context or backend systems. This happens when developers inadvertently pass sensitive variables or objects to the Liquid rendering context, making them accessible within templates. Attackers can then craft templates to extract and display this information.

**Impact:** Exposure of confidential data, API keys, internal configurations, user data (PII), intellectual property, business secrets.

**Affected Liquid Component:**  Liquid Context (data passed to templates), Variable Resolution (how Liquid accesses data).

**Risk Severity:** High

**Mitigation Strategies:**

*   Minimize Context Data:  Only pass the absolutely necessary data to the Liquid template context. Avoid exposing entire objects or large datasets.
*   Context Auditing:  Regularly audit the data being passed to Liquid templates to identify and remove any unintentionally exposed sensitive information.
*   Explicit Data Whitelisting:  Explicitly define and whitelist the data that is allowed to be accessed within templates, instead of blacklisting.
*   Secure Data Handling:  Implement proper access control and data masking mechanisms in the application code before data reaches the templating engine.

## Threat: [Client-Side Cross-Site Scripting (XSS) via `raw` Filter Misuse](./threats/client-side_cross-site_scripting__xss__via__raw__filter_misuse.md)

**Description:** Developers incorrectly use the `raw` Liquid filter or create custom filters that bypass Liquid's automatic output escaping. This allows attackers to inject malicious JavaScript code into the rendered HTML output. If user-controlled data is passed to `raw` without proper sanitization, XSS vulnerabilities can be introduced.

**Impact:** Client-side code execution in users' browsers, session hijacking, cookie theft, website defacement, redirection to malicious sites, information theft from users, phishing attacks.

**Affected Liquid Component:**  `raw` Filter, Custom Filters, Output Escaping Mechanism.

**Risk Severity:** High

**Mitigation Strategies:**

*   Avoid `raw` Filter:  Avoid using the `raw` filter unless absolutely necessary and with extreme caution.
*   Strict Sanitization with `raw`: If `raw` is unavoidable, rigorously sanitize all data before passing it to the `raw` filter using a robust HTML sanitizer library.
*   Secure Custom Filters:  Carefully review and audit custom Liquid filters to ensure they properly escape output and do not introduce XSS vulnerabilities. Implement output escaping within custom filters.
*   Content Security Policy (CSP): Implement a strong CSP to further mitigate the impact of potential XSS vulnerabilities by restricting the sources of executable code and other resources.
*   Regular Security Audits: Conduct regular security audits and penetration testing to identify potential XSS vulnerabilities.

