# Threat Model Analysis for github/markup

## Threat: [Cross-Site Scripting (XSS) via Markdown HTML Injection](./threats/cross-site_scripting__xss__via_markdown_html_injection.md)

*   **Description:** An attacker crafts malicious Markdown input containing raw HTML or JavaScript. A vulnerability in the underlying Markdown renderer (e.g., `commonmarker`, `goldmark`) allows this injection to bypass sanitization. The attacker's code executes in the victim's browser when the rendered HTML is displayed, potentially stealing cookies, redirecting to phishing sites, or defacing the page.
    *   **Impact:**  High - Account takeover, session hijacking, data theft, website defacement, phishing, malware distribution.
    *   **Affected Component:** Markdown rendering libraries (e.g., `commonmarker`, `goldmark`), and potentially `github/markup` itself if its sanitization is flawed. The specific vulnerable function is within the HTML parsing and sanitization routines.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Keep Libraries Updated:** *Prioritize* updating `github/markup` and the Markdown rendering library (e.g., `commonmarker`, `goldmark`) to the latest versions.
        *   **Content Security Policy (CSP):** Implement a strict CSP to restrict script sources, mitigating even successful injections.
        *   **Review Security Advisories:** Regularly monitor security advisories for `github/markup` and its dependencies.

## Threat: [Remote File Inclusion (RFI) in AsciiDoc](./threats/remote_file_inclusion__rfi__in_asciidoc.md)

*   **Description:** An attacker exploits a vulnerability in the AsciiDoc renderer (e.g., `asciidoctor`) to include and execute arbitrary files from a remote server, often using the `include` directive with a malicious URL.
    *   **Impact:** High - Remote code execution, complete server compromise.
    *   **Affected Component:** AsciiDoc rendering library (e.g., `asciidoctor`). Vulnerability in the handling of the `include` directive and URL validation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Disable `include` (if possible):** If file inclusion is not *absolutely required*, disable it in the AsciiDoc renderer's configuration.
        *   **Strictly Control Allowed Paths:** If `include` is necessary, configure the renderer to *only* allow inclusion from a specific, tightly controlled directory. Do *not* allow arbitrary URLs.
        *   **Keep Libraries Updated:** Update the AsciiDoc renderer.

## Threat: [Local File Inclusion (LFI) in AsciiDoc](./threats/local_file_inclusion__lfi__in_asciidoc.md)

*   **Description:** An attacker exploits a vulnerability in the AsciiDoc renderer to include and potentially execute arbitrary files from the *local* server's filesystem, often using the `include` directive with path traversal (e.g., `../../etc/passwd`).
    *   **Impact:** High - Sensitive data disclosure, potential code execution.
    *   **Affected Component:** AsciiDoc rendering library (e.g., `asciidoctor`). Vulnerability in `include` directive handling and path sanitization.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Disable `include` (if possible):** Same as RFI.
        *   **Strictly Control Allowed Paths:** Same as RFI, with emphasis on preventing path traversal.
        *   **Keep Libraries Updated:** Same as RFI.
        * **Run with Least Privilege:** Ensure the application runs with minimal privileges.

## Threat: [XSS via Custom AsciiDoc Macros/Attributes](./threats/xss_via_custom_asciidoc_macrosattributes.md)

*   **Description:** If custom AsciiDoc macros/attributes are used, an attacker crafts input exploiting vulnerabilities in their *implementation*. If the macro/attribute doesn't sanitize user input before generating HTML, it leads to XSS.
    *   **Impact:** High - Similar to Markdown XSS.
    *   **Affected Component:** Custom AsciiDoc macros/attributes implemented within the application.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Thoroughly Audit Custom Code:** Carefully review custom macro/attribute code for security vulnerabilities, focusing on input handling.
        *   **Use a Templating Engine with Auto-Escaping:** If possible, use a secure templating engine that automatically escapes HTML.
        *   **Input Validation and Sanitization:** Within the custom code, perform strict input validation and sanitization *before* generating HTML.
        *   **CSP:** Use a strong CSP.

## Threat: [XSS via reStructuredText `raw` Directive](./threats/xss_via_restructuredtext__raw__directive.md)

*   **Description:** An attacker uses the `raw` directive in reStructuredText to embed raw HTML/JavaScript. If `github/markup` or the RST renderer (e.g., `docutils`) doesn't disable/sanitize `raw`, this leads to XSS.
    *   **Impact:** High - Similar to Markdown XSS.
    *   **Affected Component:** reStructuredText rendering library (e.g., `docutils`), and potentially `github/markup`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Disable `raw` Directive:** Ensure the `raw` directive is *completely disabled* in the RST renderer's configuration. Verify that `github/markup` does this by default.
        *   **Keep Libraries Updated:** Update the RST renderer.
        *   **CSP:** Use a strong CSP.

## Threat: [File Inclusion via reStructuredText `include` Directive](./threats/file_inclusion_via_restructuredtext__include__directive.md)

*   **Description:** Similar to AsciiDoc, an attacker exploits the `include` directive in reStructuredText to include arbitrary files (local or potentially remote).
    *   **Impact:** High - Similar to AsciiDoc LFI/RFI.
    *   **Affected Component:** reStructuredText rendering library (e.g., `docutils`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Disable `include` (if possible):** Disable if not essential.
        *   **Strictly Control Allowed Paths:** If required, allow inclusion *only* from a trusted directory. Prevent path traversal.
        *   **Keep Libraries Updated:** Update the RST renderer.

