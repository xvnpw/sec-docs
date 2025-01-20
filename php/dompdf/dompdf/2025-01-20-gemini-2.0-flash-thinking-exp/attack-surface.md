# Attack Surface Analysis for dompdf/dompdf

## Attack Surface: [Cross-Site Scripting (XSS) via HTML Injection](./attack_surfaces/cross-site_scripting__xss__via_html_injection.md)

*   **Description:** Cross-Site Scripting (XSS) via HTML Injection
    *   **How Dompdf Contributes to the Attack Surface:** Dompdf parses and renders HTML. If the application allows user-controlled HTML to be passed to Dompdf without proper sanitization, malicious JavaScript embedded within the HTML can be rendered into the PDF. When the PDF is viewed in a vulnerable PDF reader, this script can execute within the reader's context.
    *   **Example:** An attacker injects `<script>alert('XSS')</script>` into a field that is later used to generate a PDF using Dompdf. When a user opens the generated PDF, the alert box appears.
    *   **Impact:**  Potentially allows an attacker to execute arbitrary JavaScript within the user's PDF viewer, potentially leading to information disclosure, session hijacking (if the PDF reader interacts with web services), or other malicious actions depending on the PDF reader's capabilities.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Strictly sanitize all user-provided HTML input before passing it to Dompdf. Use a robust HTML sanitization library specifically designed to prevent XSS.
        *   Consider using a Content Security Policy (CSP) for PDFs if the PDF reader supports it, to restrict the capabilities of embedded scripts.
        *   Educate users about the risks of opening PDFs from untrusted sources.

## Attack Surface: [Server-Side Request Forgery (SSRF) via HTML Resource Loading](./attack_surfaces/server-side_request_forgery__ssrf__via_html_resource_loading.md)

*   **Description:** Server-Side Request Forgery (SSRF) via HTML Resource Loading
    *   **How Dompdf Contributes to the Attack Surface:** Dompdf, when configured to allow remote resources (`isRemoteEnabled` option), can fetch external resources (images, stylesheets) referenced in the HTML. An attacker can inject HTML with URLs pointing to internal network resources or external servers.
    *   **Example:** An attacker injects `<img src="http://internal.server/admin">` into the HTML. If `isRemoteEnabled` is true, Dompdf will attempt to fetch this resource, potentially revealing information about the internal network or triggering actions on the internal server.
    *   **Impact:** Allows an attacker to probe internal network infrastructure, potentially access sensitive internal services, or launch attacks against other systems from the server running Dompdf.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Disable the `isRemoteEnabled` option in Dompdf's configuration if fetching remote resources is not absolutely necessary.
        *   If remote resources are required, implement a strict whitelist of allowed domains or URLs.
        *   Use a Content Security Policy (CSP) to restrict the domains from which Dompdf can load resources.
        *   Implement network segmentation to limit the impact of SSRF attacks.

## Attack Surface: [Local File Inclusion (LFI) via HTML Resource Loading](./attack_surfaces/local_file_inclusion__lfi__via_html_resource_loading.md)

*   **Description:** Local File Inclusion (LFI) via HTML Resource Loading
    *   **How Dompdf Contributes to the Attack Surface:** Similar to SSRF, if Dompdf's configuration or the PDF reader's capabilities allow, an attacker might be able to include local files on the server using file paths in resource-loading tags (e.g., `<img src="file:///etc/passwd">`).
    *   **Example:** An attacker injects `<img src="file:///etc/passwd">` into the HTML. If Dompdf or the PDF reader processes this, the contents of `/etc/passwd` might be included in the generated PDF.
    *   **Impact:** Allows an attacker to read sensitive files on the server's filesystem, potentially leading to information disclosure, privilege escalation, or other security breaches.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Ensure Dompdf's `chroot` configuration option is properly set and restricts access to only necessary directories.
        *   Sanitize and validate all user-provided input that could influence resource paths.
        *   Configure the PDF reader to restrict access to local files.
        *   Principle of least privilege: Run the Dompdf process with minimal necessary permissions.

