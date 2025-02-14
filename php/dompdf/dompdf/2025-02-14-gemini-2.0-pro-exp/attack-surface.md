# Attack Surface Analysis for dompdf/dompdf

## Attack Surface: [Remote Code Execution (RCE) via Malicious Font Files](./attack_surfaces/remote_code_execution__rce__via_malicious_font_files.md)

*   **Description:** Attackers can craft malicious font files (TTF, OTF) that exploit vulnerabilities in Dompdf's font parsing libraries, leading to arbitrary code execution on the server.
    *   **How Dompdf Contributes:** Dompdf relies on external libraries to parse and render fonts. Vulnerabilities in these libraries, *directly triggered by Dompdf's font processing*, can be exploited.
    *   **Example:** An attacker uploads a `.ttf` file disguised as a custom font. This file contains exploit code that, when parsed *by Dompdf*, overwrites memory and executes a shell command.
    *   **Impact:** Complete server compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Disable User-Uploaded Fonts:** The best mitigation is to *completely disallow* user-uploaded fonts. Use only pre-installed, known-good fonts.
        *   **Strict Font Validation (If User Uploads are *Unavoidable*):** If user uploads are *absolutely* required, implement *extremely* rigorous validation *before* Dompdf processes them. Use a dedicated, up-to-date font validation library (not just file type checks). This validation must occur *outside* of Dompdf's processing pipeline.
        *   **Disable Remote Font Loading:** Ensure `DOMPDF_ENABLE_REMOTE` is set to `false` in Dompdf's configuration.
        *   **Sandboxing/Containerization:** Run Dompdf in a sandboxed environment (e.g., Docker) with minimal privileges.
        *   **Least Privilege:** The Dompdf process should run with the absolute minimum necessary permissions.
        *   **Regular Updates:** Keep Dompdf and all dependencies (especially font libraries) updated.

## Attack Surface: [Remote Code Execution (RCE) via Malicious HTML/CSS](./attack_surfaces/remote_code_execution__rce__via_malicious_htmlcss.md)

*   **Description:** Vulnerabilities in Dompdf's HTML and CSS parsing engine can be exploited to achieve RCE.
    *   **How Dompdf Contributes:** Dompdf's *own* HTML/CSS parser is complex and may contain vulnerabilities that can be triggered by specially crafted input *processed by Dompdf*.
    *   **Example:** An attacker injects malicious CSS (e.g., exploiting a bug in how `@font-face` rules are handled, even with remote fonts disabled, or a vulnerability in CSS selector parsing) that triggers a buffer overflow *within Dompdf's parsing logic*, leading to code execution.
    *   **Impact:** Complete server compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Sanitization:** *Thoroughly* sanitize *all* user-supplied HTML and CSS using a robust HTML sanitization library (e.g., HTML Purifier). Whitelist *allowed* tags/attributes; do not blacklist.
        *   **Disable JavaScript:** Set `DOMPDF_ENABLE_JAVASCRIPT` to `false`.
        *   **Limit CSS Features:** Restrict allowed CSS to the bare minimum.
        *   **Sandboxing/Containerization:** Same as with font-based RCE.
        *   **Regular Updates:** Keep Dompdf and dependencies updated.
        *   **Least Privilege:** Same as with font-based RCE.

## Attack Surface: [Local File Inclusion (LFI) / Information Disclosure](./attack_surfaces/local_file_inclusion__lfi___information_disclosure.md)

*   **Description:** Attackers can use path traversal to trick Dompdf into reading arbitrary files from the server.
    *   **How Dompdf Contributes:** Dompdf's *own* handling of local resource inclusion (images, stylesheets) can be abused if not properly configured, *directly* leading to file reads.
    *   **Example:** An attacker injects `<img src="../../etc/passwd">` or `<img src="file:///etc/passwd">`. If Dompdf's configuration is weak, *Dompdf itself* will read and potentially include the contents of `/etc/passwd`.
    *   **Impact:** Disclosure of sensitive system files.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Base Path (Chroot):** Configure Dompdf with a very specific `DOMPDF_CHROOT` that restricts access to *only* necessary directories.
        *   **Disable Remote File Access:** Ensure `DOMPDF_ENABLE_REMOTE` is set to `false`.
        *   **Validate Resource Paths:** If users specify resource paths, *strictly* validate them *before* passing them to Dompdf. Ensure they are within `DOMPDF_CHROOT` and contain no path traversal (`..`). Use a dedicated path sanitization function; *never* directly use user input in file paths.
        *   **Least Privilege:** The Dompdf process should have read-only access to `DOMPDF_CHROOT` and *no* access elsewhere.

## Attack Surface: [Server-Side Request Forgery (SSRF)](./attack_surfaces/server-side_request_forgery__ssrf_.md)

*   **Description:** Attackers might be able to induce Dompdf to make requests to internal or external servers.
    *   **How Dompdf Contributes:** While `DOMPDF_ENABLE_REMOTE` is intended to prevent this, vulnerabilities or misconfigurations within *Dompdf's request handling* could still allow SSRF.
    *   **Example:** An attacker might try to include a resource from an internal IP address (e.g., `<img src="http://192.168.1.1/admin">`) or a URL that triggers a DNS lookup, even with remote file access supposedly disabled. *Dompdf's handling of the URL, even if flawed, is the direct cause*.
    *   **Impact:** Access to internal services, data exfiltration.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Network Segmentation:** Isolate the server running Dompdf.
        *   **DNS Resolution Control:** If possible, control DNS resolution for the Dompdf process.
        *   **Input Sanitization:** Sanitize URLs even if remote access is disabled. Validate URLs.
        *   **Regular Updates:** Keep Dompdf updated.

