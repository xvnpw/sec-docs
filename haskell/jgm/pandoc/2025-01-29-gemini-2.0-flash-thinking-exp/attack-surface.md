# Attack Surface Analysis for jgm/pandoc

## Attack Surface: [Format-Specific Parsing Exploits](./attack_surfaces/format-specific_parsing_exploits.md)

*   **Description:** Vulnerabilities within Pandoc's parsers for various input document formats (Markdown, HTML, LaTeX, etc.) that can be exploited via crafted documents.
*   **Pandoc Contribution:** Pandoc's core design necessitates parsing diverse and complex document formats, inherently creating parsing attack surfaces.
*   **Example:** A malicious Markdown file triggers a buffer overflow in Pandoc's Markdown parser, allowing arbitrary code execution.
*   **Impact:** Arbitrary code execution, denial of service, information disclosure.
*   **Risk Severity:** **Critical** to **High**
*   **Mitigation Strategies:**
    *   **Keep Pandoc updated:** Regularly update Pandoc to the latest version to patch known parser vulnerabilities.
    *   **Limit input formats:** Restrict the application to accept only essential input formats, reducing the number of parsers exposed.
    *   **Sandboxing:** Run Pandoc in a sandboxed environment to contain potential exploits.

## Attack Surface: [Cross-Site Scripting (XSS) via HTML Output](./attack_surfaces/cross-site_scripting__xss__via_html_output.md)

*   **Description:** Generation of HTML output by Pandoc that contains malicious JavaScript from processed input, leading to XSS vulnerabilities when displayed in a browser.
*   **Pandoc Contribution:** Pandoc processes HTML and can generate HTML output. If user-provided HTML (or formats convertible to HTML) is processed and the output is served without sanitization, XSS is possible.
*   **Example:** A user provides Markdown with embedded HTML containing malicious JavaScript. Pandoc converts it to HTML, and the application serves this HTML unsanitized, resulting in XSS.
*   **Impact:** Account compromise, data theft, website defacement, malware distribution.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Sanitize HTML output:** Always sanitize Pandoc's HTML output before displaying it in a web browser using a robust HTML sanitization library.
    *   **Avoid `--no-xss-protection`:** Do not use Pandoc's `--no-xss-protection` option unless absolutely necessary and with extreme caution.
    *   **Implement CSP:** Utilize Content Security Policy (CSP) to further reduce XSS risks.

## Attack Surface: [XML External Entity (XXE) Injection](./attack_surfaces/xml_external_entity__xxe__injection.md)

*   **Description:** Exploitation of XML parsing within Pandoc when processing XML-based formats (DOCX, EPUB, etc.), allowing attackers to include external entity declarations in input documents to access local files or perform SSRF.
*   **Pandoc Contribution:** Pandoc's support for XML-based formats and its XML parsing capabilities can be vulnerable to XXE if not properly configured.
*   **Example:** A crafted DOCX file includes an external entity pointing to `/etc/passwd`. Pandoc attempts to resolve this entity during parsing, potentially exposing the file content.
*   **Impact:** Local file disclosure, Server-Side Request Forgery (SSRF), denial of service.
*   **Risk Severity:** **High** to **Medium** (can be High depending on application context and data sensitivity).
*   **Mitigation Strategies:**
    *   **Disable XXE in XML parsing:** Configure Pandoc's underlying XML parsing (if possible through Pandoc options or dependency configuration) to disable or restrict external entity resolution.
    *   **Limit XML formats:** If feasible, restrict the application from accepting XML-based input formats to reduce XXE exposure.
    *   **Sandboxing:** Run Pandoc in a sandboxed environment with restricted network and file system access.

## Attack Surface: [Command Injection via Output Format Options](./attack_surfaces/command_injection_via_output_format_options.md)

*   **Description:** Injection of arbitrary commands through manipulation of Pandoc's command-line options, particularly those related to output formats and external tools (like LaTeX for PDF generation).
*   **Pandoc Contribution:** Pandoc's command-line interface and flexible options, especially for output format customization, can be misused if user input directly controls these options.
*   **Example:** An application allows users to specify custom LaTeX templates for PDF conversion. An attacker injects shell commands into a malicious LaTeX template, which are executed when Pandoc generates the PDF.
*   **Impact:** Arbitrary code execution, server compromise.
*   **Risk Severity:** **Critical** to **High**
*   **Mitigation Strategies:**
    *   **Avoid direct command-line construction:** Never build Pandoc command-line calls directly from unsanitized user input.
    *   **Restrict options:** Limit user influence over Pandoc options to a predefined safe set.
    *   **Parameterization:** Use secure APIs or parameterization methods instead of directly exposing command-line options to users.
    *   **Input validation:** Sanitize and validate any user-provided values used in Pandoc options.
    *   **Least privilege:** Run Pandoc with the minimum necessary privileges.

## Attack Surface: [Lua Filter Vulnerabilities](./attack_surfaces/lua_filter_vulnerabilities.md)

*   **Description:** Execution of malicious code via Pandoc's Lua filter feature, either through vulnerabilities in Pandoc's Lua integration or by allowing untrusted Lua filters to be used.
*   **Pandoc Contribution:** Pandoc's Lua filter functionality allows extending its capabilities with Lua scripts, which can introduce significant security risks if not managed securely.
*   **Example:** A user provides a malicious Lua filter that, when executed by Pandoc during document processing, gains access to the server's file system or executes system commands.
*   **Impact:** Arbitrary code execution, server compromise, data theft.
*   **Risk Severity:** **Critical** to **High**
*   **Mitigation Strategies:**
    *   **Disable Lua filters:** If Lua filter functionality is not essential, disable it entirely.
    *   **Strictly control filters:** If Lua filters are necessary, rigorously control and validate all user-provided or external Lua filters.
    *   **Sandboxing for Lua:** Implement a secure sandboxing environment for Lua execution within Pandoc to limit the impact of malicious scripts.
    *   **Code review:** Thoroughly review and audit all Lua filters, even those developed internally.

