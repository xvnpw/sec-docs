# Attack Surface Analysis for github/markup

## Attack Surface: [Cross-Site Scripting (XSS) via Malicious Markup](./attack_surfaces/cross-site_scripting__xss__via_malicious_markup.md)

*   **Description:** An attacker injects malicious JavaScript code into the rendered HTML output by providing crafted markup that bypasses sanitization or exploits vulnerabilities in the parsing process. This executes in the context of other users' browsers.
*   **How `markup` Contributes:** `github/markup` processes the user-supplied markup, which is the direct source of the injected script. The vulnerability exists if the library fails to properly sanitize the input, allowing malicious code to be included in the output.
*   **Example:**
    *   **Markdown (attempting to bypass sanitization):**
        ```markdown
        <a href="javascript:alert('XSS')">Click Me</a>
        <img src="x" onerror="alert('XSS')">
        <div style="background-image: url(javascript:alert('XSS'))">
        <svg><animate onbegin=alert(1) attributeName=x dur=1s>
        ```
        (These *should* be blocked, but variations and new bypasses are constantly being discovered. The attacker's goal is to find a combination of tags, attributes, and encodings that slip through.)
    *   **AsciiDoc (if raw HTML is enabled - it shouldn't be):**
        ```asciidoc
        [raw]
        <script>alert('XSS');</script>
        [/raw]
        ```
    *   **reStructuredText (similar to AsciiDoc):**
        ```rst
        .. raw:: html

           <script>alert('XSS');</script>
        ```
*   **Impact:**
    *   Theft of user cookies and session tokens.
    *   Redirection of users to malicious websites.
    *   Defacement of the application.
    *   Execution of arbitrary code in the user's browser.
    *   Keylogging and data theft.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Use the Latest Version:** Always use the latest version of `github/markup` and all its dependencies.
    *   **Strict Sanitization:** Configure the sanitizer to allow *only* a minimal set of safe HTML tags and attributes.  *Never* allow `<script>`, `<style>`, `<object>`, `<embed>`, `<iframe>`, or event handlers.
    *   **Content Security Policy (CSP):** Implement a strong CSP with a restrictive `script-src` directive (e.g., `script-src 'self';`).
    *   **Input Validation (Length Limits):** Impose reasonable length limits.
    *   **Regular Security Audits:** Conduct regular audits and penetration testing, focusing on XSS.
    *   **Context-Aware Output Encoding:** Ensure proper encoding for the context where the output is used.

## Attack Surface: [Regular Expression Denial of Service (ReDoS) via Malicious Markup](./attack_surfaces/regular_expression_denial_of_service__redos__via_malicious_markup.md)

*   **Description:** An attacker provides crafted markup containing regular expressions (or patterns that are parsed as such) that cause catastrophic backtracking in the parser, consuming excessive CPU and leading to denial of service. The markup itself is the attack vector.
*   **How `markup` Contributes:** `github/markup` uses underlying parsers that rely on regular expressions. The attacker's crafted markup is directly processed by these regular expressions.
*   **Example:**
    *   **Markdown (highly parser-dependent):**
        ```markdown
        ((((((((((((((((((((((((((((((((((((((((((((((((((a))))))))))))))))))))))))))))))))))))))))))))))))))))
        ```
        (Repeated many times, or other patterns that trigger exponential backtracking in the *specific* Markdown parser being used). The attacker crafts the *markup* to exploit this.
    *   **AsciiDoc/reStructuredText:** Similar principles; the specific vulnerable patterns depend on the underlying parser (Asciidoctor, Docutils), but the attacker provides the malicious *markup* as input.
*   **Impact:**
    *   Application becomes unavailable.
    *   Server resources are exhausted.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use Updated Parsers:** Ensure the underlying parsers are up-to-date with ReDoS mitigations.
    *   **Input Length Limits:** *Strictly* limit the length of user-supplied markup. This is the most practical and effective mitigation.
    *   **Timeout Mechanisms:** Implement timeouts for parsing operations.
    *   **Resource Limits:** Limit the resources (CPU, memory) the parsing process can consume.

## Attack Surface: [Local File Inclusion (LFI) via Malicious Markup (Include Directives)](./attack_surfaces/local_file_inclusion__lfi__via_malicious_markup__include_directives_.md)

*   **Description:** An attacker uses crafted markup containing include directives (in AsciiDoc and reStructuredText) to include local files from the server, potentially revealing sensitive information. The malicious *markup* is the attack vector.
*   **How `markup` Contributes:** `github/markup` processes the markup, and if include directives are not properly disabled or restricted, the attacker's markup can directly trigger the file inclusion.
*   **Example:**
    *   **AsciiDoc:**
        ```asciidoc
        include::/etc/passwd[]
        ```
    *   **reStructuredText:**
        ```rst
        .. include:: /etc/passwd
        ```
*   **Impact:**
    *   Disclosure of sensitive system files.
    *   Potential for code execution.
*   **Risk Severity:** High (if include directives are enabled and not properly restricted)
*   **Mitigation Strategies:**
    *   **Disable Include Directives:** *Explicitly* disable the `include` directive in the configuration for AsciiDoc and reStructuredText parsers. This is the *primary* mitigation.
    *   **Strict Path Validation (if include is absolutely necessary - strongly discouraged):** Implement *extremely* strict path validation, allowing inclusion *only* from a specific, whitelisted, isolated directory. *Never* allow absolute paths or relative paths that traverse outside the allowed directory.
    *   **Least Privilege:** Ensure the rendering process runs with minimal privileges.

## Attack Surface: [Sanitization Bypass via Malicious Markup](./attack_surfaces/sanitization_bypass_via_malicious_markup.md)

*   **Description:**  The attacker crafts markup designed to exploit weaknesses in the HTML sanitizer, allowing malicious HTML to pass through and be rendered. The *markup itself* is crafted to bypass the sanitizer.
*   **How `markup` Contributes:** The core function of `github/markup` is to sanitize the input markup. This attack targets flaws in that sanitization process, using the markup as the vehicle for the bypass.
*   **Example:**
    *   **Mutation XSS (mXSS):** Exploiting differences in how browsers and the sanitizer interpret HTML.  The attacker crafts markup that the sanitizer *thinks* is safe, but the browser mutates into something malicious.
        ```html
        <img src=x onerror="alert(1)" alt="<img src=x onerror=alert(2)>">
        ```
    *   **Character Encoding Tricks:** Using unusual character encodings or Unicode homoglyphs to confuse the sanitizer. The attacker crafts the *markup* using these techniques.
    *   **Exploiting Sanitizer Bugs:** Finding specific HTML constructs that the sanitizer incorrectly handles. The attacker crafts *markup* to trigger these specific bugs.
*   **Impact:** (Same as general XSS)
    *   Theft of user cookies and session tokens.
    *   Redirection of users to malicious websites.
    *   Defacement of the application.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use a Well-Vetted Sanitizer:** Ensure `github/markup` uses a reputable and actively maintained HTML sanitizer.
    *   **Keep the Sanitizer Updated:** Regularly update the sanitizer library.
    *   **Restrictive Configuration:** Configure the sanitizer to allow the absolute minimum necessary HTML.
    *   **CSP:** A strong Content Security Policy (CSP) is a crucial second layer of defense.
    *   **Fuzzing:** Use fuzzing to test the sanitizer with a wide range of malicious markup inputs.

