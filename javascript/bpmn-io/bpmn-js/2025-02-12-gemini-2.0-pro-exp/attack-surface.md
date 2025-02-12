# Attack Surface Analysis for bpmn-io/bpmn-js

## Attack Surface: [XML External Entity (XXE) Injection](./attack_surfaces/xml_external_entity__xxe__injection.md)

*   **Description:** Exploitation of vulnerabilities in XML parsers to access local files, perform SSRF, or cause DoS.
*   **bpmn-js Contribution:** `bpmn-js` *directly* parses BPMN 2.0 XML files.  The library's handling of XML parsing is the core of this vulnerability. If the underlying XML parser (or how `bpmn-js` uses it) is misconfigured, it's vulnerable.
*   **Example:** An attacker uploads a BPMN file containing:
    ```xml
    <!DOCTYPE bpmn:definitions [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL">
      <bpmn:process id="Process_1">
        <bpmn:startEvent id="StartEvent_1" name="&xxe;"/>
      </bpmn:process>
    </bpmn:definitions>
    ```
    If the parser resolves external entities, the content of `/etc/passwd` might be exposed.
*   **Impact:**
    *   Disclosure of sensitive server files.
    *   Server-Side Request Forgery (SSRF).
    *   Denial of Service (DoS).
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Disable External Entities (Primary):**  Ensure the XML parser used by `bpmn-js` (or the application layer *before* data reaches `bpmn-js`) is configured to *completely disable* the resolution of external entities and DTDs.  This is the *absolute most important* mitigation.  The specific configuration depends on the underlying XML parsing library.  If `bpmn-js` uses a configurable parser, configure it directly. If the application handles XML before passing it to `bpmn-js`, configure *that* parser.
    *   **Input Validation (Secondary):** Validate the structure of the BPMN XML *before* parsing, but *do not rely on this as the primary defense*. Reject files with suspicious elements like `<!ENTITY`.

## Attack Surface: [JavaScript Execution within the Diagram (XSS)](./attack_surfaces/javascript_execution_within_the_diagram__xss_.md)

*   **Description:** Execution of malicious JavaScript embedded within BPMN elements (e.g., script tasks) if `bpmn-js` is configured to execute them.
*   **bpmn-js Contribution:** `bpmn-js` *directly* provides the functionality to potentially execute JavaScript embedded within the diagram.  This is a core feature that, if enabled, creates the XSS vulnerability.
*   **Example:** An attacker uploads a BPMN file with a script task:
    ```xml
    <bpmn:scriptTask id="ScriptTask_1" scriptFormat="javascript">
      <bpmn:script>
        alert(document.cookie); // Steal cookies
      </bpmn:script>
    </bpmn:scriptTask>
    ```
*   **Impact:**
    *   Session hijacking.
    *   Data theft.
    *   Redirection to malicious sites.
    *   Defacement.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Disable Script Execution (Primary):** Configure `bpmn-js` to *not* execute scripts embedded in the diagram. This is the most secure and recommended approach. Consult the `bpmn-js` documentation for configuration options related to disabling script execution. This might involve disabling a specific module or providing a custom "scripting" implementation that does nothing.
    *   **Content Security Policy (CSP) (Strong Secondary):** Implement a *strict* CSP that limits the sources from which scripts can be loaded.  This is a crucial defense-in-depth measure.  Example: `Content-Security-Policy: script-src 'self';`.
    *   **Input Sanitization (Difficult/Unreliable as Primary):**  If (and *only* if) script execution is absolutely required, *attempt* to sanitize the script content using a robust HTML/JavaScript sanitization library (like DOMPurify).  This is *extremely difficult* to do correctly and should *never* be the sole defense.

## Attack Surface: [Denial of Service (DoS) via Complex Diagrams](./attack_surfaces/denial_of_service__dos__via_complex_diagrams.md)

*   **Description:** Overwhelming the `bpmn-js` rendering engine with a large/complex BPMN diagram.
*   **bpmn-js Contribution:** `bpmn-js` is *directly* responsible for rendering the diagram in the browser.  Its rendering engine is the target of this attack.
*   **Example:** An attacker uploads a BPMN file with thousands of nested elements or extremely long labels.
*   **Impact:**
    *   Application unresponsiveness.
    *   Browser crashes.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Input Size Limits:** Enforce strict limits on the size of uploaded BPMN files.
    *   **Complexity Limits:** Analyze the parsed BPMN XML *before* rendering (this might be done in the application layer before passing data to `bpmn-js`) and reject diagrams exceeding limits on:
        *   Number of elements.
        *   Number of connections.
        *   Nesting depth.
        *   Text label length.
    *   **Timeouts:** Set reasonable timeouts for diagram rendering within `bpmn-js` (if configurable) or in the application's handling of `bpmn-js`.

## Attack Surface: [XML Bomb (Billion Laughs Attack)](./attack_surfaces/xml_bomb__billion_laughs_attack_.md)

*    **Description:** A specific type of XML-based DoS attack where nested entities are defined recursively, leading to exponential expansion and resource exhaustion.
*    **bpmn-js Contribution:** `bpmn-js` *directly* parses BPMN 2.0 XML files. The library's handling of XML parsing is the core of this vulnerability.
*    **Example:**
    ```xml
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
     <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
     <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
     <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
     <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
     <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
     <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL">
      <bpmn:process id="Process_1">
        <bpmn:startEvent id="StartEvent_1" name="&lol9;"/>
      </bpmn:process>
    </bpmn:definitions>
    ```
*   **Impact:** Can crash the application or even the server by consuming excessive memory or CPU.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Entity Expansion Limits:** Configure the XML parser to limit the depth and number of entity expansions. Most modern XML parsers have built-in safeguards, but these should be explicitly configured and tested.
    *   **Input Size Limits:** Impose reasonable limits on the size of the uploaded BPMN XML file.

