# Threat Model Analysis for bpmn-io/bpmn-js

## Threat: [XML External Entity (XXE) Injection](./threats/xml_external_entity__xxe__injection.md)

*   **Description:** An attacker crafts a malicious BPMN 2.0 XML file containing XXE payloads. They upload this file, tricking the application into processing it. The attacker exploits the XML parser's handling of external entities.
    *   **Impact:**
        *   **Local File Disclosure:** Reading arbitrary files from the server's filesystem (configuration files, source code, etc.).
        *   **Server-Side Request Forgery (SSRF):** Forcing the server to make requests to internal/external resources, accessing internal services, scanning networks, or exfiltrating data.
        *   **Denial of Service (DoS):** Consuming server resources (CPU, memory) via entity expansion ("billion laughs").
    *   **Affected Component:**
        *   `moddle` (and the underlying XML parsing library it uses, likely `saxen` or a similar SAX-based parser). The vulnerability is in the *initial* XML parsing, *before* `bpmn-js` processes the model. The key is whether external entities are resolved.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Disable External Entity Resolution (Primary):** Configure the XML parser (through `moddle`'s options or by directly patching the underlying parser if needed) to *completely disable* external entity resolution and DTD processing. This must be done at the lowest level (the XML parser).
        *   **Input Validation (Secondary):** Validating the XML structure *before* parsing can help, but is easily bypassed and should *not* be the sole defense.

## Threat: [Malicious BPMN 2.0 XML (Non-XXE) - Resource Exhaustion](./threats/malicious_bpmn_2_0_xml__non-xxe__-_resource_exhaustion.md)

*   **Description:** An attacker crafts a BPMN 2.0 XML file that, without XXE payloads, is designed to be extremely large or complex, overwhelming the parser or renderer.
    *   **Impact:**
        *   **Denial of Service (DoS):** The server or user's browser becomes unresponsive due to excessive resource consumption (CPU, memory), disrupting service.
    *   **Affected Component:**
        *   `moddle` (XML parsing)
        *   `bpmn-js` core (diagram rendering and manipulation)
        *   `diagram-js` (underlying diagram rendering library)
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Size Limits:** Enforce strict limits on the size of uploaded BPMN files.
        *   **Complexity Limits (Difficult but Recommended):** Implement limits on the number of elements, nesting depth, or other complexity metrics. Requires careful analysis of typical diagram sizes.
        *   **Server-Side Resource Monitoring:** Monitor server resource usage (CPU, memory) and implement throttling/rate limiting.

## Threat: [Cross-Site Scripting (XSS) via Element Labels](./threats/cross-site_scripting__xss__via_element_labels.md)

*   **Description:** An attacker injects malicious JavaScript into the text label of a BPMN element (task, gateway, event, etc.). When rendered, the script executes in the victim's browser.
    *   **Impact:**
        *   **Session Hijacking:** Stealing session cookies, impersonating the victim.
        *   **Data Theft:** Accessing sensitive data on the page or in local storage.
        *   **Website Defacement:** Modifying page appearance or content.
        *   **Redirection:** Redirecting the victim to a malicious site.
    *   **Affected Component:**
        *   `bpmn-js` core (rendering logic)
        *   `diagram-js` (underlying rendering)
        *   Components rendering user-provided text from the BPMN model (e.g., `label` elements).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Output Encoding (Primary):** *Always* HTML-encode user-provided data (including element labels) *before* rendering in the DOM. Use a well-tested encoding library.
        *   **Content Security Policy (CSP):** Implement a strict CSP to restrict script sources, preventing execution of injected code even if encoding fails.
        *   **Input Sanitization (Secondary):** Sanitize user input, but output encoding is the primary defense.

## Threat: [Cross-Site Scripting (XSS) via Documentation Fields](./threats/cross-site_scripting__xss__via_documentation_fields.md)

*   **Description:** Similar to XSS via labels, but the attacker injects malicious JavaScript into a documentation field of a BPMN element.
    *   **Impact:** Same as XSS via Element Labels.
    *   **Affected Component:**
        *   `bpmn-js` core (rendering logic)
        *   `diagram-js`
        *   Components rendering documentation fields (potentially custom UI elements).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:** Same as XSS via Element Labels (Output Encoding, CSP, Input Sanitization).

