# Attack Surface Analysis for bpmn-io/bpmn-js

## Attack Surface: [1. Stored/Reflected Cross-Site Scripting (XSS) via BPMN Diagram Content](./attack_surfaces/1__storedreflected_cross-site_scripting__xss__via_bpmn_diagram_content.md)

*   **Description:** An attacker injects malicious JavaScript code into BPMN diagram elements (e.g., task names, labels, documentation fields, custom properties) within the BPMN XML. When `bpmn-js` renders this diagram, the injected script executes in the user's browser.
*   **How bpmn-js Contributes:** `bpmn-js` is directly responsible for rendering the BPMN diagram content, including user-provided text and attributes from the XML. If `bpmn-js` does not properly sanitize or escape this content during rendering, it becomes vulnerable to XSS.  The library's rendering pipeline is the direct pathway for this vulnerability.
*   **Example:** A user creates a BPMN diagram and sets the name of a task to `<img src=x onerror=alert('XSS')>`. When another user views this diagram rendered by `bpmn-js`, the JavaScript `alert('XSS')` will execute in their browser.
*   **Impact:**
    *   Cross-Site Scripting (XSS).
    *   Session hijacking.
    *   Cookie theft.
    *   Defacement.
    *   Redirection to malicious websites.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Output Encoding/Escaping:** Ensure that the application, *especially when feeding data to `bpmn-js` for rendering*, properly encodes or escapes user-provided content for the HTML context. This should be done *before* the data is passed to `bpmn-js` for display. Use appropriate escaping functions provided by your frontend framework or libraries.  While `bpmn-js` might have some internal sanitization, relying solely on it is not recommended. Application-level output encoding is crucial.
    *   **Content Security Policy (CSP):** Implement a strict Content Security Policy to limit the sources from which the browser is allowed to load resources. This acts as a defense-in-depth measure to mitigate the impact of XSS even if output encoding is missed.

## Attack Surface: [2. Dependency Vulnerabilities (Indirectly via bpmn-js)](./attack_surfaces/2__dependency_vulnerabilities__indirectly_via_bpmn-js_.md)

*   **Description:** `bpmn-js` relies on various JavaScript dependencies. Vulnerabilities in these dependencies (both direct and transitive) can indirectly affect the security of applications using `bpmn-js`. While not a vulnerability *in* `bpmn-js` code itself, the library's dependency chain introduces this attack surface.
*   **How bpmn-js Contributes:** By including `bpmn-js` in your project, you inherently include its dependency tree. If `bpmn-js` depends on a vulnerable library, and that vulnerability is exploitable in the context of how `bpmn-js` or your application uses it, then `bpmn-js`'s dependency choice contributes to the attack surface.
*   **Example:** A specific version of a library used by `bpmn-js` (e.g., an XML parsing library or a utility library) is found to have an XSS or Remote Code Execution (RCE) vulnerability. Applications using `bpmn-js` with this vulnerable dependency are then also at risk.
*   **Impact:** Varies depending on the nature of the dependency vulnerability. Could range from XSS to RCE.
*   **Risk Severity:** Medium to High (depending on the severity of the dependency vulnerability - can be Critical for RCE).  We are including it here because dependency vulnerabilities can easily become High or Critical.
*   **Mitigation Strategies:**
    *   **Regular Dependency Updates:** Keep `bpmn-js` and *all* its dependencies updated to the latest versions. Regularly check for updates and apply them promptly. This is crucial for mitigating known vulnerabilities in the dependency chain.
    *   **Dependency Scanning:** Use dependency scanning tools (e.g., npm audit, OWASP Dependency-Check, Snyk) to identify known vulnerabilities in your project's dependencies. Integrate these tools into your development and CI/CD pipelines to proactively detect and address vulnerable dependencies introduced by `bpmn-js`.
    *   **Vulnerability Monitoring:** Subscribe to security advisories and vulnerability databases to stay informed about newly discovered vulnerabilities in libraries you use, including those in `bpmn-js`'s dependency tree.

