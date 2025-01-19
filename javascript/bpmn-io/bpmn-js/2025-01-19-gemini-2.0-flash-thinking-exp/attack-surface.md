# Attack Surface Analysis for bpmn-io/bpmn-js

## Attack Surface: [Script Injection via BPMN Attributes](./attack_surfaces/script_injection_via_bpmn_attributes.md)

**Description:** Malicious actors could craft BPMN XML where certain attributes contain JavaScript or other executable code that might be executed when the application processes or renders the diagram.

**How bpmn-js Contributes:** `bpmn-js` parses the BPMN XML, making the attribute values accessible to the application. If the application then uses these values without proper sanitization in a context where JavaScript execution is possible (e.g., dynamically generating HTML), it becomes vulnerable.

**Example:** A BPMN element with a custom property containing a JavaScript `<img>` tag with an `onerror` attribute that executes malicious code.

**Impact:** Cross-Site Scripting (XSS), leading to potential session hijacking, data theft, or malicious actions on behalf of the user.

**Risk Severity:** High

**Mitigation Strategies:**
* **Strict Output Encoding/Escaping:**  When displaying or using data extracted from the BPMN model, especially attribute values, ensure proper encoding and escaping based on the output context (HTML escaping, JavaScript escaping, etc.).
* **Content Security Policy (CSP):** Implement a strict CSP to limit the sources from which the browser can load resources and restrict inline script execution.
* **Avoid Dynamic HTML Generation with Untrusted Data:** Minimize the use of `eval()` or similar functions that execute strings as code, especially when dealing with data from the BPMN model.

## Attack Surface: [Dependency Vulnerabilities](./attack_surfaces/dependency_vulnerabilities.md)

**Description:** `bpmn-js` relies on other JavaScript libraries. Vulnerabilities in these dependencies can indirectly affect the security of the application.

**How bpmn-js Contributes:** By including `bpmn-js`, the application also includes its dependencies, inheriting any vulnerabilities present in those dependencies.

**Example:** A known security vulnerability in a specific version of a library used by `bpmn-js` that could be exploited by a crafted input.

**Impact:**  Wide range of potential impacts depending on the vulnerability in the dependency, including XSS, remote code execution, or information disclosure.

**Risk Severity:** High

**Mitigation Strategies:**
* **Regular Dependency Updates:** Keep `bpmn-js` and all its dependencies up-to-date with the latest versions to patch known vulnerabilities.
* **Security Scanning:** Use tools like npm audit or yarn audit to identify known vulnerabilities in your project's dependencies.
* **Software Composition Analysis (SCA):** Implement SCA tools in your development pipeline to continuously monitor and manage open-source dependencies.

