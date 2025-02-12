# Attack Surface Analysis for angular/angular.js

## Attack Surface: [Client-Side Template Injection (CSTI) / Expression Sandboxing Bypass](./attack_surfaces/client-side_template_injection__csti___expression_sandboxing_bypass.md)

*   **Description:**  Attackers inject malicious AngularJS expressions into client-side templates, leading to arbitrary JavaScript execution. This exploits AngularJS's expression evaluation mechanism.
*   **How AngularJS Contributes:** AngularJS 1.x's client-side template rendering and expression evaluation, especially its historically flawed sandbox, make it inherently vulnerable to this if user input is not handled correctly.  This is the *core* vulnerability of AngularJS 1.x.
*   **Example:**
    *   Vulnerable Code (assuming `userInput` is directly from user input):
        ```html
        <div>{{userInput}}</div>
        ```
    *   Attacker Input:
        ```
        {{constructor.constructor('alert("XSS")')()}}
        ```
        (Classic sandbox escape; many variations exist).
*   **Impact:**
    *   Execution of arbitrary JavaScript in the victim's browser.
    *   Theft of cookies, session tokens, and other sensitive data.
    *   DOM manipulation and website defacement.
    *   Redirection to malicious sites.
    *   Bypass of client-side security controls.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Contextual Escaping (SCE):** Use `$sce.trustAsHtml`, `$sce.trustAsJs`, etc., *only* when absolutely necessary and with full understanding of the risks.  Favor `ng-bind` and `ng-bind-html` (with proper server-side sanitization) over direct interpolation.
    *   **Avoid `ng-bind-html-unsafe`:** Never use this directive with untrusted input.
    *   **Content Security Policy (CSP):** Implement a strong CSP, especially `script-src`, to limit the impact of successful injections.  Avoid `unsafe-eval` in your CSP.
    *   **Server-Side Input Validation & Sanitization:**  *Always* validate and sanitize user input on the server *before* it reaches the client.  Use a robust HTML sanitization library (e.g., DOMPurify on the server if you must allow some HTML).
    *   **Upgrade to Angular (v2+):**  This is the most effective long-term solution.  Modern frameworks have built-in protection against CSTI.

## Attack Surface: [Prototype Pollution on `$scope`](./attack_surfaces/prototype_pollution_on__$scope_.md)

*   **Description:** Attackers manipulate the prototype chain of AngularJS's `$scope` object by injecting malicious properties, potentially leading to unexpected behavior or code execution.
*   **How AngularJS Contributes:** AngularJS's reliance on the `$scope` object for data binding and its dynamic nature make it susceptible to prototype pollution if user input is not carefully controlled. This is a *direct* consequence of AngularJS's design.
*   **Example:**
    *   Vulnerable Code (if `userInput` is an object directly from user input):
        ```javascript
        $scope.data = userInput;
        ```
    *   Attacker Input (as JSON):
        ```json
        {
          "__proto__": {
            "polluted": true
          }
        }
        ```
*   **Impact:**
    *   Denial of Service (DoS) through unexpected application behavior.
    *   Potential for code execution (though less direct than CSTI).
    *   Modification of application logic.
*   **Risk Severity:** High (can be Critical in some scenarios, depending on how `$scope` is used)
*   **Mitigation Strategies:**
    *   **Strict Input Validation:**  Thoroughly validate and sanitize any user-supplied data before assigning it to the `$scope`.  Define expected data structures and reject anything that doesn't conform.
    *   **Object.freeze() / Object.seal():**  Use these methods to prevent modification of `$scope` objects or properties after initialization, where appropriate.
    *   **Avoid Direct Assignment:**  Do not directly assign user-supplied objects to `$scope` without careful validation and sanitization.  Create new objects and copy only the expected properties.
    *   **`controllerAs` Syntax:**  Using `controllerAs` can help isolate scope properties, reducing the risk.
    *   **Upgrade:** Migrate to a modern framework that is less susceptible to prototype pollution.

## Attack Surface: [Vulnerable Directives and Third-Party Libraries](./attack_surfaces/vulnerable_directives_and_third-party_libraries.md)

*   **Description:**  Custom AngularJS directives or third-party libraries may contain vulnerabilities (e.g., XSS, insecure DOM manipulation) or be outdated and unmaintained, exposing the application to known exploits.
*   **How AngularJS Contributes:** AngularJS's extensive use of directives and its ecosystem of third-party libraries create a large potential attack surface if these components are not carefully vetted and maintained.  The directive system is *fundamental* to AngularJS.
*   **Example:**
    *   A custom directive that directly inserts user-provided HTML into the DOM without sanitization.
    *   Using an outdated version of a popular AngularJS UI library with a known XSS vulnerability.
*   **Impact:**
    *   XSS vulnerabilities.
    *   Other vulnerabilities specific to the directive or library.
    *   Exposure to known exploits in outdated components.
*   **Risk Severity:** High (can be Critical depending on the vulnerability)
*   **Mitigation Strategies:**
    *   **Secure Directive Development:**  Follow secure coding practices when creating custom directives.  Sanitize user input, avoid direct DOM manipulation, and use AngularJS's built-in security features.
    *   **Library Vetting:**  Thoroughly vet any third-party libraries before use.  Check for known vulnerabilities, review the code, and ensure the library is actively maintained.
    *   **Regular Updates:**  Keep all AngularJS libraries and modules updated to the latest versions to patch known vulnerabilities.  Use dependency management tools (npm, yarn).
    *   **Software Composition Analysis (SCA):**  Use SCA tools to automatically identify known vulnerabilities in dependencies.

## Attack Surface: [`$http` and JSON-Related Issues (CSRF) - *Conditional High Risk*](./attack_surfaces/_$http__and_json-related_issues__csrf__-_conditional_high_risk.md)

*   **Description:** Improper use of the `$http` service can expose the application to CSRF attacks if proper protection mechanisms are not in place.
*   **How AngularJS Contributes:** While `$http` itself isn't inherently vulnerable, AngularJS applications often rely heavily on AJAX requests *made through `$http`*, making CSRF a significant concern if not addressed. AngularJS *does* provide built-in CSRF protection, but it must be correctly configured. *This is only high risk if the built-in protection is not used or is misconfigured.*
*   **Example:**
    *   An application that uses `$http` to make state-changing requests (e.g., POST, PUT, DELETE) without including and validating a CSRF token.
*   **Impact:**
    *   Attackers can forge requests on behalf of authenticated users, leading to unauthorized actions (e.g., changing passwords, making purchases, deleting data).
*   **Risk Severity:** High (Conditional - only if CSRF protection is not properly implemented)
*   **Mitigation Strategies:**
    *   **Implement CSRF Protection:** Use AngularJS's built-in CSRF protection (using the `X-XSRF-TOKEN` header) or a server-side CSRF protection library. Ensure both client and server are correctly configured. The server must generate and send the token, and the client must include it in subsequent requests *using `$http`*.

