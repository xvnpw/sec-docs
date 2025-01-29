# Attack Surface Analysis for angular/angular.js

## Attack Surface: [Client-Side Template Injection (CSTI) / AngularJS Expression Injection](./attack_surfaces/client-side_template_injection__csti___angularjs_expression_injection.md)

*   **Description:**  A **critical** vulnerability directly stemming from AngularJS's template engine. When user-controlled data is injected into AngularJS expressions within templates without proper sanitization, attackers can execute arbitrary JavaScript code in the user's browser. This is due to AngularJS's expression evaluation mechanism.
*   **AngularJS Contribution:** AngularJS's core feature of data binding and expression evaluation (`{{expression}}`, `ng-bind`, etc.) is the direct enabler of this vulnerability. Older versions of AngularJS, especially before Strict Contextual Escaping (SCE) was enforced by default, were particularly susceptible.
*   **Example:**
    *   An AngularJS application uses `ng-bind-html` to display user-provided content: `<div ng-bind-html="userInput"></div>`
    *   If `userInput` is directly taken from a URL parameter and contains malicious code like `<img src="x" onerror="alert('XSS')">`, AngularJS will render this HTML.
    *   The `onerror` event in the injected `<img>` tag will execute JavaScript `alert('XSS')`, demonstrating arbitrary code execution.
*   **Impact:** **Critical**. Full Cross-Site Scripting (XSS). Attackers can hijack user sessions, steal credentials, perform actions on behalf of the user, deface the website, and potentially distribute malware.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Strict Contextual Escaping (SCE) Enforcement:**  **Crucially ensure SCE is enabled and functioning correctly.**  Verify that developers are not accidentally disabling SCE or bypassing it with `trustAsHtml` or similar methods on user-controlled data.
        *   **Avoid `ng-bind-html` and `trustAsHtml` with User Data:**  **Never use these directives to render user-provided HTML directly.**  If absolutely necessary to display user-generated HTML, perform **robust server-side sanitization** using a well-vetted HTML sanitization library *before* passing it to the client and using `ng-bind-html`. Client-side sanitization is generally less reliable.
        *   **Treat All User Input as Untrusted in Templates:**  **Always sanitize or escape user input before embedding it into AngularJS expressions.** Use appropriate AngularJS directives that respect SCE by default (like `ng-bind`, `{{ }}` in most contexts with SCE enabled).
        *   **Content Security Policy (CSP):** Implement a strict CSP to act as a defense-in-depth measure. A properly configured CSP can significantly limit the impact of successful CSTI attacks by restricting the sources from which scripts can be loaded and executed.

## Attack Surface: [Outdated AngularJS Version with Known Vulnerabilities](./attack_surfaces/outdated_angularjs_version_with_known_vulnerabilities.md)

*   **Description:** Using an outdated version of AngularJS that has publicly disclosed **high or critical severity vulnerabilities** is a **high-risk** attack surface.  Security vulnerabilities are regularly discovered and patched in software, including AngularJS. Older versions are vulnerable to exploits targeting these known weaknesses.
*   **AngularJS Contribution:**  This is directly related to AngularJS because the vulnerability exists within the AngularJS framework code itself.  Using an older version means the application is running with known security flaws that have been addressed in newer releases.
*   **Example:**
    *   AngularJS versions prior to 1.6.4 had a known vulnerability (CVE-2017-11304) related to prototype pollution that could lead to Remote Code Execution (RCE) in specific scenarios.
    *   An application running AngularJS 1.5.x would be vulnerable to exploits targeting CVE-2017-11304 if the vulnerable conditions are met.
*   **Impact:** **High to Critical**.  Depending on the specific vulnerability in the outdated version, the impact can range from Cross-Site Scripting (XSS) to Remote Code Execution (RCE), potentially allowing complete compromise of the application and server in severe cases.
*   **Risk Severity:** **High** to **Critical** (depending on the specific vulnerability).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Immediately Upgrade AngularJS:** **The primary and most critical mitigation is to upgrade to the latest stable and patched version of AngularJS.**  Prioritize security updates.
        *   **Regular Dependency Updates:** Establish a process for regularly updating all application dependencies, including AngularJS and third-party libraries, to ensure security patches are applied promptly.
        *   **Vulnerability Scanning and Monitoring:** Implement automated vulnerability scanning tools that check for known vulnerabilities in application dependencies, including AngularJS. Regularly monitor security advisories and vulnerability databases for AngularJS.
        *   **Security Audits:** Conduct periodic security audits and penetration testing to identify potential vulnerabilities, especially after major updates or changes to the application.

These two attack surfaces represent the most critical AngularJS-specific security concerns that development teams must address to ensure the security of their applications. Addressing CSTI and keeping AngularJS up-to-date are paramount for mitigating high and critical risks.

