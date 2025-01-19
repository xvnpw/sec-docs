# Attack Surface Analysis for preactjs/preact

## Attack Surface: [Cross-Site Scripting (XSS) via Unsanitized Props/State](./attack_surfaces/cross-site_scripting__xss__via_unsanitized_propsstate.md)

*   **Description:** Malicious scripts are injected into the application through unsanitized data passed as props or used to update component state. When Preact renders this data, the script is executed in the user's browser.
*   **How Preact Contributes to the Attack Surface:** Preact, by default, renders HTML content passed to it. If developers don't explicitly sanitize or escape user-provided or external data before passing it as props or setting it in the state, Preact will render any HTML, including malicious `<script>` tags.
*   **Example:** A component receives user input for a "description" field via props. If the user enters `<img src="x" onerror="alert('XSS')">`, Preact will render this tag, and the `onerror` event will execute the JavaScript alert.
*   **Impact:**  Full compromise of the user's session, redirection to malicious sites, data theft, installation of malware, defacement of the website.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Sanitize all user-provided or external data before using it in Preact components. Use browser built-in functions like `textContent` or libraries like DOMPurify for sanitization. Employ Content Security Policy (CSP) to further restrict the execution of inline scripts.

## Attack Surface: [Cross-Site Scripting (XSS) via Dynamically Generated Event Handlers](./attack_surfaces/cross-site_scripting__xss__via_dynamically_generated_event_handlers.md)

*   **Description:** Event handlers (like `onClick`) are constructed dynamically based on user input or external data without proper validation, allowing attackers to inject malicious JavaScript code.
*   **How Preact Contributes to the Attack Surface:** While Preact itself doesn't directly encourage this pattern, developers might inadvertently create dynamic event handlers. If these handlers are based on untrusted data, Preact will execute the provided JavaScript when the event is triggered.
*   **Example:** A component dynamically creates an `onClick` handler based on a user-provided string: `<button onClick={userProvidedFunction}>Click Me</button>`. If `userProvidedFunction` is `javascript:alert('XSS')`, clicking the button will execute the malicious script.
*   **Impact:** Similar to XSS via props/state, leading to session compromise, data theft, and other malicious activities.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Avoid dynamically generating event handlers based on untrusted data. If necessary, strictly validate and sanitize the input used to construct the handler. Prefer using predefined functions and passing data as arguments.

## Attack Surface: [Client-Side Routing Vulnerabilities (if using a Preact Router)](./attack_surfaces/client-side_routing_vulnerabilities__if_using_a_preact_router_.md)

*   **Description:**  Vulnerabilities in the client-side routing logic allow attackers to manipulate the URL to access unauthorized parts of the application or trigger unexpected behavior.
*   **How Preact Contributes to the Attack Surface:** If using a Preact-specific router library (or a custom implementation within a Preact application), improper handling of route parameters or path matching can create vulnerabilities. For instance, failing to sanitize route parameters before using them to fetch data can lead to further issues.
*   **Example:** A route defined as `/users/:id`. If the `id` parameter is not validated and is directly used in an API call, an attacker could inject malicious characters or SQL injection attempts (if the backend is vulnerable).
*   **Impact:** Access to sensitive information, unauthorized actions, potential backend exploitation if route parameters are used in backend queries without sanitization.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:**  Thoroughly validate and sanitize route parameters before using them. Implement proper access controls and authorization checks for different routes. Use a well-vetted and regularly updated Preact router library.

## Attack Surface: [Vulnerabilities in Third-Party Preact Components](./attack_surfaces/vulnerabilities_in_third-party_preact_components.md)

*   **Description:**  Security flaws in third-party Preact components used within the application can introduce vulnerabilities.
*   **How Preact Contributes to the Attack Surface:**  By integrating and relying on external components, the application inherits the security risks associated with those components. Preact's component model facilitates the use of such libraries.
*   **Example:** Using a vulnerable date picker component (built for Preact or adaptable to it) that has a known XSS vulnerability.
*   **Impact:**  Depends on the vulnerability within the third-party component, ranging from XSS to remote code execution.
*   **Risk Severity:** Varies (can be Critical or High depending on the vulnerability)
*   **Mitigation Strategies:**
    *   **Developer:**  Carefully vet third-party Preact components before using them. Regularly update dependencies to patch known vulnerabilities. Monitor security advisories for the libraries being used.

## Attack Surface: [Dependency Vulnerabilities in Preact's Ecosystem](./attack_surfaces/dependency_vulnerabilities_in_preact's_ecosystem.md)

*   **Description:**  Vulnerabilities in the dependencies of Preact itself or other libraries commonly used with Preact can be exploited.
*   **How Preact Contributes to the Attack Surface:**  Like any modern JavaScript framework, Preact relies on a set of dependencies. Vulnerabilities in these dependencies can indirectly affect applications built with Preact.
*   **Example:** A vulnerability in a common utility library used by Preact or a routing library specifically designed for Preact.
*   **Impact:**  Depends on the vulnerability within the dependency, potentially leading to XSS, remote code execution, or other security breaches.
*   **Risk Severity:** Varies (can be Critical or High depending on the vulnerability)
*   **Mitigation Strategies:**
    *   **Developer:** Regularly update Preact and all its dependencies. Use tools like `npm audit` or `yarn audit` to identify and address known vulnerabilities. Implement a Software Bill of Materials (SBOM) to track dependencies.

