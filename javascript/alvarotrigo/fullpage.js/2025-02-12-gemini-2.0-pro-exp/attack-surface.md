# Attack Surface Analysis for alvarotrigo/fullpage.js

## Attack Surface: [Unsafe Callback Execution (XSS)](./attack_surfaces/unsafe_callback_execution__xss_.md)

*   **Description:**  Execution of malicious JavaScript code injected through user-supplied data within `fullPage.js` callback functions. This remains the most dangerous vulnerability type *specific to how fullPage.js is used*.
*   **How fullPage.js Contributes:**  The library provides numerous callback functions (e.g., `afterLoad`, `onLeave`, `afterRender`, `afterSlideLoad`, `onSlideLeave`) that are executed at specific points in the navigation lifecycle.  These callbacks are *designed* to allow developers to execute custom code, making them inherently vulnerable if user input is mishandled. This is a *direct* contribution.
*   **Example:**
    ```javascript
    // Vulnerable code:
    fullpage('#fullpage', { 
        afterLoad: function(origin, destination, direction) {
            // Assume 'userInput' comes from a user-controlled input field.
            let userInput = document.getElementById('userInput').value;
            document.getElementById('message').innerHTML = "Welcome to section: " + userInput;
        }
    });

    // Attacker input in 'userInput' field:
    // <img src=x onerror="alert('XSS!')">
    ```
    The attacker's input is directly used within the `fullPage.js` callback, leading to XSS.
*   **Impact:**
    *   Session hijacking.
    *   Theft of sensitive data (cookies, tokens).
    *   Defacement of the website.
    *   Redirection to malicious websites.
    *   Installation of malware.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid User Input in Callbacks:** The *primary* mitigation is to avoid using user-supplied data directly within `fullPage.js` callbacks. Fetch data from trusted, server-side sources instead.
    *   **Content Security Policy (CSP):** Implement a strict CSP to restrict the sources from which scripts can be executed.  This is a crucial defense-in-depth measure.
    *   **Sanitization Libraries:** If user input *must* be used, employ a robust HTML sanitization library like DOMPurify *before* incorporating it into the callback.
    *   **Templating Engines (with Auto-Escaping):** Use a templating engine that automatically escapes output by default.
    *   **Output Encoding:** If manually constructing HTML, use appropriate output encoding (e.g., `textContent` instead of `innerHTML`).

## Attack Surface: [Manipulation of fullPage.js API Methods](./attack_surfaces/manipulation_of_fullpage_js_api_methods.md)

*   **Description:**  Unauthorized use of `fullPage.js` API methods (e.g., `moveSectionDown()`, `moveTo()`, `setAllowScrolling()`) to bypass intended navigation, expose hidden content, or cause a denial-of-service.  This is *directly* related to the API provided by the library.
*   **How fullPage.js Contributes:**  The library *intentionally* exposes a global API (`fullpage_api`) for programmatic control.  This API is a core feature of `fullPage.js`, and its misuse is a direct consequence of its existence.
*   **Example:**
    An attacker uses the browser's developer console:
    ```javascript
    fullpage_api.moveTo('secretSection', 0); // Access a hidden section
    fullpage_api.setAllowScrolling(false); // Disable scrolling (DoS)
    ```
*   **Impact:**
    *   Exposure of sensitive information in hidden sections.
    *   Bypassing of security controls.
    *   Denial-of-service (by disabling scrolling).
    *   Disruption of the user experience.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Obfuscation/Minification:**  Makes it harder, but not impossible, to understand and misuse the API.
    *   **Event Validation (Server-Side):**  *Crucially*, validate *all* actions triggered by navigation changes on the *server-side*.  Do *not* rely on client-side `fullPage.js` events alone.
    *   **Disable API Access (if possible):** If external control is not needed, wrap the `fullPage.js` initialization in a closure to limit the scope of `fullpage_api`, preventing direct global access.
        ```javascript
        (function() {
            var fp = new fullpage('#fullpage', { /* options */ });
            // fullpage_api is not accessible from outside this closure
        })();
        ```
    *   **Custom Events and Secure Handlers:** Use custom events to trigger server-side actions, validating these events on the server.
    *   **Timeout/Reset (for Scrolling):** Implement a timer to automatically re-enable scrolling if it's been disabled unexpectedly, mitigating the DoS.

## Attack Surface: [Using outdated fullPage.js version](./attack_surfaces/using_outdated_fullpage_js_version.md)

*   **Description:**  Attackers can use known vulnerabilities in outdated fullPage.js version.
*   **How fullPage.js Contributes:** Older versions might contain known vulnerabilities.
*   **Example:**
    Using version with known XSS vulnerability.
*   **Impact:**
    *   Depends on vulnerability.
*   **Risk Severity:** High to Critical (depends on vulnerability)
*   **Mitigation Strategies:**
    *   **Keep fullPage.js Updated:** Regularly update `fullPage.js` to the latest version.
    *   **Vulnerability Scanning:** Use vulnerability scanning tools.

