# Attack Surface Analysis for yewstack/yew

## Attack Surface: [Cross-Site Scripting (XSS) via DOM Manipulation](./attack_surfaces/cross-site_scripting__xss__via_dom_manipulation.md)

*   **Description:** Injection of malicious scripts into web pages, executed in the user's browser.
*   **Yew Contribution:** Yew's client-side rendering and DOM manipulation can create XSS vulnerabilities if user or external data is rendered unsafely within Yew components.  Specifically, using `dangerously_set_inner_html` directly bypasses Yew's virtual DOM safety and introduces direct DOM manipulation risks.
*   **Example:** A Yew component displays user-submitted blog posts. If post content containing `<img src=x onerror=alert('XSS')>` is rendered using `dangerously_set_inner_html` without sanitization, the script will execute when the image fails to load.
*   **Impact:** Session hijacking, data theft, website defacement, redirection to malicious sites.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Sanitization:** Sanitize all user-provided and external data before rendering it in Yew components. Use robust HTML sanitization libraries.
    *   **Avoid `dangerously_set_inner_html`:**  Strictly avoid using `dangerously_set_inner_html` unless absolutely necessary and with extreme caution. Prefer Yew's virtual DOM for safe updates.
    *   **Content Security Policy (CSP):** Implement a strict CSP to mitigate the impact of XSS even if it occurs.

## Attack Surface: [JavaScript Interoperability Vulnerabilities (`JsValue`, `Callback`)](./attack_surfaces/javascript_interoperability_vulnerabilities___jsvalue____callback__.md)

*   **Description:** Vulnerabilities introduced through insecure interaction between Yew/WASM code and JavaScript, specifically via `JsValue` and `Callback`.
*   **Yew Contribution:** Yew's mechanisms for JavaScript interop (`JsValue`, `Callback`) can become attack surfaces if not handled securely. Incorrectly handling `JsValue` types or allowing untrusted JavaScript to trigger Yew callbacks with malicious data can lead to vulnerabilities.
*   **Example:** A Yew application uses `JsValue` to receive data from a JavaScript function. If the Yew code assumes the data is always a string but JavaScript can return an object, it could lead to type confusion and unexpected behavior.  If a `Callback` allows JavaScript to execute arbitrary Yew functions based on user-controlled input, it could be exploited to bypass security checks or trigger unintended actions.
*   **Impact:** Type confusion, unexpected program behavior, potential for arbitrary code execution within the WASM context or potentially in JavaScript.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Data Validation:**  Thoroughly validate and sanitize all data received from JavaScript via `JsValue` before using it in Yew code. Enforce expected types and data structures.
    *   **Type Safety:** Leverage Rust's strong typing to enforce type safety when working with `JsValue`. Consider using wrapper libraries for safer JavaScript API interactions.
    *   **Secure Callback Design:** Design `Callback` functions to be as restrictive as possible. Limit the functionality exposed to JavaScript and carefully validate any data passed to callbacks from JavaScript.
    *   **Minimize JavaScript Interop:** Reduce reliance on JavaScript interop. Implement functionality in Rust/WASM whenever feasible to minimize the attack surface at the WASM/JavaScript boundary.

## Attack Surface: [Insecure Client-Side Storage of Authentication Tokens](./attack_surfaces/insecure_client-side_storage_of_authentication_tokens.md)

*   **Description:** Storing authentication tokens insecurely in the browser's client-side storage, making them vulnerable to client-side attacks.
*   **Yew Contribution:** While not directly *caused* by Yew, Yew applications, being client-side, often manage authentication tokens.  If developers choose insecure storage methods within their Yew application, it becomes a Yew-contextual vulnerability.
*   **Example:** A Yew application stores a JWT in local storage without any protection. An XSS vulnerability in another part of the application (even unrelated to token handling) could allow an attacker to steal the token from local storage and gain unauthorized access.
*   **Impact:** Account takeover, unauthorized access to user data and application functionality.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **HTTP-only Cookies (Recommended):**  Prefer using HTTP-only cookies for storing authentication tokens. These are inaccessible to JavaScript, significantly reducing XSS-based token theft.
    *   **Avoid Local Storage for Sensitive Tokens:**  Avoid storing sensitive authentication tokens in local storage if possible due to XSS risks.
    *   **Secure Local Storage (If Necessary, with Extreme Caution):** If local storage *must* be used, implement robust client-side encryption of the token before storage. However, client-side encryption is complex and keys can be compromised. This is a less secure option than HTTP-only cookies.
    *   **Short-Lived Tokens and Refresh Tokens:** Use short-lived access tokens and refresh tokens to minimize the impact of token theft, even if storage is compromised.

