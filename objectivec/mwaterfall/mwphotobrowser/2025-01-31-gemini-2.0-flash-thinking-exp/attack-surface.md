# Attack Surface Analysis for mwaterfall/mwphotobrowser

## Attack Surface: [Cross-Site Scripting (XSS) via Configuration](./attack_surfaces/cross-site_scripting__xss__via_configuration.md)

*   **Description:** Injection of malicious JavaScript code into the web page through application configuration options that are rendered by `mwphotobrowser`. This occurs when unsanitized user-controlled data is used in configuration options like `caption` or `description`.
*   **How mwphotobrowser contributes:** `mwphotobrowser` directly renders configuration options, including `caption` and `description`, into the DOM. If the application provides unsanitized data to these options, `mwphotobrowser` will render it as HTML, potentially executing injected JavaScript.
*   **Example:** An attacker injects `<img src=x onerror=alert('XSS')>` into an image caption field in the application. If the application passes this unsanitized caption as the `caption` option to `mwphotobrowser`, the JavaScript `alert('XSS')` will execute when `mwphotobrowser` renders the image display.
*   **Impact:** Full compromise of the user's browser session, including stealing cookies, session tokens, redirecting to malicious websites, defacement, and potentially further attacks against the user's system.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Input Sanitization:** The application **must** sanitize all user-provided data before using it in `mwphotobrowser` configuration options (especially `caption`, `description`, and any URL-based options). Use robust HTML escaping or sanitization libraries to neutralize potentially malicious JavaScript code before passing data to `mwphotobrowser`.
    *   **Content Security Policy (CSP):** Implement a strict Content Security Policy to limit the sources from which the browser can load resources and execute scripts. This acts as a secondary defense to mitigate the impact of XSS even if input sanitization is bypassed.

## Attack Surface: [DOM-based XSS through Image Attributes](./attack_surfaces/dom-based_xss_through_image_attributes.md)

*   **Description:** XSS vulnerability arising from `mwphotobrowser`'s manipulation of the Document Object Model (DOM) when setting image attributes (like `alt` or `title`) using data from potentially untrusted sources.
*   **How mwphotobrowser contributes:** If `mwphotobrowser` dynamically sets image attributes based on configuration data originating from user input or untrusted sources without proper encoding, it can introduce DOM-based XSS. `mwphotobrowser`'s code is responsible for setting these attributes in the DOM.
*   **Example:** The application uses a user-provided description as the `alt` attribute for images displayed by `mwphotobrowser`. If the description contains `<img alt="Attacker's payload" onerror=alert('DOM XSS')>`, and `mwphotobrowser` directly sets this as the `alt` attribute without encoding, the JavaScript `alert('DOM XSS')` will execute when the browser processes the image tag.
*   **Impact:** Similar to reflected XSS, can lead to browser session compromise, data theft, redirection, and defacement.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Output Encoding:**  Ensure that data used to set HTML attributes by `mwphotobrowser` is properly encoded before being inserted into the DOM. Use browser-provided encoding functions or libraries to escape special characters and prevent JavaScript injection within attribute values.
    *   **Input Validation and Sanitization (Defense in Depth):** While output encoding is essential, sanitizing input as a defense-in-depth measure can further reduce the risk. Validate and sanitize user inputs before they are used to configure `mwphotobrowser`.
    *   **Regular Security Audits:**  Review the source code of `mwphotobrowser` (or the parts you are using and configuring) and the application's integration to verify that proper output encoding is consistently applied when setting DOM attributes.

