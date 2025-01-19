# Attack Surface Analysis for impress/impress.js

## Attack Surface: [Client-Side Cross-Site Scripting (XSS) via HTML Injection](./attack_surfaces/client-side_cross-site_scripting__xss__via_html_injection.md)

*   **Description:** Attackers inject malicious scripts into the impress.js presentation by providing unsanitized HTML content within the steps.
    *   **How impress.js Contributes:** Impress.js directly renders the HTML content provided within the `div` elements marked as steps. If this content originates from user input or an untrusted source and is not properly sanitized, it can lead to XSS.
    *   **Example:** A user provides the following as part of a step's content: `<img src="x" onerror="alert('XSS')">`. When impress.js renders this, the JavaScript will execute.
    *   **Impact:** Account takeover, session hijacking, redirection to malicious sites, data theft, defacement of the application.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:** Implement strict output encoding/escaping of any user-provided content before rendering it within the impress.js steps. Use context-aware escaping techniques appropriate for HTML.
        *   **Developer:** Utilize a Content Security Policy (CSP) to restrict the sources from which the browser can load resources and to prevent inline script execution.
        *   **Developer:** Avoid directly embedding user-controlled data into the HTML structure. If necessary, use templating engines with built-in escaping mechanisms.

## Attack Surface: [Client-Side Cross-Site Scripting (XSS) via Data Attribute Manipulation](./attack_surfaces/client-side_cross-site_scripting__xss__via_data_attribute_manipulation.md)

*   **Description:** Attackers manipulate the `data-*` attributes used by impress.js to inject and execute malicious scripts.
    *   **How impress.js Contributes:** While less direct than HTML injection, if the application logic uses user input to dynamically set or modify impress.js's `data-*` attributes (e.g., `data-transition-duration`), and this input is not validated, attackers might attempt to inject JavaScript. Browser behavior regarding script execution within data attributes can vary, but it's a potential vector.
    *   **Example:** An attacker might try to inject a value like `"1s; javascript:alert('XSS')"` into a data attribute if the application doesn't properly validate the input format.
    *   **Impact:** Similar to HTML injection, potentially leading to account takeover, data theft, etc.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**  Strictly validate and sanitize any user input that influences the `data-*` attributes used by impress.js. Ensure the input conforms to the expected data type and format.
        *   **Developer:** Implement a strong CSP to mitigate the risk of executing unexpected scripts.
        *   **Developer:** Avoid directly using user input to construct or modify these attributes without thorough validation.

