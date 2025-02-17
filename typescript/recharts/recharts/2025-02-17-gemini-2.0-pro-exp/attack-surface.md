# Attack Surface Analysis for recharts/recharts

## Attack Surface: [Cross-Site Scripting (XSS) via Untrusted Data in Chart Components](./attack_surfaces/cross-site_scripting__xss__via_untrusted_data_in_chart_components.md)

*   **Description:** Malicious JavaScript is injected into the chart's rendering context (SVG or HTML) through user-supplied data that populates Recharts components (labels, tooltips, axis values, data point values, etc.) and is not properly sanitized *before* being passed to Recharts.
*   **How Recharts Contributes:** Recharts is the *direct* mechanism by which the unsanitized user data is rendered into the DOM (as SVG or HTML), making it the execution point for the XSS payload. Recharts' rendering process itself is the vulnerable component.
*   **Example:**
    *   A user enters `<script>alert('XSS');</script>` into a form field, and this value is directly used as a label in a `BarChart`. Recharts renders this label, executing the script.
    *   A custom tooltip component uses a formatting function that directly injects user input into HTML: `tooltipContent = "<div>" + userData + "</div>";`. If `userData` is `<img src=x onerror=alert(1)>`, Recharts renders this, causing XSS.
*   **Impact:**
    *   Theft of user cookies and session tokens.
    *   Redirection to malicious websites.
    *   Defacement of the web page.
    *   Execution of arbitrary code in the user's browser.
    *   Keylogging and data theft.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Input Validation (Whitelist):** *Strictly* validate all user input *before* it is passed to *any* Recharts component. Use a whitelist approach, allowing only known-good characters and patterns. Reject any non-conforming input.
    *   **Output Encoding/Escaping (Context-Aware):** Use a robust HTML/SVG escaping library (e.g., DOMPurify) to encode or escape special characters *before* passing data to *any* Recharts component. The escaping must be context-aware (attribute vs. text content). *Do not rely on any potential internal sanitization by Recharts.*
    *   **Content Security Policy (CSP):** Implement a strong CSP to restrict script execution sources. This is a crucial second layer of defense.
    *   **Avoid `innerHTML` with User Data:** In custom components, avoid `innerHTML` with unsanitized user data. Use `textContent` or sanitize with DOMPurify *before* using `innerHTML`.
    * **Safe Templating:** If using templates, ensure automatic escaping or use explicit escaping functions.

## Attack Surface: [XSS via Vulnerable Custom Components/Event Handlers (Directly within Recharts)](./attack_surfaces/xss_via_vulnerable_custom_componentsevent_handlers__directly_within_recharts_.md)

*   **Description:** Custom Recharts components or event handlers (e.g., `onClick`, `onMouseEnter`) contain XSS vulnerabilities due to unsafe handling of user data or direct, unsanitized DOM manipulation *within the Recharts component's logic*.
*   **How Recharts Contributes:** The vulnerability exists *within* the custom component or event handler code that is *part of* the Recharts implementation. This is not about external data passed *to* Recharts, but about how Recharts' *own* custom code handles data.
*   **Example:**
    *   A custom tooltip component (defined *within* the Recharts usage) uses `innerHTML` to display user-provided data *without sanitization*. The vulnerability is *inside* the Recharts component definition.
    *   An `onClick` handler (defined as part of the Recharts chart) modifies the DOM based on unsanitized user input passed to that handler. The vulnerability is in the Recharts event handler code.
*   **Impact:**
    *   XSS (leading to the same consequences as above: cookie theft, redirection, etc.).
    *   Potentially other DOM manipulation issues, depending on the specific vulnerability.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Avoid `innerHTML` with User Data (within custom components):**  *Within* the custom component or event handler code, *never* use `innerHTML` with unsanitized user data. Prefer `textContent`. If `innerHTML` is absolutely necessary, *always* sanitize the data first using DOMPurify.
    *   **Safe DOM Manipulation (within custom components):** Use safe DOM manipulation methods within the custom component's code. Avoid directly modifying the DOM with user-supplied data.
    *   **Code Review (of custom components):** Thoroughly review the code of *all* custom Recharts components and event handlers for potential security vulnerabilities, paying close attention to how user data is handled and how the DOM is manipulated.

