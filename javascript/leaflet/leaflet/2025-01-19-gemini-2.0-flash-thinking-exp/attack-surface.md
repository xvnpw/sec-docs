# Attack Surface Analysis for leaflet/leaflet

## Attack Surface: [Cross-Site Scripting (XSS) through Unsanitized User Input in Popups/Tooltips](./attack_surfaces/cross-site_scripting__xss__through_unsanitized_user_input_in_popupstooltips.md)

*   **Description:** Malicious JavaScript code is injected into the application and executed in a user's browser when they interact with a Leaflet popup or tooltip.
    *   **How Leaflet Contributes:** Leaflet provides methods (`bindPopup`, `bindTooltip`) that allow developers to display arbitrary HTML content. If this content originates from user input and is not properly sanitized, Leaflet will render the malicious script.
    *   **Example:** A user submits a form with the value `<img src="x" onerror="alert('XSS!')">`. This value is then used to set the content of a popup. When the popup is opened, the JavaScript within the `onerror` attribute executes.
    *   **Impact:**  Account takeover, redirection to malicious sites, data theft, defacement of the application.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Sanitization:**  Always sanitize user-provided data before using it in `bindPopup` or `bindTooltip`. Use a trusted HTML sanitization library.
        *   **Content Security Policy (CSP):** Implement a strict CSP to limit the sources from which scripts can be executed.
        *   **Avoid Direct HTML Insertion:** If possible, avoid directly inserting HTML. Use Leaflet's API to dynamically create elements and set their text content, which is safer.

## Attack Surface: [Cross-Site Scripting (XSS) through Unsanitized User Input in Custom Controls](./attack_surfaces/cross-site_scripting__xss__through_unsanitized_user_input_in_custom_controls.md)

*   **Description:** Similar to popups, if the application creates custom Leaflet controls and allows user-provided content within them without sanitization, XSS vulnerabilities can occur.
    *   **How Leaflet Contributes:** Leaflet's API allows developers to create custom controls with arbitrary HTML structures. If user input is directly embedded into this HTML without sanitization, it becomes an XSS vector.
    *   **Example:** A user's profile description is used to populate part of a custom control. If the description contains `<script>alert('XSS!')</script>`, this script will execute when the control is rendered.
    *   **Impact:** Account takeover, redirection to malicious sites, data theft, defacement of the application.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Sanitization:** Sanitize all user-provided data before incorporating it into custom control HTML.
        *   **Templating Engines with Auto-Escaping:** Use templating engines that automatically escape HTML by default.
        *   **Content Security Policy (CSP):** Implement a strict CSP.

