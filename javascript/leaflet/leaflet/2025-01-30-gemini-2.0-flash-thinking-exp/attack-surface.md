# Attack Surface Analysis for leaflet/leaflet

## Attack Surface: [Cross-Site Scripting (XSS) via User-Provided Data in Popups and Tooltips](./attack_surfaces/cross-site_scripting__xss__via_user-provided_data_in_popups_and_tooltips.md)

*   **Description:** Injection of malicious scripts into web pages through user-controlled data displayed in Leaflet popups or tooltips.
*   **Leaflet Contribution:** Leaflet provides easy mechanisms to display dynamic content in popups and tooltips, often populated from external data sources that might include user input. If developers don't sanitize this data, XSS vulnerabilities arise *directly due to how Leaflet handles content in popups/tooltips*.
*   **Example:** A website displays user-submitted place descriptions in marker popups. An attacker submits a description containing `<img src=x onerror=alert('XSS')>` which, when displayed in a popup, executes the malicious script *because Leaflet renders the provided HTML content*.
*   **Impact:**
    *   Session hijacking
    *   Account takeover
    *   Data theft
    *   Website defacement
    *   Malware distribution
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Input Sanitization:**  Always sanitize and encode user-provided data before displaying it in popups and tooltips. Use HTML escaping functions appropriate for the context (e.g., `textContent` property, or HTML encoding libraries).
    *   **Content Security Policy (CSP):** Implement a strict CSP to limit the sources from which scripts can be executed, reducing the impact of XSS even if it occurs.
    *   **Template Engine Security:** If using templating (like `L.Util.template`), ensure proper escaping is applied within the template, especially for user-provided data.

## Attack Surface: [Cross-Site Scripting (XSS) via Custom Control Content](./attack_surfaces/cross-site_scripting__xss__via_custom_control_content.md)

*   **Description:** Injection of malicious scripts through dynamically generated content within custom Leaflet controls, especially when this content is based on user input or external data.
*   **Leaflet Contribution:** Leaflet allows developers to create custom UI controls. If the content of these controls is dynamically generated and includes unsanitized data, it becomes a potential XSS vector *because Leaflet renders the HTML content provided for custom controls*.
*   **Example:** A custom search control displays search results directly in the control panel. If search results from an external API are not sanitized and contain malicious scripts, they will be executed when displayed in the control *because Leaflet renders the provided HTML in the control*.
*   **Impact:**
    *   Session hijacking
    *   Account takeover
    *   Data theft
    *   Website defacement
    *   Malware distribution
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Input Sanitization:** Sanitize and encode any dynamic content used within custom controls, particularly if it originates from user input or external, untrusted sources.
    *   **Content Security Policy (CSP):**  Implement CSP to further mitigate the impact of potential XSS vulnerabilities in custom controls.
    *   **Secure Control Development:** Follow secure coding practices when developing custom Leaflet controls, paying close attention to data handling and output encoding.

