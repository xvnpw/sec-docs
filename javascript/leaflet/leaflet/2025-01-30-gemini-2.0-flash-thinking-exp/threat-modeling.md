# Threat Model Analysis for leaflet/leaflet

## Threat: [Malicious GeoJSON Injection](./threats/malicious_geojson_injection.md)

*   **Threat:** Malicious GeoJSON Injection
*   **Description:** An attacker crafts malicious GeoJSON data and injects it into the application, for example, through user uploads or compromised external APIs. This data is processed by Leaflet's `L.geoJSON` module. The attacker aims to exploit vulnerabilities in Leaflet's GeoJSON parsing or rendering to execute arbitrary JavaScript code in the user's browser. This could be achieved by embedding malicious scripts within GeoJSON properties or geometry definitions.
*   **Impact:** Cross-Site Scripting (XSS), leading to session hijacking, cookie theft, defacement of the application, redirection to malicious sites, or other client-side attacks.
*   **Leaflet Component Affected:** `L.geoJSON` module, data parsing and rendering logic.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Server-side validation and sanitization of all GeoJSON data before sending it to the client.
    *   Utilize a robust server-side GeoJSON parsing library to detect and prevent injection attempts.
    *   Implement Content Security Policy (CSP) to restrict the execution of inline scripts and external resources, limiting the impact of XSS.
    *   Validate GeoJSON schema against expected structure and properties.

## Threat: [Unsafe Feature Property Handling in Popups/Tooltips](./threats/unsafe_feature_property_handling_in_popupstooltips.md)

*   **Threat:** Unsafe Feature Property Handling in Popups/Tooltips
*   **Description:** An attacker injects malicious JavaScript code into feature properties within GeoJSON or other map data. When these properties are displayed in Leaflet popups or tooltips (using `L.popup` or `L.tooltip`) without proper sanitization, the malicious code is executed in the user's browser. This is a form of DOM-based XSS directly related to how Leaflet handles and renders feature data in interactive elements.
*   **Impact:** Cross-Site Scripting (XSS), leading to session hijacking, cookie theft, defacement of the application, redirection to malicious sites, or other client-side attacks.
*   **Leaflet Component Affected:** `L.popup`, `L.tooltip`, feature property access and rendering within popups/tooltips.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Sanitize feature properties server-side before sending data to the client.
    *   Sanitize feature properties client-side before displaying them in popups or tooltips using appropriate escaping or sanitization functions.
    *   Avoid using `innerHTML` to set popup/tooltip content based on feature properties. Prefer `textContent` or templating engines with auto-escaping.
    *   Implement Content Security Policy (CSP) to mitigate XSS risks.

