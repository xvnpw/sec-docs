# Attack Surface Analysis for leaflet/leaflet

## Attack Surface: [GeoJSON/Data Source Poisoning (XSS)](./attack_surfaces/geojsondata_source_poisoning__xss_.md)

*   **Description:** Maliciously crafted GeoJSON data, or data from a compromised source, is used to inject JavaScript code into the application.
    *   **Leaflet Contribution:** Leaflet *directly* renders GeoJSON data, including feature properties, into the map's UI (e.g., popups, tooltips). This provides the *direct* injection point if the data isn't properly sanitized. Leaflet's `bindPopup` and `bindTooltip` methods, when used with unsanitized GeoJSON properties, are the primary concern.
    *   **Example:** An attacker uploads a GeoJSON file with a feature property containing `<script>alert('XSS')</script>`.  The application uses `feature.properties.name` directly in `marker.bindPopup(feature.properties.name)`. When a user clicks on the feature, the script executes.
    *   **Impact:**
        *   Session hijacking.
        *   Data theft.
        *   Defacement.
        *   Redirection to malicious websites.
        *   Installation of malware.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Validation:** Rigorously validate the structure and *content* of all GeoJSON data. Reject any data that doesn't conform to expected types and formats.
        *   **Output Encoding/Sanitization:** *Always* sanitize and HTML-encode any data extracted from GeoJSON properties *before* displaying it in the UI. Use a robust HTML sanitization library (e.g., DOMPurify).  *Never* directly insert GeoJSON data into the DOM using Leaflet's `bindPopup` or similar methods without sanitization.  This is the *most crucial* mitigation.
        *   **Content Security Policy (CSP):** Implement a strict CSP to limit the sources from which scripts can be executed.

## Attack Surface: [GeoJSON/Data Source Poisoning (DoS)](./attack_surfaces/geojsondata_source_poisoning__dos_.md)

*   **Description:** Extremely large or complex GeoJSON files are used to overwhelm the client-side processing, leading to a denial of service.
    *   **Leaflet Contribution:** Leaflet *directly* processes GeoJSON data on the client-side to render it on the map.  Large or deeply nested GeoJSON can consume excessive resources, causing the browser to become unresponsive or crash. This is a *direct* consequence of Leaflet's client-side rendering of GeoJSON.
    *   **Example:** An attacker uploads a GeoJSON file containing millions of features or features with extremely complex, deeply nested geometries.  Leaflet attempts to render all of this, exhausting browser memory.
    *   **Impact:**
        *   Application unavailability.
        *   User frustration.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Size Limits:** Enforce strict size limits on uploaded or fetched GeoJSON data on the client-side.
        *   **Complexity Limits:** Limit the complexity of GeoJSON geometries (e.g., number of vertices, nesting depth) that Leaflet will process.
        *   **Progressive Loading/Tiling:** For large datasets, implement progressive loading or tiling techniques to avoid loading the entire dataset at once. Use Leaflet plugins designed for handling large datasets (e.g., plugins that use clustering or vector tiles). This directly mitigates Leaflet's attempt to render everything at once.
        *   **Web Workers:** Offload GeoJSON parsing and processing to a Web Worker to prevent blocking the main thread and improve responsiveness, allowing Leaflet to handle larger datasets more gracefully.

## Attack Surface: [Tile Layer URL Manipulation](./attack_surfaces/tile_layer_url_manipulation.md)

*   **Description:** An attacker modifies the URL used to fetch map tiles, potentially redirecting to a malicious server.
    *   **Leaflet Contribution:** Leaflet *directly* uses the provided tile layer URL to fetch and display map tiles.  This is a core function of Leaflet. If the application allows this URL to be manipulated, Leaflet will fetch tiles from the attacker-controlled location.
    *   **Example:** An attacker intercepts a request and changes the tile URL passed to `L.tileLayer()` to `https://malicious.example.com/{z}/{x}/{y}.png`. Leaflet then fetches tiles from the attacker's server.
    *   **Impact:**
        *   Display of malicious content.
        *   Potential XSS (if the malicious tiles contain JavaScript – less common, but possible).
        *   Information disclosure (if the original URL contained API keys).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Hardcode/Whitelist Tile URLs:** Hardcode the tile layer URLs in the application's configuration or use a strict whitelist of allowed tile providers. *Never* allow users to directly input tile URLs that are then passed to `L.tileLayer()`.
        *   **Content Security Policy (CSP):** Use the `img-src` and `connect-src` directives in CSP to restrict the domains from which Leaflet can load tiles and related resources. This directly controls where Leaflet fetches data.

