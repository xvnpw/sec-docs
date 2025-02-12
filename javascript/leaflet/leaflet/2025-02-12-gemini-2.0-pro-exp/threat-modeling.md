# Threat Model Analysis for leaflet/leaflet

## Threat: [Leaflet Library Compromise (CDN Attack)](./threats/leaflet_library_compromise__cdn_attack_.md)

*   **Description:** An attacker compromises the CDN hosting the Leaflet library files. They replace the legitimate `leaflet.js` file with a modified version containing malicious code. Any application loading Leaflet from that compromised CDN will execute the attacker's code, giving them full control over the map and potentially the entire application.
*   **Impact:** Complete compromise of the Leaflet map component and potentially the entire application. The attacker could steal user data, manipulate the map display, redirect users, or perform other harmful actions. This is a direct attack on the Leaflet library itself.
*   **Affected Component:** The core Leaflet library (`leaflet.js`) loaded from a CDN.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Subresource Integrity (SRI):** *Mandatory*. Always use Subresource Integrity (SRI) when loading Leaflet from a CDN. Include the `integrity` attribute in the `<script>` tag, providing a cryptographic hash of the expected file content. The browser will verify the hash before executing the script.
    *   **Self-Hosting:** Host the Leaflet library files on your own server. This eliminates reliance on a third-party CDN and gives you complete control over the files.
    *   **Reputable CDN:** If a CDN must be used, choose a highly reputable provider with a strong security track record.

## Threat: [Malicious Plugin](./threats/malicious_plugin.md)

*   **Description:** A third-party Leaflet plugin contains vulnerabilities (intentional or unintentional) that can be exploited. This could be due to poor coding, lack of security reviews, or a compromised plugin repository. The plugin might introduce XSS vulnerabilities, allow for data injection, or perform other malicious actions *through its Leaflet integration*. This is distinct from a general web vulnerability *within* the plugin; it must leverage Leaflet's API or functionality.
*   **Impact:** The impact depends on the specific vulnerability. It could range from significant UI issues to complete application compromise, especially if the plugin has extensive access to Leaflet's core functionality.
*   **Affected Component:** Any third-party Leaflet plugin.
*   **Risk Severity:** High (Potentially Critical, depending on the plugin's capabilities and the nature of the vulnerability).
*   **Mitigation Strategies:**
    *   **Plugin Vetting:** Rigorously research and vet any third-party plugins before use. Check reputation, source code (if available), maintenance, and community feedback. Prioritize well-known, actively maintained plugins.
    *   **Use Well-Known Plugins:** Prefer plugins that are widely used, actively maintained, and have a good reputation within the Leaflet community.
    *   **Keep Plugins Updated:** Regularly update plugins to the latest versions to patch vulnerabilities.
    *   **SRI (for CDN-loaded plugins):** Use Subresource Integrity (SRI) if loading plugins from a CDN.
    *   **Fork and Maintain:** For critical plugins, consider forking the repository and maintaining your own version. This allows for security audits and rapid patching.
    *   **CSP:** Use a strict Content Security Policy (CSP) to limit the capabilities of plugins, restricting the domains they can access and the types of actions they can perform. This can mitigate the impact of a compromised plugin.

## Threat: [Sensitive Information Disclosure in GeoJSON Properties (When Leaflet *directly* handles display)](./threats/sensitive_information_disclosure_in_geojson_properties__when_leaflet_directly_handles_display_.md)

*   **Description:** While *primarily* a data handling issue, if Leaflet's default popup behavior (or custom code using Leaflet's API) is used to *directly* display GeoJSON `properties` *without sanitization*, and developers inadvertently include sensitive information (API keys, private data) in those properties, this becomes a Leaflet-related vulnerability. The core issue is the lack of sanitization *before* using Leaflet's display mechanisms.
*   **Impact:** Leakage of sensitive information, potentially leading to unauthorized access, data breaches, or other security compromises. The vulnerability arises from using Leaflet's features to display unsanitized data.
*   **Affected Component:** `L.GeoJSON`, `L.geoJSON`, and specifically any code that uses Leaflet's popup functionality (e.g., `bindPopup`) or other display methods to render feature properties *without prior sanitization*.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Data Separation:** *Never* store sensitive information directly within GeoJSON properties. This is the most important mitigation.
    *   **Server-Side Data Association:** Store sensitive data separately (e.g., database) and associate it with map features on the server-side, only when needed and with authorization.
    *   **Property Sanitization:** *Before* using Leaflet's `bindPopup` or any other method to display feature properties, *always* sanitize the property values using a robust HTML sanitization library (like DOMPurify). Do *not* rely on simple escaping.
    *   **Whitelist Properties:** Implement a whitelist approach. Define a list of *allowed* properties and only display those, rather than trying to filter out "bad" properties.
    *   **Data Review:** Carefully review all GeoJSON data before deployment to ensure no sensitive information is included.

