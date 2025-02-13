# Threat Model Analysis for react-native-maps/react-native-maps

## Threat: [Fake Location Injection for Markers](./threats/fake_location_injection_for_markers.md)

*   **Description:** An attacker provides manipulated GPS coordinates (latitude/longitude) to the `MapView.Marker` component, causing it to display a false location.  This bypasses any *external* location validation if the validation isn't directly tied to the data *before* it's passed to the `react-native-maps` component. The attacker directly influences the rendering of the `Marker`.
*   **Impact:**
    *   Users see incorrect marker locations, leading to misinformation.
    *   Application logic relying on accurate marker positions is disrupted, potentially causing significant errors.
    *   Facilitates social engineering or other attacks by presenting false information on the map.
*   **Affected Component:** `MapView.Marker` component (specifically, the `coordinate` prop).
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Pre-Component Validation:**  Implement rigorous validation of coordinate data *before* it is passed to the `coordinate` prop of the `MapView.Marker` component. This validation should be independent of any external location services.
    *   **Server-Side Validation (Essential):**  Never trust client-provided location data.  Always validate coordinates on the server-side before storing or using them.
    *   **Sanitize Input:** If coordinates originate from user input, thoroughly sanitize the input to prevent injection attacks.

## Threat: [Map Tile Hijacking (Man-in-the-Middle)](./threats/map_tile_hijacking__man-in-the-middle_.md)

*   **Description:** An attacker intercepts the network traffic between the `MapView` component and the map tile server.  `react-native-maps` relies on the underlying platform (iOS/Android) and network libraries to fetch tiles.  If HTTPS is not properly enforced *or* if there's a vulnerability in the platform's handling of HTTPS, the attacker can replace legitimate map tiles with malicious ones. This directly affects the visual output of the `MapView`.
*   **Impact:**
    *   Users see incorrect or manipulated map data, leading to navigation errors or misinterpretations.
    *   Potential exposure to malicious content embedded within the altered map tiles.
    *   Complete loss of trust in the application's map display.
*   **Affected Component:** `MapView` component (the core component responsible for rendering map tiles).
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Strict HTTPS Enforcement:** Ensure that *all* map tile requests use HTTPS, and that the application correctly validates the server's certificate. This is crucial for the security of the `MapView`.
    *   **Certificate Pinning:** If the map provider and platform support it, implement certificate pinning for the map tile server. This significantly increases the difficulty of a successful MitM attack.
    *   **Network Security Configuration (Android):** Use Android's Network Security Configuration to explicitly define trusted CAs and enforce certificate pinning at the platform level.
    *   **URL Validation:** Ensure the URL used for the map tile provider is hardcoded correctly and not susceptible to manipulation.

## Threat: [Malicious Custom Overlay Injection](./threats/malicious_custom_overlay_injection.md)

*   **Description:** If the application uses custom overlays (e.g., `MapView.Polygon`, `MapView.Polyline`, `MapView.Circle`) and allows user-provided data to be incorporated into these overlays *without proper sanitization*, an attacker can inject malicious code (e.g., JavaScript) or content. This directly exploits the rendering logic of these `react-native-maps` components.
*   **Impact:**
    *   Cross-site scripting (XSS) attacks, potentially compromising user accounts or data.
    *   Display of inappropriate, misleading, or offensive content within the map overlays.
    *   Phishing attacks, where the overlay is designed to trick users into revealing sensitive information.
*   **Affected Component:** `MapView.Polygon`, `MapView.Polyline`, `MapView.Circle`, `MapView.Overlay` (and any custom overlay components built using `react-native-maps`).
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Rigorous Input Sanitization:**  *Always* sanitize user-provided data *before* it is used in any `react-native-maps` overlay component. This includes text, coordinates, and any other properties. Use a well-vetted sanitization library.
    *   **Output Encoding:** Encode any user-provided data before rendering it within the overlay to prevent XSS.
    *   **Content Security Policy (CSP):** Implement a CSP to restrict the types of content that can be loaded and executed, mitigating the impact of XSS.
    *   **Component-Specific Validation:** Validate the structure and content of overlays *before* passing them to the `react-native-maps` components. For example, check that polygon coordinates form a valid closed shape.

## Threat: [API Key Exposure](./threats/api_key_exposure.md)

*   **Description:** The application's map provider API key (necessary for `MapView` to function with most providers) is exposed in the client-side code or through insecure storage. An attacker can extract this key and use it maliciously. While not *exclusively* a `react-native-maps` issue, the library's functionality is directly impacted.
*   **Impact:**
    *   Financial loss due to unauthorized API usage.
    *   Potential access to other services associated with the compromised API key.
    *   Service disruption if the API key is revoked or rate-limited.
*   **Affected Component:** `MapView` (as it relies on the API key to function).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Never Hardcode:** Absolutely never store API keys directly in client-side code.
    *   **Backend Proxy (Recommended):** The best practice is to proxy map API requests through your own backend server. The client app communicates with your server, which then makes the authenticated request to the map provider, keeping the API key completely hidden from the client.
    *   **Environment Variables:** If a backend proxy is not feasible, use environment variables to store the API key securely, ensuring they are not committed to version control.
    *   **Secure Storage:** Utilize platform-specific secure storage mechanisms (e.g., Keychain on iOS, Keystore on Android) if the key *must* be stored on the device, but this is still less secure than a backend proxy.
    *   **Regular Rotation:** Rotate API keys periodically.
    *   **Usage Monitoring:** Monitor API usage for any suspicious patterns.

