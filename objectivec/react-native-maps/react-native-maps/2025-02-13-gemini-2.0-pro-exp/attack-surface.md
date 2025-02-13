# Attack Surface Analysis for react-native-maps/react-native-maps

## Attack Surface: [API Key Exposure/Theft](./attack_surfaces/api_key_exposuretheft.md)

*   **Description:**  Unauthorized access and use of the map provider's API key.
*   **`react-native-maps` Contribution:** The library *requires* an API key to function, making secure key management a central concern. The library's functionality is *dependent* on the API key, making this a direct attack surface.
*   **Example:**  An attacker extracts a hardcoded API key from a decompiled APK and uses it to make excessive requests to the Google Maps API, incurring charges for the legitimate application owner.
*   **Impact:** Financial loss (due to API usage charges), service disruption (if the key is revoked), reputational damage.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Secure Backend Retrieval:** Fetch the API key from a secure backend service *at runtime*.  Never store the key directly in the client-side code.
        *   **Platform-Specific Secure Storage:** After retrieval, store the key using platform-specific secure storage (Keychain on iOS, Keystore on Android).
        *   **API Key Restrictions:** Configure strict usage restrictions on the API key within the map provider's console (e.g., limit to specific APIs, application identifiers, and potentially IP addresses for server-side components).
        *   **Backend Proxy:** For sensitive operations or high-volume requests, proxy requests through a secure backend that handles the API key.
    *   **User:** (Limited direct mitigation, relies on developer implementation)

## Attack Surface: [Map Data Manipulation (Man-in-the-Middle)](./attack_surfaces/map_data_manipulation__man-in-the-middle_.md)

*   **Description:**  Interception and modification of map data (tiles, markers, etc.) transmitted between the application and the map provider.
*   **`react-native-maps` Contribution:** The library *directly handles* the communication with the map provider to fetch and display map data.  This network communication is a core function of the library.
*   **Example:**  An attacker on a compromised Wi-Fi network intercepts map tile requests and replaces them with tiles showing incorrect information, misleading the user.
*   **Impact:**  Misinformation, misdirection, potential for phishing attacks, compromised application functionality.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Certificate Pinning:** Implement certificate pinning to ensure the application only communicates with the legitimate map provider server. This prevents attackers from using forged certificates.
        *   **Data Validation:** Validate and sanitize all data received that will be displayed on the map.
        *   **Secure Backend for Sensitive Data:** Fetch sensitive data (like marker locations with personal information) through a secure backend, rather than directly from a third-party API on the client.
    *   **User:**
        *   Use a VPN when connecting to public Wi-Fi networks.
        *   Be cautious of apps that display obviously incorrect map information.

## Attack Surface: [Map Provider Vulnerabilities (SDK/API Exploits)](./attack_surfaces/map_provider_vulnerabilities__sdkapi_exploits_.md)

*   **Description:**  Exploitation of vulnerabilities within the map provider's SDK or API.
*   **`react-native-maps` Contribution:** The library acts as a *direct bridge* to the underlying native map SDKs (Google Maps, Apple Maps).  Vulnerabilities in these SDKs *directly* impact the application because `react-native-maps` is the intermediary.
*   **Example:**  A zero-day vulnerability in the Google Maps SDK for Android allows an attacker to execute arbitrary code on the device through a specially crafted map request made *via* `react-native-maps`.
*   **Impact:**  Varies widely depending on the vulnerability, potentially ranging from denial of service to remote code execution.
*   **Risk Severity:** **High** to **Critical** (depending on the specific vulnerability)
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Keep Libraries Updated:**  Regularly update the `react-native-maps` library *and* the underlying native map SDKs to the latest versions. This is crucial for receiving security patches.  This is the *most important* mitigation.
        *   **Monitor Security Advisories:**  Stay informed about security advisories and vulnerabilities related to the chosen map provider and its SDKs.
    *   **User:**
        *   Keep the device's operating system and apps updated.

## Attack Surface: [Cross-Site Scripting (XSS) in Custom Markers](./attack_surfaces/cross-site_scripting__xss__in_custom_markers.md)

*   **Description:**  Injection of malicious JavaScript code into custom marker content.
*   **`react-native-maps` Contribution:** The library *provides the API* for creating custom markers and rendering arbitrary content within them.  The library's `Marker` component and its props are the *direct mechanism* for this vulnerability if misused.
*   **Example:**  An attacker creates a marker with a `title` or `description` prop containing malicious JavaScript code.  When another user views the marker, the code executes in their application context.
*   **Impact:**  Theft of user cookies, session hijacking, redirection to malicious websites, defacement of the application.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Input Sanitization:**  Thoroughly sanitize *all* user-provided data *before* passing it to the `title`, `description`, or any other prop of the `Marker` component that renders HTML or allows for script execution. Use a well-vetted sanitization library (e.g., DOMPurify).  Do *not* rely on simple escaping.
        *   **Content Security Policy (CSP):** Implement a Content Security Policy to restrict the sources from which scripts can be loaded.
    *   **User:** (Limited direct mitigation, relies on developer implementation)

