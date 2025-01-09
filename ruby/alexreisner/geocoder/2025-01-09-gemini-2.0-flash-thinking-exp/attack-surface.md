# Attack Surface Analysis for alexreisner/geocoder

## Attack Surface: [API Parameter Injection](./attack_surfaces/api_parameter_injection.md)

*   **Description:** Maliciously crafted input provided to the application is passed through the `geocoder` library and used as parameters in requests to external geocoding APIs, potentially leading to unintended actions or information disclosure from the API provider.
    *   **How Geocoder Contributes:** The `geocoder` library takes user-supplied strings (addresses, coordinates) and uses them to construct requests to various geocoding services. If these strings are not sanitized, malicious input can be directly incorporated into the API request parameters.
    *   **Example:** An attacker provides the input `

