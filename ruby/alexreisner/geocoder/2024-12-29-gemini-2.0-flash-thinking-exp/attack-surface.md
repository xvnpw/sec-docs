*   **Attack Surface:** Provider API Parameter Injection
    *   **Description:**  Malicious data injected into parameters sent to third-party geocoding provider APIs.
    *   **How Geocoder Contributes to the Attack Surface:** `geocoder` constructs API requests to various providers based on user input (e.g., location names). If this input isn't sanitized, attackers can inject arbitrary parameters.
    *   **Example:** An attacker provides a location name like `"London&extra_param=malicious_value"` which, if not properly handled, could be passed directly to the provider's API, potentially causing unexpected behavior or information disclosure at the provider level.
    *   **Impact:**  Unauthorized access to provider data, manipulation of geocoding results, denial of service against the provider, potentially leading to incorrect application behavior or exposure of sensitive information.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Implement strict input validation and sanitization on all user-provided data before using it with the `geocoder` library. Use parameterized queries or equivalent mechanisms if the provider API allows. Avoid directly concatenating user input into API request strings.

*   **Attack Surface:** API Key Exposure
    *   **Description:**  Sensitive API keys required by some geocoding providers are exposed.
    *   **How Geocoder Contributes to the Attack Surface:** `geocoder` often requires API keys for certain providers to function. If these keys are not managed securely, they can become a point of vulnerability.
    *   **Example:** API keys are hardcoded in the application's source code, stored in insecure configuration files, or accidentally committed to version control systems.
    *   **Impact:**  Unauthorized use of the geocoding provider's API, potentially leading to financial costs, data breaches, or abuse of the provider's services under the application's credentials.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:** Store API keys securely using environment variables, dedicated secrets management systems (e.g., HashiCorp Vault, AWS Secrets Manager), or encrypted configuration files. Avoid hardcoding keys in the codebase or committing them to version control.