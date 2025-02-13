# Attack Surface Analysis for apollographql/apollo-android

## Attack Surface: [Insecure Storage of Sensitive Data (Related to Caching)](./attack_surfaces/insecure_storage_of_sensitive_data__related_to_caching_.md)

*   **Description:** Sensitive data fetched via GraphQL is cached insecurely on the device by `apollo-android`'s default caching mechanisms.
*   **How apollo-android Contributes:** Fetches data that *might* be sensitive and, by default, caches it in a potentially insecure manner (depending on OS and configuration). This is the *direct* involvement.
*   **Example:** An attacker gains access to the device and retrieves authentication tokens or personal information from the `apollo-android` cache, which was not explicitly configured for secure storage.
*   **Impact:** Data breach, unauthorized access to user accounts or sensitive information.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Client-Side:** *Never* rely solely on `apollo-android`'s default caching for sensitive data persistence.  Use secure storage mechanisms provided by Android (e.g., EncryptedSharedPreferences, Keystore) to store sensitive data, *regardless* of whether it was fetched via GraphQL.  Explicitly configure the `apollo-android` cache to *exclude* sensitive fields from being cached, or use a custom cache implementation that encrypts sensitive data.  This is crucial.

## Attack Surface: [Client-Side Cache Poisoning (If Custom Cache Handling is Mishandled)](./attack_surfaces/client-side_cache_poisoning__if_custom_cache_handling_is_mishandled_.md)

* **Description:** If the application uses custom logic to interact with or modify the `apollo-android` cache, vulnerabilities in *that custom code* could allow an attacker to inject malicious data. This is distinct from server-side cache poisoning. The risk is *high* only if the developer introduces vulnerabilities in their custom cache handling.
    * **How apollo-android Contributes:** Provides the caching mechanism that *could* be misused by custom application code. The vulnerability isn't inherent to `apollo-android` itself, but the library provides the *potential* for misuse.
    * **Example:** A developer implements a custom cache interceptor that incorrectly handles user input, allowing an attacker to inject malicious data into the cache. This then leads to XSS or other vulnerabilities when the cached data is used.
    * **Impact:** Data corruption, potential execution of malicious code (if cached data is used unsafely), leading to various client-side attacks.
    * **Risk Severity:** High (conditional - depends entirely on the presence of vulnerabilities in *custom* cache handling code).
    * **Mitigation Strategies:**
        *   **Client-Side:** If implementing *any* custom logic to interact with the `apollo-android` cache (e.g., custom interceptors, manual cache manipulation), apply rigorous secure coding practices.  Thoroughly validate and sanitize *all* data before writing it to the cache.  Treat any data retrieved from the cache as potentially untrusted, and sanitize it again before use. Avoid custom cache handling if possible; rely on `apollo-android`'s built-in mechanisms with appropriate configuration (e.g., normalized caching) whenever feasible.

