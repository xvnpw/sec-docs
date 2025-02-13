# Threat Model Analysis for apollographql/apollo-android

## Threat: [Persisted Query ID Guessing (with Client-Side ID Generation)](./threats/persisted_query_id_guessing__with_client-side_id_generation_.md)

*   **Description:** An attacker exploits a weak or predictable client-side persisted query ID generation algorithm in `apollo-android` to guess valid IDs and access data without knowing the full query. This specifically targets scenarios where the *client* is responsible for generating the ID.
    *   **Impact:** Unauthorized access to data returned by the persisted query. Data exposure, potential privacy violations.
    *   **Affected Component:** `apollo-android`'s persisted query feature, specifically any custom code or configuration related to *client-side* ID generation (e.g., custom implementations of `PersistedQueryInterceptor` or related logic).
    *   **Risk Severity:** High (if client-side ID generation is used and is weak).
    *   **Mitigation Strategies:**
        *   **Strongly Avoid Client-Side ID Generation:** This is the most crucial mitigation. Let the server generate and manage persisted query IDs. This eliminates the client-side vulnerability.
        *   **If Client-Side Generation is Absolutely Unavoidable (Not Recommended):** Use a cryptographically secure hash function (e.g., SHA-256) with a large, randomly generated, and *secret* salt. The salt must be kept confidential and not be predictable. This is significantly harder to implement securely than server-side generation.
        *   **Backend Authorization is Still Essential:** Even with strong client-side ID generation, the backend *must* still authorize access based on the ID and user context.

## Threat: [Cache Poisoning via Malicious Response (with Misconfigured HTTPS)](./threats/cache_poisoning_via_malicious_response__with_misconfigured_https_.md)

*   **Description:** An attacker intercepts a GraphQL response and modifies it before it reaches the `apollo-android` client. This is facilitated by a *misconfiguration* of HTTPS in the client (e.g., disabling certificate validation, trusting a custom CA), allowing a Man-in-the-Middle (MitM) attack. The modified response is then stored in the `apollo-android` cache.
    *   **Impact:** The application displays incorrect or malicious data, potentially leading to incorrect behavior, data corruption, or even execution of malicious code (if the cached data is used in a vulnerable way).
    *   **Affected Component:** `apollo-android`'s caching mechanism (e.g., `NormalizedCacheFactory`, `ApolloClient`'s cache interaction) *in conjunction with* a misconfigured `HttpEngine` or network settings that allow MitM attacks.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   **Strict HTTPS Enforcement:** Ensure HTTPS is properly configured and *strictly enforced*. Do *not* disable certificate validation.
        *   **Certificate Pinning:** Implement certificate pinning within the `apollo-android` client to further protect against MitM attacks, even if a CA is compromised. Apollo Android supports this. This is a crucial mitigation.
        *   **Data Validation After Cache Retrieval:** Validate data retrieved from the cache *before* using it, especially for security-sensitive operations.
        *   **Secure Cache Storage:** If the cache contains sensitive data, use a secure storage mechanism.

## Threat: [Subscription Hijacking (WebSocket, with Misconfigured Security)](./threats/subscription_hijacking__websocket__with_misconfigured_security_.md)

*   **Description:** An attacker intercepts or takes over the WebSocket connection used for GraphQL subscriptions due to *misconfigured security* on the client-side (e.g., using insecure WebSockets (WS) instead of WSS, or failing to properly authenticate the connection).
    *   **Impact:** Unauthorized access to real-time data, potential for data manipulation or injection of malicious data into the application.
    *   **Affected Component:** `apollo-android`'s subscription handling, specifically the WebSocket connection management (e.g., classes related to `SubscriptionNetworkTransport`, WebSocket connection setup and configuration).
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   **Mandatory Secure WebSockets (WSS):**  *Always* use WSS (secure WebSockets) with TLS encryption. Never use plain WS.
        *   **Client-Side Authentication:** Ensure the `apollo-android` client sends appropriate authentication tokens (e.g., JWTs) when establishing the WebSocket connection, even if the backend handles authorization. This provides an additional layer of defense.
        *   **Proper WebSocket Configuration:** Carefully review and configure the WebSocket connection settings within `apollo-android` to ensure they are secure.

## Threat: [Unauthorized Mutation Execution (Client-Side Bypass)](./threats/unauthorized_mutation_execution__client-side_bypass_.md)

*   **Description:** While primarily a backend concern, if the `apollo-android` client has flaws that allow bypassing client-side checks (e.g., incorrect handling of authentication tokens, vulnerabilities in custom interceptors), an attacker might be able to send unauthorized mutation requests. This focuses on vulnerabilities *within the client's logic* that could facilitate the attack.
    *   **Impact:** Data modification, deletion, or corruption. Potential for significant data loss or system compromise.
    *   **Affected Component:** `apollo-android`'s mutation execution mechanism (e.g., `ApolloCall`, `ApolloClient`), and *especially* any custom interceptors or authentication logic implemented within the client.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Secure Authentication Handling:** Ensure the `apollo-android` client correctly handles authentication tokens and securely transmits them with mutation requests.
        *   **Careful Interceptor Implementation:** If using custom interceptors, thoroughly review them for security vulnerabilities. Ensure they don't inadvertently bypass security checks.
        *   **Regular Code Reviews:** Conduct regular security-focused code reviews of the client-side code, paying close attention to how mutations are handled and how authentication is integrated.
        * **Rely on Backend Authorization (Primary Defense):** The backend *must* be the primary enforcement point for authorization. Client-side checks are a secondary layer of defense.

## Threat: [`apollo-android` Library Vulnerability (Direct Exploitation)](./threats/_apollo-android__library_vulnerability__direct_exploitation_.md)

*   **Description:** A vulnerability is discovered *directly within* the `apollo-android` library itself (or a *directly used* dependency like OkHttp, *not* a transitive dependency several layers deep), allowing an attacker to exploit it. This is distinct from general application vulnerabilities.
    *   **Impact:** Varies depending on the vulnerability. Could range from denial of service to arbitrary code execution *within the context of the application*.
    *   **Affected Component:** Potentially any part of the `apollo-android` library or its *direct* dependencies.
    *   **Risk Severity:** Varies (High to Critical) depending on the specific vulnerability.
    *   **Mitigation Strategies:**
        *   **Immediate Updates:** Update the `apollo-android` library and its *direct* dependencies to the latest versions *immediately* upon the release of security patches.
        *   **Vulnerability Monitoring:** Actively monitor security advisories and vulnerability databases (e.g., CVE) for any reported issues related to `apollo-android` and its *direct* dependencies.
        *   **Dependency Analysis (Direct Dependencies):** Use dependency analysis tools, focusing on identifying vulnerabilities in the *direct* dependencies used by `apollo-android`.

