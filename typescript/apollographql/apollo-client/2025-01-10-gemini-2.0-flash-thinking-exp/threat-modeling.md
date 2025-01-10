# Threat Model Analysis for apollographql/apollo-client

## Threat: [Cache Poisoning](./threats/cache_poisoning.md)

**Description:** An attacker could compromise the GraphQL server or a network intermediary to inject crafted, harmful data into the Apollo Client's `InMemoryCache`. When the application retrieves this cached data, it could lead to incorrect information being displayed, application errors, or even client-side vulnerabilities if the data is interpreted as code. This directly involves how Apollo Client manages and retrieves data from its cache.

**Impact:** Display of false information, application malfunction, potential client-side code execution (if the poisoned data is used in a vulnerable way).

**Affected Apollo Client Component:** `InMemoryCache`

**Risk Severity:** High

**Mitigation Strategies:**
* Implement robust server-side data validation and sanitization.
* Utilize cache directives from the server to control what is cached and for how long.
* Implement client-side data validation after fetching from the cache.
* Consider using a Content Security Policy (CSP) to mitigate potential script injection from poisoned data.

## Threat: [Exposure of Sensitive Data in Cache](./threats/exposure_of_sensitive_data_in_cache.md)

**Description:** An attacker with access to the user's browser (e.g., through malware or physical access) could potentially access sensitive data stored in the Apollo Client's `InMemoryCache` (which can persist in local storage or session storage depending on configuration). This is a direct consequence of how Apollo Client stores cached data.

**Impact:** Disclosure of sensitive user data, potential for identity theft or unauthorized access to accounts if authentication tokens are also cached insecurely.

**Affected Apollo Client Component:** `InMemoryCache`, potentially storage adapters

**Risk Severity:** High

**Mitigation Strategies:**
* Avoid caching highly sensitive data if possible.
* If caching is necessary, consider encrypting the cache data.
* Implement appropriate security measures on the user's device to prevent unauthorized access.
* Be mindful of what data is included in GraphQL responses and avoid sending unnecessary sensitive information.

## Threat: [Man-in-the-Middle (MITM) Attacks on GraphQL Requests](./threats/man-in-the-middle__mitm__attacks_on_graphql_requests.md)

**Description:** An attacker intercepting network traffic between the client and the GraphQL server could potentially eavesdrop on or modify GraphQL requests and responses if HTTPS is not properly implemented or if the client trusts invalid certificates. Apollo Client's `HttpLink` is responsible for making these network requests, making it directly involved.

**Impact:** Data breaches, unauthorized access, manipulation of application data and behavior.

**Affected Apollo Client Component:** `HttpLink`, `WebSocketLink` (for subscriptions)

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Enforce HTTPS:** Ensure all communication with the GraphQL server uses HTTPS with a valid TLS certificate.
* **Implement Certificate Pinning (Advanced):**  For highly sensitive applications, consider implementing certificate pinning to prevent MITM attacks using forged certificates.
* Educate users about the importance of avoiding untrusted networks.

## Threat: [Subscription Hijacking (if using GraphQL Subscriptions)](./threats/subscription_hijacking__if_using_graphql_subscriptions_.md)

**Description:** An attacker could potentially subscribe to GraphQL data streams they are not authorized to access if proper authorization checks are not implemented on the server-side for subscription requests. Apollo Client's `WebSocketLink` handles the subscription connection, making it directly relevant.

**Impact:** Unauthorized access to real-time data, potential for information leakage or manipulation.

**Affected Apollo Client Component:** `WebSocketLink`, components using `useSubscription`.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement robust authentication and authorization checks on the GraphQL server for subscription requests.
* Secure the WebSocket connection used for subscriptions (WSS).
* Validate the user's permissions on the server for each subscription event.

## Threat: [Insecure Storage of Authentication Tokens](./threats/insecure_storage_of_authentication_tokens.md)

**Description:** Apollo Client often handles authentication tokens (e.g., JWTs) used to authenticate with the GraphQL server. Storing these tokens insecurely (e.g., in local storage without proper precautions) can make them vulnerable to theft through client-side attacks like XSS. This is directly related to how authentication is managed within the application using Apollo Client to interact with the backend.

**Impact:** Unauthorized access to user accounts and data.

**Affected Apollo Client Component:**  Components handling authentication headers or state management related to authentication (e.g., custom links, state management libraries integrated with Apollo Client).

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Use HTTP-only cookies with the `Secure` attribute:** This is the most secure way to store authentication tokens in the browser, as they are not accessible to JavaScript.
* **Consider using refresh tokens:** Implement a refresh token mechanism to minimize the lifespan of access tokens and reduce the impact of token compromise.
* If local storage or session storage is used, implement additional security measures like encryption (though this can be complex and may not fully mitigate the risk).

