# Attack Surface Analysis for apollographql/apollo-client

## Attack Surface: [Client-Side Query Injection](./attack_surfaces/client-side_query_injection.md)

*   **Description:** Vulnerability where user-controlled input is directly embedded into GraphQL query strings without proper sanitization or parameterization, allowing attackers to manipulate the query structure and potentially gain unauthorized access or cause harm.
*   **Apollo Client Contribution:** Apollo Client is used to construct and send GraphQL queries from the client-side. Incorrect handling of user input when building queries using Apollo Client directly leads to this vulnerability.
*   **Example:**  A search feature where user input is directly concatenated into a GraphQL query string, allowing an attacker to inject malicious GraphQL syntax.
*   **Impact:**
    *   Data Breach: Unauthorized access to sensitive data.
    *   Authorization Bypass: Circumventing access control mechanisms.
    *   Denial of Service (DoS): Crafting complex queries to overload the server.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use GraphQL Variables:**  Always use GraphQL variables provided by Apollo Client to parameterize queries and separate user input from the query structure.
    *   **Server-Side Input Validation:** Implement robust input validation and sanitization on the GraphQL server as a secondary defense layer.

## Attack Surface: [Cache Poisoning](./attack_surfaces/cache_poisoning.md)

*   **Description:** Attackers manipulate data in the Apollo Client cache, causing users to receive incorrect or malicious data, potentially leading to information disclosure, application malfunction, or client-side XSS if rendered unsafely.
*   **Apollo Client Contribution:** Apollo Client's caching mechanisms (`InMemoryCache`) store GraphQL responses. Vulnerabilities in network communication or server response handling, combined with Apollo Client's caching, can lead to cache poisoning.
*   **Example:** An attacker intercepts network traffic and modifies a GraphQL response before it reaches Apollo Client. This modified response, containing malicious data, is cached by Apollo Client and served to subsequent users.
*   **Impact:**
    *   Information Disclosure: Displaying incorrect or manipulated data to users.
    *   Application Malfunction: Application logic breaks due to unexpected cached data.
    *   Client-Side XSS: If poisoned data contains malicious scripts and is rendered without proper sanitization in the application.
*   **Risk Severity:** High (due to potential for XSS and information disclosure)
*   **Mitigation Strategies:**
    *   **Enforce HTTPS:** Use HTTPS for all communication to prevent Man-in-the-Middle attacks that can facilitate cache poisoning.
    *   **Server-Side Data Validation:** Implement robust server-side data validation to ensure only valid and expected data is returned, reducing the risk of caching malicious server responses.
    *   **Proper Cache Configuration:** Carefully configure Apollo Client's cache policies to control caching behavior and minimize the window for caching potentially manipulated data.
    *   **Output Encoding/Sanitization:**  Always properly encode or sanitize data retrieved from the cache before rendering it in the UI to prevent XSS, even if cache poisoning occurs.

## Attack Surface: [Man-in-the-Middle (MitM) Attacks (HTTP vs. HTTPS)](./attack_surfaces/man-in-the-middle__mitm__attacks__http_vs__https_.md)

*   **Description:** Attackers intercept network communication between Apollo Client and the GraphQL server when HTTP is used instead of HTTPS, allowing them to eavesdrop on or modify data in transit.
*   **Apollo Client Contribution:** Apollo Client handles network communication. Configuring Apollo Client to use HTTP directly exposes the application to MitM attacks.
*   **Example:** Apollo Client is configured to connect to the GraphQL server using `http://api.example.com`. An attacker on the network intercepts the HTTP traffic and reads or modifies sensitive GraphQL queries and responses.
*   **Impact:**
    *   Data Breach: Exposure of sensitive data transmitted in GraphQL queries and responses.
    *   Authentication Bypass: Interception of authentication tokens.
    *   Data Manipulation: Modifying requests and responses, potentially leading to unauthorized actions.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Enforce HTTPS:** **Always use HTTPS** for all communication between Apollo Client and the GraphQL server. Configure Apollo Client to connect using `https://` URLs.
    *   **HSTS (HTTP Strict Transport Security):** Implement HSTS on the server to force browsers to always use HTTPS.

## Attack Surface: [Insecure WebSocket Connections (for Subscriptions)](./attack_surfaces/insecure_websocket_connections__for_subscriptions_.md)

*   **Description:** If GraphQL subscriptions are used via WebSockets and connections are not secured (WSS), attackers can intercept subscription data.
*   **Apollo Client Contribution:** Apollo Client manages WebSocket connections for GraphQL subscriptions. Using insecure WebSocket connections (`ws://`) directly exposes subscription data to interception.
*   **Example:** Apollo Client connects to a GraphQL subscription endpoint using `ws://subscriptions.example.com`. An attacker intercepts the WebSocket traffic and eavesdrops on real-time data being streamed through the subscription.
*   **Impact:**
    *   Data Breach: Exposure of real-time subscription data.
    *   Data Manipulation (Potentially): Depending on server-side implementation, attackers might attempt to inject malicious messages.
*   **Risk Severity:** High (due to potential for real-time data breach)
*   **Mitigation Strategies:**
    *   **Use WSS:** **Always use WSS** (WebSocket Secure) for WebSocket connections to encrypt communication. Configure Apollo Client to connect to subscription endpoints using `wss://` URLs.
    *   **Origin Validation:** Implement robust origin validation on both client and server for WebSocket connections.

## Attack Surface: [Exposure of Sensitive Headers in Network Requests](./attack_surfaces/exposure_of_sensitive_headers_in_network_requests.md)

*   **Description:** Sensitive information (API keys, secrets, authentication tokens in incorrect headers) is inadvertently included in HTTP headers sent by Apollo Client, potentially exposing it to logging or interception.
*   **Apollo Client Contribution:** Apollo Client allows configuration of HTTP headers for requests. Misconfiguration when setting headers in Apollo Client can lead to unintentional exposure of sensitive information.
*   **Example:** A developer mistakenly includes an API key directly in a custom header configuration within Apollo Client, causing it to be sent with every GraphQL request and potentially logged by intermediaries.
*   **Impact:**
    *   Credential Leakage: Exposure of API keys, secrets, or authentication tokens.
    *   Information Disclosure: Leakage of potentially sensitive information in headers.
*   **Risk Severity:** High (if critical credentials or sensitive data are exposed)
*   **Mitigation Strategies:**
    *   **Minimize Header Usage:** Review and minimize headers sent by Apollo Client. Only include necessary headers.
    *   **Secure Credential Management:** **Never hardcode sensitive credentials** in client-side code or headers. Use secure methods for managing and passing authentication tokens (e.g., Authorization header with Bearer tokens).
    *   **Environment Variables/Configuration:** Use environment variables or secure configuration mechanisms to manage API keys and sensitive configuration, avoiding direct embedding in code.

