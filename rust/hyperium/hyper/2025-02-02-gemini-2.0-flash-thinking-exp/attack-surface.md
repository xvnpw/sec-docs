# Attack Surface Analysis for hyperium/hyper

## Attack Surface: [HTTP Request Smuggling/Splitting](./attack_surfaces/http_request_smugglingsplitting.md)

*   **Description:** Manipulating HTTP requests to cause discrepancies in request boundary interpretation between intermediaries and Hyper, leading to request smuggling or splitting. This exploits subtle vulnerabilities in Hyper's HTTP parsing and connection handling logic, especially in HTTP/1.1.
*   **Hyper Contribution:** Hyper's implementation of HTTP/1.1 connection handling and request parsing is directly involved. Bugs or oversights in how Hyper manages connection reuse or parses ambiguous requests can create smuggling vulnerabilities.
*   **Example:** Crafting a request with conflicting `Content-Length` and `Transfer-Encoding` headers that are parsed differently by a proxy and Hyper. This allows an attacker to inject a second, malicious request within the body of the first, which Hyper might process as a separate request.
*   **Impact:** Bypassing security controls, unauthorized access to resources, data leakage, cache poisoning, and potentially remote code execution in vulnerable backend applications.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Use HTTP/2 or HTTP/3:** Migrate to HTTP/2 or HTTP/3 as these protocols are inherently more resistant to request smuggling due to their framing mechanisms. Configure Hyper to use these protocols if possible.
    *   **Strict HTTP Parsing (Hyper Configuration):** Ensure Hyper is configured for strict HTTP parsing. While Hyper aims for correctness, review configuration options related to request parsing and ensure they are set to be as strict as possible to reject ambiguous requests.
    *   **Disable HTTP/1.1 Connection Reuse (If Necessary):** If request smuggling is a major concern and HTTP/2/3 migration is not immediately feasible, consider disabling HTTP/1.1 connection reuse in Hyper's configuration to reduce the attack surface, although this may impact performance.
    *   **Regular Security Audits:** Conduct regular security audits specifically focusing on HTTP request handling within the application and Hyper's configuration to identify and address potential smuggling vulnerabilities.

## Attack Surface: [Large Request Body Denial of Service (DoS)](./attack_surfaces/large_request_body_denial_of_service__dos_.md)

*   **Description:** Exploiting Hyper's handling of request bodies by sending excessively large payloads to exhaust server resources, leading to denial of service. This targets Hyper's resource management when processing incoming data.
*   **Hyper Contribution:** Hyper is responsible for receiving and processing request bodies. If not properly configured with limits, Hyper might allow processing of excessively large bodies, leading to resource exhaustion.
*   **Example:** Sending a POST request with an extremely large request body (e.g., multiple gigabytes) to an endpoint. If Hyper is not configured to limit body size, it might attempt to buffer or process this large body, leading to memory exhaustion or excessive processing time, causing a server crash or unresponsiveness.
*   **Impact:** Denial of Service (DoS), server unavailability, service disruption.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Limit Request Body Size (Hyper Configuration):**  **Crucially configure Hyper** to enforce strict limits on the maximum allowed request body size. Use Hyper's server builder and request body configuration options to set appropriate limits based on application needs and resource capacity.
    *   **Streaming Request Body Handling (Application Logic):**  Design application logic to handle request bodies in a streaming manner using Hyper's API, instead of buffering the entire body in memory. This reduces memory footprint and improves resilience against large body attacks.
    *   **Rate Limiting (Application or Infrastructure Level):** Implement rate limiting to restrict the number of requests from a single IP address or client within a given time frame. This can help mitigate the impact of rapid large body attacks by limiting the attack scale.

## Attack Surface: [HTTP/2 Stream Exhaustion Denial of Service (DoS)](./attack_surfaces/http2_stream_exhaustion_denial_of_service__dos_.md)

*   **Description:** In HTTP/2, attackers can exploit Hyper's HTTP/2 implementation by opening a large number of streams without sending data, exhausting server resources and causing denial of service. This targets Hyper's stream management in HTTP/2.
*   **Hyper Contribution:** Hyper implements HTTP/2 and manages stream limits. Misconfigurations or vulnerabilities in Hyper's HTTP/2 stream management directly contribute to this attack surface. Inadequate default stream limits or bugs in limit enforcement within Hyper can be exploited.
*   **Example:** An attacker rapidly opens the maximum allowed number of HTTP/2 streams to a Hyper server, consuming server resources (memory, connection tracking) without sending any data on those streams. This can prevent legitimate clients from establishing new connections or streams, leading to DoS.
*   **Impact:** Denial of Service (DoS), server unavailability, performance degradation for legitimate users.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Configure HTTP/2 Stream Limits (Hyper Configuration):** **Carefully configure Hyper's HTTP/2 settings** to set appropriate and restrictive limits on the maximum number of concurrent streams per connection. Adjust `max_concurrent_streams` and related settings in Hyper's HTTP/2 configuration.
    *   **Connection Limits (Hyper or Infrastructure Level):** Limit the total number of concurrent connections to the server. This indirectly limits the total number of streams an attacker can open across all connections. Configure connection limits in Hyper or at the infrastructure level (e.g., load balancer).
    *   **Resource Monitoring and Alerting:** Implement robust monitoring of server resource usage (CPU, memory, connections, stream counts) and set up alerts to detect and respond to potential stream exhaustion attacks in real-time.

## Attack Surface: [TLS/SSL Configuration Weaknesses (Hyper TLS Termination)](./attack_surfaces/tlsssl_configuration_weaknesses__hyper_tls_termination_.md)

*   **Description:** Misconfiguring TLS/SSL settings when Hyper is used for TLS termination, leading to weak encryption, outdated protocols, or improper certificate validation. This directly weakens the security of HTTPS connections handled by Hyper.
*   **Hyper Contribution:** Hyper provides the API and configuration options for setting up TLS using libraries like `rustls` or `openssl-sys`. Incorrect configuration choices made when using Hyper for TLS termination directly introduce vulnerabilities.
*   **Example:** Configuring Hyper to allow outdated TLS 1.0 or 1.1 protocols, or weak cipher suites. This makes connections vulnerable to downgrade attacks, eavesdropping, and man-in-the-middle attacks, compromising the confidentiality and integrity of data transmitted over HTTPS.
*   **Impact:** Eavesdropping, man-in-the-middle attacks, data breaches, loss of confidentiality and integrity of sensitive data.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strong TLS Configuration (Hyper Configuration):** **Configure Hyper to enforce strong and modern TLS settings.**  Specifically:
        *   **Use TLS 1.3 (or TLS 1.2 minimum):** Disable older, insecure TLS versions (TLS 1.0, TLS 1.1).
        *   **Select Secure Cipher Suites:**  Configure Hyper to use only strong and recommended cipher suites. Avoid weak or outdated ciphers like RC4, DES, or export ciphers. Prioritize forward secrecy cipher suites.
        *   **Enable HSTS (HTTP Strict Transport Security):** Configure Hyper to send HSTS headers to enforce HTTPS and prevent downgrade attacks.
    *   **Strict Certificate Validation (Hyper Configuration):** Ensure proper and strict certificate validation is enabled in Hyper's TLS configuration. Do not disable certificate validation unless absolutely necessary and with extreme caution. Use trusted certificate authorities and regularly renew certificates.
    *   **Regular Security Scans and Audits:** Periodically scan the application's HTTPS configuration using tools like SSL Labs' SSL Server Test to identify and remediate any TLS configuration weaknesses. Regularly audit Hyper's TLS configuration to ensure it aligns with security best practices.

