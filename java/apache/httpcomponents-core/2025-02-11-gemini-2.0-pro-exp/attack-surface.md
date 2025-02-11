# Attack Surface Analysis for apache/httpcomponents-core

## Attack Surface: [1. Request Smuggling/Splitting](./attack_surfaces/1__request_smugglingsplitting.md)

*Description:* Exploitation of discrepancies in how HTTP requests with ambiguous `Transfer-Encoding`, `Content-Length`, or chunked encoding are handled.  This focuses on HttpCore's *own* parsing and handling, not just its interaction with other components.
*HttpComponents-Core Contribution:* HttpCore's internal parsing logic for `Transfer-Encoding`, `Content-Length`, and chunked encoding is the direct source of the vulnerability if it deviates from strict RFC compliance or has subtle bugs in edge-case handling.
*Example:* A bug in HttpCore's chunked encoding parser allows an attacker to craft a request that bypasses length checks, leading to the injection of a second, malicious request. This is distinct from a front-end/back-end discrepancy; it's a flaw *within* HttpCore itself.
*Impact:* Allows attackers to bypass security controls, access unauthorized resources, poison caches, and potentially gain control of the application.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Update:** Use the *absolute latest* patched version of HttpComponents Core. Prioritize updates addressing CVEs related to request parsing and handling.
    *   **Configuration (HttpCore):** Configure HttpCore to be as strict as possible in rejecting ambiguous or malformed requests. Examine configuration options for strict RFC compliance and header validation. Enable any available strict parsing modes. This is crucial for mitigating *internal* parsing issues.
    *   **Fuzz Testing:** Conduct fuzz testing specifically targeting HttpCore's request parsing functionality with malformed and edge-case inputs to identify potential vulnerabilities.
    * **Code Review:** Manually review the relevant sections of HttpCore's source code (if accessible) that handle request parsing, looking for potential vulnerabilities.

## Attack Surface: [2. HTTP/2-Specific Vulnerabilities (if using HTTP/2)](./attack_surfaces/2__http2-specific_vulnerabilities__if_using_http2_.md)

*Description:* Exploitation of vulnerabilities specific to the HTTP/2 protocol, such as HPACK bombing (header compression attacks), stream multiplexing issues, and flow control errors. This focuses on HttpCore's *own* HTTP/2 implementation.
*HttpComponents-Core Contribution:* HttpCore's internal implementation of the HTTP/2 protocol, including header compression (HPACK), stream management, and flow control, is the direct attack surface.
*Example:* A flaw in HttpCore's HPACK decompression logic allows an attacker to send a crafted request that causes excessive memory allocation, leading to a denial-of-service attack. This is a vulnerability *within* HttpCore's HTTP/2 implementation.
*Impact:* Denial of service (DoS), potentially leading to application crashes or instability.
*Risk Severity:* **High** (if HTTP/2 is used)
*Mitigation Strategies:*
    *   **Update:** Use the *very latest* patched version of HttpComponents Core, prioritizing updates that address HTTP/2-related CVEs.
    *   **Configuration (HttpCore):** Carefully review and configure HttpCore's HTTP/2 settings:
        *   `MaxHeaderListSize`:  Set a *strict* limit on the maximum size of the header list.
        *   `MaxConcurrentStreams`:  Limit the maximum number of concurrent streams to a reasonable value.
        *   `InitialWindowSize`:  Configure appropriate flow control window sizes to prevent resource exhaustion.
    *   **Fuzz Testing:** Perform fuzz testing specifically targeting HttpCore's HTTP/2 implementation with various malformed and edge-case inputs.
    * **Code Review:** If source code is available, review the HTTP/2 implementation for potential vulnerabilities.

## Attack Surface: [3. Connection Pool Exhaustion (DoS) - *Specific HttpCore Misconfiguration*](./attack_surfaces/3__connection_pool_exhaustion__dos__-_specific_httpcore_misconfiguration.md)

*Description:*  An attacker exhausts HttpCore's *internal* connection pool due to misconfiguration, leading to DoS. This is distinct from general connection exhaustion; it's about the *pool itself* being misconfigured.
*HttpComponents-Core Contribution:*  HttpCore's connection pool and its configuration parameters (`MaxTotalConnections`, `MaxConnectionsPerRoute`) are directly responsible.  The vulnerability arises from setting these values *too high* relative to the system's capabilities.
*Example:*  `MaxTotalConnections` is set to an extremely large value (e.g., 100,000) on a system that can only handle a few thousand concurrent connections.  Even a moderate number of legitimate requests could exhaust the pool and prevent further connections. This is *not* about an external attacker; it's about the *internal* limit being too high.
*Impact:*  Denial of service (DoS) due to HttpCore's internal resource limits being exceeded.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Tune Connection Pool Parameters:**  Carefully configure `MaxTotalConnections` and `MaxConnectionsPerRoute` to *realistic* values based on thorough testing and system resource monitoring.  Start with *conservative* values and increase them *only if necessary* and with careful monitoring.  Do *not* use excessively large values.
    *   **Monitoring (HttpCore Specific):**  If HttpCore provides metrics or logging for its connection pool (e.g., number of active connections, number of idle connections, number of pending requests), monitor these *closely* to detect exhaustion or near-exhaustion conditions.
    * **Stress Testing:** Perform stress testing to determine the *actual* limits of the system and HttpCore's connection pool under realistic load conditions.

