# Attack Surface Analysis for hyperium/hyper

## Attack Surface: [1. Request Smuggling/Splitting (HTTP/1.1)](./attack_surfaces/1__request_smugglingsplitting__http1_1_.md)

*Description:* Exploitation of ambiguities in how `hyper` interprets HTTP/1.1 headers like `Transfer-Encoding` and `Content-Length`. Attackers craft requests processed differently by `hyper` and downstream systems.
*   *How Hyper Contributes:* `hyper`'s parsing and handling of these headers are the *direct* source of this vulnerability.
*   *Example:* An attacker sends a request with conflicting `Transfer-Encoding` and `Content-Length` headers, leading to `hyper` misinterpreting the request boundary.
*   *Impact:* Bypass security controls, access unauthorized data, execute arbitrary requests, poison caches.
*   *Risk Severity:* **Critical**
*   *Mitigation Strategies:*
    *   **Update `hyper`:** Use the latest version.
    *   **Fuzz Testing:** Extensively fuzz test `hyper`'s handling of `Transfer-Encoding`, `Content-Length`, and chunked encoding.
    *   **Proxy Configuration (Indirect):** While not *directly* `hyper`, ensure consistent proxy handling. Prefer HTTP/2.
    *   **WAF (with caution):** Can help, but *do not rely solely on it*.

## Attack Surface: [2. HTTP/2 Frame Handling Vulnerabilities](./attack_surfaces/2__http2_frame_handling_vulnerabilities.md)

*Description:* Flaws in `hyper`'s processing of HTTP/2 frames (HEADERS, DATA, SETTINGS, etc.) leading to DoS, information leaks, or potentially RCE.
*   *How Hyper Contributes:* `hyper`'s core functionality is the *direct* implementation of HTTP/2 frame handling.
*   *Example:* An attacker sends a malformed `HEADERS` frame causing `hyper` to crash or enter an infinite loop.
*   *Impact:* Denial-of-service (most likely), information disclosure, potential remote code execution (less likely).
*   *Risk Severity:* **High**
*   *Mitigation Strategies:*
    *   **Update `hyper`:** Prioritize updates addressing HTTP/2 vulnerabilities.
    *   **Extensive Fuzzing:** Fuzz test the HTTP/2 frame handling extensively.
    *   **Resource Monitoring:** Monitor CPU and memory usage.
    *   **Rate Limiting:** Implement connection-level rate limiting.

## Attack Surface: [3. HPACK Bomb (HTTP/2 Header Compression)](./attack_surfaces/3__hpack_bomb__http2_header_compression_.md)

*Description:* Attackers send requests with highly compressed headers that expand to consume excessive memory, causing a denial-of-service.
*   *How Hyper Contributes:* `hyper`'s HPACK decompression implementation is *directly* responsible.
*   *Example:* A crafted request with a HPACK header expands to consume gigabytes of memory.
*   *Impact:* Denial-of-service due to memory exhaustion.
*   *Risk Severity:* **High**
*   *Mitigation Strategies:*
    *   **Configure Header Limits:** Use `hyper`'s API to set appropriate limits on header list size (`max_header_list_size()`).
    *   **Memory Monitoring:** Monitor server memory usage.

