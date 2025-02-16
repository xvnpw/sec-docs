# Threat Model Analysis for hyperium/hyper

## Threat: [Threat: Request Smuggling via Chunked Encoding Mishandling](./threats/threat_request_smuggling_via_chunked_encoding_mishandling.md)

*   **Description:** An attacker sends a maliciously crafted HTTP request with `Transfer-Encoding: chunked` that contains ambiguous or malformed chunk sizes or terminators. The attacker aims to cause a discrepancy in how the frontend (if any) and the Hyper-based backend interpret the request boundaries. This allows the attacker to "smuggle" a second, hidden request within the first.
*   **Impact:**  Bypass security controls, access unauthorized resources, poison web caches, hijack user sessions, potentially leading to complete application compromise and data breaches.
*   **Hyper Component Affected:**
    *   `hyper::proto::h1::io::DecodedLength::Chunked` (and related parsing logic within `hyper::proto::h1::decode`). The core parsing logic for chunked encoding.
    *   Any code manually handling `Transfer-Encoding` headers without using Hyper's built-in parsing (highly discouraged).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strongly Prefer Higher-Level Frameworks:** Use frameworks like Axum or Actix-web, which have more robust and battle-tested handling of chunked encoding. This is the *best* mitigation.
    *   **Strict Validation (If Using Raw Hyper):** If using Hyper directly (not recommended for this reason), *rigorously* validate all chunk sizes and terminators against the RFC specifications. Reject *any* ambiguous or malformed requests. This is difficult to get right.
    *   **Web Application Firewall (WAF):** Employ a WAF with specific rules to detect and block request smuggling attempts. This is a defense-in-depth measure.

## Threat: [Threat: Header Injection via Unvalidated Input (within Hyper's context)](./threats/threat_header_injection_via_unvalidated_input__within_hyper's_context_.md)

*   **Description:** While header injection is often an application-level vulnerability, if the application uses user-provided data *directly* to construct `hyper::header::HeaderMap` objects without proper sanitization, Hyper's internal representation of headers becomes the attack surface. The attacker injects malicious header values.
*   **Impact:**  Can influence Hyper's internal processing, potentially leading to misrouting of requests, bypassing security checks based on headers, or triggering unexpected behavior within Hyper itself. The specific impact depends on which headers are injected and how Hyper uses them.
*   **Hyper Component Affected:**
    *   `hyper::header` module (specifically, any code that constructs `HeaderMap` objects from unsanitized user input).
    *   Any custom code that manually parses or constructs HTTP headers and then passes them to Hyper.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Sanitize Input Before Using with `hyper::header`:** *Always* sanitize and validate user-provided input *before* using it to construct any `HeaderMap` or individual header values. Use a whitelist approach.
    *   **Use Typed Headers:** Prefer Hyper's typed header API (e.g., `hyper::header::Host`, `hyper::header::ContentType`) which provide *some* built-in validation, but *do not rely on them alone for security*.
    *   **Avoid Direct Raw Header Manipulation:** Minimize direct manipulation of raw header strings. Let Hyper's API handle the formatting and encoding.

## Threat: [Threat: Resource Exhaustion via Slowloris Attack (targeting Hyper's connection handling)](./threats/threat_resource_exhaustion_via_slowloris_attack__targeting_hyper's_connection_handling_.md)

*   **Description:** An attacker establishes numerous HTTP connections and sends only partial HTTP requests very slowly. The goal is to tie up Hyper's connection handling resources, preventing legitimate clients from connecting.
*   **Impact:**  Denial-of-service (DoS). The Hyper-based server becomes unresponsive.
*   **Hyper Component Affected:**
    *   `hyper::server::conn` (connection handling and timeout mechanisms).
    *   `hyper::proto::h1::io` (I/O handling for HTTP/1.x connections).
    *   Indirectly, the underlying Tokio runtime, as it manages the asynchronous tasks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Aggressive Timeouts:** Implement *short* timeouts for both reading and writing data on connections using `hyper::server::conn::Builder::http1_read_timeout` and `hyper::server::conn::Builder::http1_write_timeout`. This is crucial.
    *   **Connection Limits (Within Hyper or Externally):** Limit the maximum number of concurrent connections. This can be done within Hyper's configuration or via an external load balancer.
    *   **Rate Limiting (Ideally External):** Implement rate limiting, preferably at a layer *before* the Hyper server (e.g., a reverse proxy or load balancer).

## Threat: [Threat: HPACK Bomb (HTTP/2 Header Compression Bomb)](./threats/threat_hpack_bomb__http2_header_compression_bomb_.md)

*   **Description:** An attacker sends a crafted HTTP/2 request with compressed headers designed to expand to a very large size upon decompression, consuming excessive CPU and memory within Hyper's HTTP/2 processing.
*   **Impact:**  Denial-of-service (DoS) due to resource exhaustion.
*   **Hyper Component Affected:**
    *   `hyper::proto::h2` (specifically, the HPACK decoding logic).
    *   The `hpack` crate (which Hyper uses for HPACK).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Header Size Limits:** Configure *strict* limits on the maximum size of decompressed HTTP/2 headers using `hyper::server::conn::Builder::max_header_list_size`. Review and adjust these limits carefully.
    *   **Resource Monitoring:** Monitor CPU and memory usage to detect potential HPACK bomb attacks.
    *   **Web Application Firewall (WAF):** Use a WAF that understands HTTP/2 and can detect/mitigate HPACK bombs.

