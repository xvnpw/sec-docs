# Mitigation Strategies Analysis for hyperium/hyper

## Mitigation Strategy: [Implement Robust Stream ID Management and Error Handling (HTTP/2)](./mitigation_strategies/implement_robust_stream_id_management_and_error_handling__http2_.md)

*   **Mitigation Strategy:** Implement Robust Stream ID Management and Error Handling (HTTP/2)

    *   **Description:**
        1.  **`stream_timeout` Configuration:** Use `hyper::client::conn::http2::Builder::stream_timeout` (for clients) and `hyper::server::conn::http2::Builder::stream_timeout` (for servers) to set a maximum duration for individual HTTP/2 streams.  This is a *direct* use of `hyper`'s API to control stream lifecycle.  Choose a value appropriate for your application's expected response times (e.g., 30 seconds, but adjust as needed).
        2.  **`RST_STREAM` Handling:** Within your `hyper` request/response handling logic (where you interact with `hyper::Request` and `hyper::Response` objects), explicitly handle `RST_STREAM` errors.  `hyper` will surface these errors through its error types.  When you encounter a `RST_STREAM`, ensure you release any resources associated with that stream. This is crucial because `hyper` itself manages the stream state, and you need to react to its signals.
        3.  **`max_concurrent_streams` Configuration:** Use `hyper::server::conn::http2::Builder::max_concurrent_streams` (server) or the client-side equivalent to limit the maximum number of concurrent streams allowed on a single HTTP/2 connection.  This is a *direct* `hyper` configuration setting to prevent resource exhaustion.  Start with a conservative value (e.g., 100) and adjust based on your server's capacity.

    *   **Threats Mitigated:**
        *   **Stream ID Exhaustion (DoS):** (Severity: High) - `hyper`'s stream management is directly involved; this prevents exhaustion of `hyper`-managed stream IDs.
        *   **Resource Leaks from Abandoned Streams:** (Severity: Medium) - Ensures resources are released when `hyper` signals a stream closure.
        *   **Slow Stream Attacks:** (Severity: Medium) - `hyper`'s timeouts directly mitigate this.

    *   **Impact:**
        *   **Stream ID Exhaustion:** Risk reduced significantly (from High to Low).
        *   **Resource Leaks:** Risk reduced significantly (from Medium to Low).
        *   **Slow Stream Attacks:** Risk reduced significantly (from Medium to Low).

    *   **Currently Implemented:**
        *   Stream timeouts are configured in `src/server.rs` using `hyper::server::conn::http2::Builder::stream_timeout`.

    *   **Missing Implementation:**
        *   `max_concurrent_streams` is not explicitly set.
        *   More robust `RST_STREAM` error handling within the request/response processing logic is needed.

## Mitigation Strategy: [Limit Decoded Header Size (HTTP/2)](./mitigation_strategies/limit_decoded_header_size__http2_.md)

*   **Mitigation Strategy:** Limit Decoded Header Size (HTTP/2)

    *   **Description:**
        1.  **`max_header_list_size` Configuration:** Use `hyper::server::conn::http2::Builder::max_header_list_size` (for servers) and `hyper::client::conn::http2::Builder::max_header_list_size` (for clients) to set a maximum size for the *decoded* header list. This is a *direct* configuration of `hyper`'s HPACK decoder.  Choose a value based on expected header sizes (e.g., 8KB or 16KB).
        2.  **Error Handling:**  `hyper` will return an error if this limit is exceeded.  Your application code, when interacting with `hyper`, must handle this error gracefully.  Return an appropriate HTTP error response (e.g., 431 Request Header Fields Too Large).

    *   **Threats Mitigated:**
        *   **HPACK Bomb (DoS):** (Severity: High) - Directly controls `hyper`'s HPACK decoding limits.
        *   **Large Header Attacks:** (Severity: Medium) - Limits the size of headers processed by `hyper`.

    *   **Impact:**
        *   **HPACK Bomb:** Risk reduced significantly (from High to Low).
        *   **Large Header Attacks:** Risk reduced significantly (from Medium to Low).

    *   **Currently Implemented:**
        *   `max_header_list_size` is set to 8KB in `src/server.rs` for the server.

    *   **Missing Implementation:**
        *   The client-side `max_header_list_size` is not explicitly configured.

## Mitigation Strategy: [Implement Request and Response Timeouts (HTTP/1)](./mitigation_strategies/implement_request_and_response_timeouts__http1_.md)

*   **Mitigation Strategy:** Implement Request and Response Timeouts (HTTP/1)

    *   **Description:**
        1.  **`read_timeout` Configuration:** For HTTP/1 servers, use `hyper::server::conn::http1::Builder::read_timeout` to set a maximum time for `hyper` to read the entire request from the client. This is a *direct* setting for `hyper`'s connection handling.
        2.  **`write_timeout` Configuration:** For HTTP/1 servers, use `hyper::server::conn::http1::Builder::write_timeout` to set a maximum time for `hyper` to send the entire response.  Another *direct* `hyper` setting.
        3.  **Client-Side Timeout:** For `hyper` clients, use `hyper::Client::builder().timeout()` to set an overall timeout for the entire request/response cycle. This controls how long `hyper` will wait for the entire operation.
        4.  **Error Handling:**  `hyper` will return timeout errors.  Your application code, when using `hyper`, must handle these errors and return appropriate HTTP responses (e.g., 408 or 504).

    *   **Threats Mitigated:**
        *   **Slowloris Attacks (DoS):** (Severity: High) - `hyper`'s timeouts directly prevent slow connections from holding resources.
        *   **Slow Read/Write Attacks:** (Severity: Medium) - `hyper`'s timeouts protect against slow network conditions.
        *   **Resource Exhaustion:** (Severity: Medium) - `hyper`'s timeouts prevent indefinite resource consumption.

    *   **Impact:**
        *   **Slowloris Attacks:** Risk reduced significantly (from High to Low).
        *   **Slow Read/Write Attacks:** Risk reduced significantly (from Medium to Low).
        *   **Resource Exhaustion:** Risk reduced significantly (from Medium to Low).

    *   **Currently Implemented:**
        *   `read_timeout` and `write_timeout` are set in `src/server.rs` for HTTP/1 connections.
        *   Client-side timeout is set in `src/client.rs`.

    *   **Missing Implementation:**
        *   None, assuming the existing timeouts are appropriately chosen and error handling is present.

