# Mitigation Strategies Analysis for yhirose/cpp-httplib

## Mitigation Strategy: [Internal Request Timeouts (cpp-httplib)](./mitigation_strategies/internal_request_timeouts__cpp-httplib_.md)

*   **Description:**
    1.  **Read Timeout:** Within your `cpp-httplib` server setup, use `svr.set_read_timeout(seconds, microseconds);`.  For example: `svr.set_read_timeout(5, 0);` (5-second read timeout). This limits the time the server will wait for data to be *received* from a client during a single read operation.
    2.  **Write Timeout:** Similarly, use `svr.set_write_timeout(seconds, microseconds);`. For example: `svr.set_write_timeout(2, 0);` (2-second write timeout). This limits the time the server will wait to *send* data to a client during a single write operation.
    3.  **Global Request Timeout (Custom, but using `cpp-httplib` connection):** Implement a timer (e.g., using `std::chrono` and `std::thread`) that starts when a request is received.  Within the request handler, periodically check if the total request processing time exceeds a threshold (e.g., 30 seconds). If it does, *forcibly close the `cpp-httplib` connection* using `res.close_connection = true;`. This is crucial, as it directly interacts with the library's connection management. This requires careful thread management to avoid race conditions.

*   **Threats Mitigated:**
    *   **Slowloris Attacks (High Severity):** Mitigates attacks where clients send data very slowly, tying up server resources. The `read_timeout` is particularly effective here.
    *   **General DoS - Resource Exhaustion (Medium Severity):** Prevents connections from lingering indefinitely if clients are unresponsive, by enforcing timeouts on read and write operations.
    *   **Hanging Connections (Medium Severity):** Addresses situations where network issues or client bugs cause connections to remain open but inactive.

*   **Impact:**
    *   **Slowloris:** Very effective at mitigating Slowloris attacks, especially with a well-tuned `read_timeout`. Risk reduction: High.
    *   **General DoS:** Reduces the impact of resource exhaustion. Risk reduction: Medium.
    *   **Hanging Connections:** Prevents resource leaks. Risk reduction: Medium.

*   **Currently Implemented:** Partially implemented. `svr.set_read_timeout()` and `svr.set_write_timeout()` are used, but the global request timeout (with `res.close_connection = true;`) is *not* implemented.

*   **Missing Implementation:** The global request timeout, which actively uses `cpp-httplib`'s `res.close_connection` to terminate long-running requests, is missing.

## Mitigation Strategy: [Internal Request Size Limits (cpp-httplib)](./mitigation_strategies/internal_request_size_limits__cpp-httplib_.md)

*   **Description:**
    1.  **Payload Max Length:** Use `svr.set_payload_max_length(max_size_in_bytes);` in your server setup.  For example: `svr.set_payload_max_length(1024 * 1024 * 10);` (10 MB limit). This directly configures `cpp-httplib` to reject requests with bodies larger than the specified limit.

*   **Threats Mitigated:**
    *   **Large Payload DoS (High Severity):** Prevents attackers from sending extremely large request bodies.
    *   **Buffer Overflow (Potentially High Severity):** Reduces the attack surface for potential buffer overflows within `cpp-httplib` or your application's handling of request data.
    *   **Resource Exhaustion (Medium Severity):** Limits the amount of memory `cpp-httplib` needs to allocate for request bodies.

*   **Impact:**
    *   **Large Payload DoS:** Highly effective. Risk reduction: High.
    *   **Buffer Overflow:** Reduces the risk. Risk reduction: Medium to High (depending on other vulnerabilities).
    *   **Resource Exhaustion:** Improves resource utilization. Risk reduction: Medium.

*   **Currently Implemented:** Implemented. `svr.set_payload_max_length()` is used in the server setup.

*   **Missing Implementation:**  While the main setting is implemented, consider if the chosen limit is appropriate for all use cases.  No further `cpp-httplib`-specific actions are missing.

## Mitigation Strategy: [Multipart Form Data Handling (within cpp-httplib callbacks)](./mitigation_strategies/multipart_form_data_handling__within_cpp-httplib_callbacks_.md)

*   **Description:**
    1.  **Per-File Size Limits (within Callbacks):** `cpp-httplib` provides callbacks for handling multipart data: `svr.set_multipart_form_data_handler(...)`.  Within this handler, you receive information about each part of the multipart data, including file uploads.  *Within this callback*, check the size of each individual file being uploaded and reject it if it exceeds a per-file limit.  This is *in addition to* `svr.set_payload_max_length()`.
        ```c++
        svr.set_multipart_form_data_handler(
            [&](const MultipartFormData &file) {
                if (file.content.size() > MAX_FILE_SIZE) {
                    // Reject the file (e.g., set an error flag)
                    return; // Stop processing this part
                }
                // ... other processing ...
            });
        ```
    2.  **Content Type Check (Basic, within Callbacks):** While *not* a strong security measure on its own (easily spoofed), you can perform a *basic* check of the `Content-Type` provided in the multipart header *within the callback*.  This can be a first-line defense, but *must* be followed by server-side validation (using something like `libmagic`, which is *outside* the scope of this `cpp-httplib`-only list).
        ```c++
         svr.set_multipart_form_data_handler(
            [&](const MultipartFormData &file) {
                if (file.content_type != "image/jpeg" && file.content_type != "image/png")
                {
                    // Reject the file (e.g., set an error flag)
                    return; // Stop processing this part
                }
                // ... other processing ...
            });
        ```

*   **Threats Mitigated:**
    *   **File Upload Vulnerabilities (High Severity):** Helps prevent uploading excessively large files, even if the overall request size is below `svr.set_payload_max_length()`.
    *   **Resource Exhaustion (Medium Severity):** Provides finer-grained control over resource usage for file uploads.

*   **Impact:**
    *   **File Upload Vulnerabilities:** Reduces the risk, especially when combined with server-side file type validation (which is outside the scope of this list). Risk reduction: Medium (becomes High with proper server-side validation).
    *   **Resource Exhaustion:** Improves resource management. Risk reduction: Medium.

*   **Currently Implemented:** Not implemented. The application uses `svr.set_multipart_form_data_handler`, but it does *not* include per-file size checks or basic content-type checks *within the callback*.

*   **Missing Implementation:** Per-file size checks and basic (preliminary) content-type checks within the `svr.set_multipart_form_data_handler` callback are missing.

## Mitigation Strategy: [Keep-Alive Configuration](./mitigation_strategies/keep-alive_configuration.md)

*   **Description:**
    1.  **Keep-Alive Max Count:** Use `svr.set_keep_alive_max_count(size_t)` to limit the maximum number of requests that can be served over a single keep-alive connection.  This prevents a single client from monopolizing a connection indefinitely.  A reasonable value might be 100 or 1000, depending on your application's needs.
    2.  **Keep-Alive Timeout:** Use `svr.set_keep_alive_timeout(sec)` to set the maximum time (in seconds) that a keep-alive connection will remain idle before being closed.  This prevents idle connections from consuming resources.  A reasonable value might be 5 or 10 seconds.

*   **Threats Mitigated:**
    *   **Resource Exhaustion (Low to Medium Severity):** Prevents a large number of idle keep-alive connections from consuming server resources (file descriptors, memory).
    *   **Slowloris-like Attacks (Low Severity):** While not a primary defense against Slowloris, limiting keep-alive duration can help mitigate some variations of the attack.

*   **Impact:**
    *   **Resource Exhaustion:** Reduces the risk of resource exhaustion due to idle connections. Risk reduction: Low to Medium.
    *   **Slowloris-like Attacks:** Provides a small degree of mitigation. Risk reduction: Low.

*   **Currently Implemented:**  Potentially implemented, but needs verification.  Check if `svr.set_keep_alive_max_count()` and `svr.set_keep_alive_timeout()` are being used with appropriate values.

*   **Missing Implementation:** If these settings are not used, or if they are used with excessively high values, then the mitigation is incomplete.

