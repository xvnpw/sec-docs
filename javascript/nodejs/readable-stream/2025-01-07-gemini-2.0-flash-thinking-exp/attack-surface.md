# Attack Surface Analysis for nodejs/readable-stream

## Attack Surface: [Malicious Data Injection via `push()`](./attack_surfaces/malicious_data_injection_via__push___.md)

*   **Description:** An attacker can inject malicious or unexpected data into a readable stream using the `push()` method if the application doesn't properly sanitize input before pushing.
    *   **How readable-stream Contributes:** `readable-stream` provides the `push()` method as the primary way to feed data into a stream. If this method is used with unsanitized data, the library facilitates the injection.
    *   **Example:** A custom readable stream fetching data from a user-controlled source directly pushes the raw data using `this.push(untrustedData)`. If `untrustedData` contains escape sequences or commands intended for a downstream interpreter, it could be executed.
    *   **Impact:** Can lead to various issues depending on the downstream processing, including code injection, data corruption, or denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Validation:** Implement strict validation of all data before calling `push()`.
        *   **Data Sanitization:** Sanitize data to remove or escape potentially harmful characters or sequences before pushing.
        *   **Content Security Policies (CSP):** If the output is rendered in a web context, use CSP to mitigate cross-site scripting (XSS) risks.

## Attack Surface: [Resource Exhaustion via Backpressure Manipulation](./attack_surfaces/resource_exhaustion_via_backpressure_manipulation.md)

*   **Description:** An attacker can manipulate the rate at which data is consumed from a readable stream, potentially causing excessive buffering and memory exhaustion.
    *   **How readable-stream Contributes:** `readable-stream`'s backpressure mechanism relies on consumers signaling their readiness to receive more data. An attacker can intentionally slow down consumption or stop consuming entirely, causing the stream to buffer indefinitely if not handled properly.
    *   **Example:** A malicious client connects to a server that streams data using `readable-stream`. The client intentionally reads data very slowly or stops reading, causing the server to buffer large amounts of data in memory, potentially leading to a denial of service.
    *   **Impact:** Denial of service due to excessive memory consumption.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Timeouts:** Implement timeouts on stream operations to prevent indefinite buffering.
        *   **Resource Limits:** Set limits on the maximum buffer size or the amount of data that can be buffered.
        *   **Monitoring:** Monitor resource usage (memory, CPU) to detect potential backpressure issues.
        *   **Proper Backpressure Handling:** Ensure downstream consumers correctly implement backpressure handling and signal their readiness.

