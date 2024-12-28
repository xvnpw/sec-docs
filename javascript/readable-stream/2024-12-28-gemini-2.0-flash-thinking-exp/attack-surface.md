Here's the updated list of key attack surfaces directly involving `readable-stream` with high or critical risk severity:

*   **Malicious Payloads via `stream.push()` in Transform Streams:**
    *   **Description:**  A Transform stream's `_transform` function processes data pushed into the stream. If this data originates from an untrusted source and contains malicious payloads, the `_transform` function might execute them.
    *   **How readable-stream contributes:** `readable-stream` provides the `push()` method to feed data into the stream and the `_transform` hook for processing, enabling the flow of potentially malicious data to the vulnerable processing logic.
    *   **Example:** A Transform stream processes user-uploaded files. A malicious user uploads a file containing shell commands disguised within its data. The `_transform` function, without proper sanitization, executes these commands.
    *   **Impact:** Remote code execution, data exfiltration, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Sanitization:**  Thoroughly sanitize and validate all data received from untrusted sources before processing it in the `_transform` function.
        *   **Secure Processing:** Avoid using `eval()` or similar dynamic code execution methods on untrusted data within `_transform`.
        *   **Sandboxing:** If possible, process data within a sandboxed environment to limit the impact of successful exploits.
        *   **Principle of Least Privilege:** Ensure the process running the stream has only the necessary permissions.

*   **Denial of Service via Large Data Pushes:**
    *   **Description:**  Pushing excessively large amounts of data into a stream can overwhelm the processing logic or consume excessive memory, leading to a denial of service.
    *   **How readable-stream contributes:** `readable-stream` allows arbitrary amounts of data to be pushed into the stream using the `push()` method. If not handled carefully, this can be exploited.
    *   **Example:** An attacker continuously sends large chunks of data to a stream processing user uploads, exhausting the server's memory and causing it to crash.
    *   **Impact:** Service disruption, resource exhaustion.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Data Size Limits:** Implement limits on the size of data that can be pushed into the stream.
        *   **Backpressure Management:** Properly implement and handle backpressure to prevent the producer from overwhelming the consumer.
        *   **Resource Monitoring:** Monitor resource usage (CPU, memory) and implement alerts to detect potential DoS attacks.