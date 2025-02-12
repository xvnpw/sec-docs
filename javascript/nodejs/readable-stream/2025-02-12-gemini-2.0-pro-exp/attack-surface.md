# Attack Surface Analysis for nodejs/readable-stream

## Attack Surface: [Uncontrolled Resource Consumption (Backpressure Failure)](./attack_surfaces/uncontrolled_resource_consumption__backpressure_failure_.md)

*   **Description:**  The application fails to properly handle backpressure from a `readable-stream`, leading to excessive resource consumption.
*   **`readable-stream` Contribution:** `readable-stream` provides mechanisms for backpressure (e.g., `highWaterMark`, return value of `push()`), but the application must *correctly implement* these.  The library's core functionality is directly involved in managing the flow of data, and misusing it leads to this vulnerability.
*   **Example:** An application reads data from a network stream using `readable-stream` but doesn't check the return value of `push()` or use `pipeline()`.  An attacker sends a flood of data, causing the application's memory usage to spike until it crashes (OOM).
*   **Impact:** Denial of Service (DoS), application crash, resource exhaustion (memory, CPU, disk, network).
*   **Risk Severity:** **Critical** (if easily exploitable and leads to complete DoS) or **High** (if it degrades performance significantly).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Implement backpressure handling: Check the return value of `readable.push()` and pause data production when it returns `false`.
        *   Use `stream.pipeline()` or `stream.pipe()` with proper error handling; these methods automatically manage backpressure.
        *   Set a reasonable `highWaterMark` to limit the internal buffer size.
        *   Monitor resource usage and implement circuit breakers or rate limiting.

## Attack Surface: [Unbounded Stream Length](./attack_surfaces/unbounded_stream_length.md)

*   **Description:** The application reads from a `readable-stream` without any limit on the total amount of data that can be consumed.
*   **`readable-stream` Contribution:** `readable-stream` doesn't impose a maximum data size limit by default; it's up to the application to implement this. The library's core function of providing a stream of data without inherent limits is the direct contributor.
*   **Example:** An application reads data from a user-uploaded file using a `readable-stream`. An attacker uploads a multi-terabyte file, causing the application to run out of disk space or memory.
*   **Impact:** Resource exhaustion (disk space, memory), Denial of Service (DoS).
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Implement a maximum data size limit for streams.  Close the stream and handle the error if the limit is exceeded.
        *   Use libraries that provide built-in size limiting for streams.

## Attack Surface: [Malicious Stream Transformation](./attack_surfaces/malicious_stream_transformation.md)

*   **Description:** A compromised or malicious transform stream (which uses `readable-stream` internally) performs resource-intensive operations or data expansion.
*   **`readable-stream` Contribution:** Transform streams are *built upon* `readable-stream` and `writable-stream`. While the malicious logic is in the *transform* code, the underlying `readable-stream` mechanism is *essential* for the attack to function. The transform stream *relies* on the `readable-stream` API for its input.
*   **Example:** An application uses a third-party transform stream to decompress data.  An attacker provides a "zip bomb" (a small, highly compressed file that expands to a huge size) that overwhelms the transform stream and the application.
*   **Impact:** Resource exhaustion (CPU, memory), Denial of Service (DoS), potential code execution (if the transform stream has vulnerabilities).
*   **Risk Severity:** **High** or **Critical** (depending on the transform stream's vulnerability).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Carefully validate and sanitize any user-provided input that influences the creation or configuration of transform streams.
        *   Avoid using untrusted third-party transform stream implementations without thorough security review.
        *   Implement resource limits and monitoring within transform streams.
        *   Use well-vetted and maintained libraries for common transformations (e.g., compression, encryption).

