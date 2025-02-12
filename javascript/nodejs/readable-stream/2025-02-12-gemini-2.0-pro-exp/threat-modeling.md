# Threat Model Analysis for nodejs/readable-stream

## Threat: [Unbounded Stream Buffering (DoS)](./threats/unbounded_stream_buffering__dos_.md)

*   **Description:** An attacker sends a very large amount of data at a high rate to a `readable-stream` that is not properly handling backpressure.  The internal buffers of `readable-stream` grow without limit because the consuming code (either a `pipe()` destination or manual `read()` calls) doesn't respect the signals to pause.
    *   **Impact:** Application crashes due to out-of-memory errors, denial of service for legitimate users.
    *   **Affected Component:**
        *   `readable.push()`:  If `push()` is called repeatedly without checking the return value (which indicates whether the internal buffer is full).  This is the *core* of the vulnerability.
        *   `highWaterMark` option: If set to an unreasonably large value or not set at all (using the default, which might still be too high).  This *exacerbates* the vulnerability.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Implement Backpressure (Essential):**  *Always* check the return value of `readable.push()`. If it returns `false`, *stop* pushing data until the `'drain'` event is emitted on a connected writable stream (or until internal buffer space becomes available). This is the *primary* mitigation.
        *   **Set `highWaterMark` Appropriately:** Choose a `highWaterMark` value that is reasonable for the expected data size and the consumer's processing speed.  Don't rely solely on the default. This is a *secondary* mitigation, providing a safety net.
        *   **Use Stream Transforms (Defensive):** Implement a custom transform stream that limits the buffer size or data rate, acting as an additional layer of protection.

## Threat: [Slowloris Stream Consumption (DoS)](./threats/slowloris_stream_consumption__dos_.md)

*   **Description:** An attacker acts as a very slow consumer of a `readable-stream`. They deliberately read data very slowly (e.g., using `readable.read(1)` in a loop with long delays), keeping the stream's internal mechanisms "busy" and potentially blocking other consumers or operations that depend on the stream's state.  This exploits the fact that `readable-stream` needs to manage internal state for each consumer.
    *   **Impact:** Resource exhaustion (primarily related to internal `readable-stream` state management, potentially file descriptors if the underlying resource is a file), denial of service for legitimate consumers. Other parts of the application that depend on the stream may become unresponsive.
    *   **Affected Component:**
        *   `readable.read()`: If called infrequently or with very small `size` arguments, intentionally delaying the consumption of data. This is the *direct* point of attack.
        *   Internal state management within `readable-stream`: The library needs to track the read position and buffered data for each consumer, and a slow consumer can tie up these resources.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Implement Timeouts (Essential):** Set timeouts for stream operations *within the consuming code*. If a consumer doesn't read data within a reasonable time, *destroy* the stream using `readable.destroy()`. This is the *primary* mitigation, directly addressing the slow consumption.
        *   **Rate Limiting (Defensive):** Implement rate limiting on the consumer side (if you control the consumer) to prevent excessively slow consumption. This is a *secondary* mitigation, adding another layer of protection.

## Threat: [Infinite Stream (DoS)](./threats/infinite_stream__dos_.md)

*   **Description:**  An attacker provides a `readable-stream` implementation that *never* signals the end of the stream.  It never calls `push(null)` and never emits the `'end'` event.  This directly exploits the core contract of a `readable-stream`.
    *   **Impact:** Application hangs or crashes due to resource exhaustion (memory, CPU, potentially file descriptors), denial of service.
    *   **Affected Component:**
        *   `readable.push(null)`: The attacker's stream implementation *fails* to call `push(null)` to signal the end of the stream. This is the *fundamental* flaw.
        *   `readable._read()`:  A malicious `_read()` implementation might never indicate that there's no more data.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Implement Timeouts (Essential):** Set a maximum time limit for the stream to complete *within the consuming code*. If the stream doesn't emit `'end'` within the timeout, *destroy* it using `readable.destroy()`. This is the *primary* and most reliable mitigation.
        *   **Watchdog Timer (Defensive):** Implement a separate watchdog timer (outside the stream handling code) that monitors the stream's activity and terminates it if it's been running for too long without producing output or completing. This is a *secondary* mitigation.

## Threat: [Sensitive Data Exposure in Stream (Information Disclosure)](./threats/sensitive_data_exposure_in_stream__information_disclosure_.md)

* **Description:** The stream contains sensitive data, and the inherent nature of streams (data flowing through) increases the risk of exposure if not handled carefully. While the *primary* vulnerability is in how the data is *used*, the stream itself is the conduit.
    * **Impact:** Leakage of sensitive information, potential privacy violations, compromise of accounts or systems.
    * **Affected Component:**
        * `readable.pipe()`: If piping to an insecure destination. The *act of piping* itself is the risk if the destination is compromised.
        * `readable.read()`: If the read data is handled insecurely (logged, displayed, etc.). The *availability of data* through `read()` is the risk.
        * Event listeners (`'data'`) : If the data chunk is handled insecurely. The *event emission* is the point of potential exposure.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Encryption (Proactive):** Encrypt sensitive data *before* it enters the stream. This is the most robust solution.
        * **Redaction (Reactive):** Redact sensitive information *within* the stream processing pipeline, ideally using a dedicated `Transform` stream. This is crucial if encryption isn't possible.
        * **Secure Transport (Essential):** Use secure channels (e.g., HTTPS) when piping stream data across network boundaries.
        * **Avoid Logging Raw Data (Essential):** *Never* log the raw contents of the stream. Log only necessary metadata, and ensure that metadata doesn't contain sensitive information.

