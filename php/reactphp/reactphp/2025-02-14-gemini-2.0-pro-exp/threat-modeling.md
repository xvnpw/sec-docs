# Threat Model Analysis for reactphp/reactphp

## Threat: [Event Loop Starvation](./threats/event_loop_starvation.md)

*   **Description:** An attacker sends a crafted request that triggers a long-running, synchronous operation *within* a ReactPHP event loop handler.  This could be a request designed to cause a blocking file read, a complex calculation, or a synchronous database call. Because ReactPHP is single-threaded, this blocks the *entire* event loop, preventing *all* other requests from being processed.
    *   **Impact:** Complete denial of service (DoS) for all users. The application becomes entirely unresponsive.
    *   **Affected ReactPHP Component:** Directly impacts the core `react/event-loop` and any component built upon it, including `react/http`, `react/socket`, `react/dns`, and any custom code using the event loop. The vulnerability is in *how* these components are used, not inherently in the components themselves.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strictly avoid blocking operations:** Never use synchronous file I/O, database calls, or any other blocking operations within event loop handlers.
        *   **Use asynchronous components:**  Exclusively use ReactPHP's asynchronous components (e.g., `react/filesystem`, `react/http-client`, `react/mysql` with *asynchronous* drivers) for all I/O operations.
        *   **Offload CPU-intensive tasks:** Move computationally heavy operations to separate processes or worker threads using `react/child-process` or a message queue system.
        *   **Timeouts:** Implement timeouts for *all* asynchronous operations to prevent indefinite hangs.
        *   **`react/async`:** Utilize `react/async` and `await` for cleaner and more manageable asynchronous code.
        *   **Monitoring:** Actively monitor event loop latency to detect potential blocking issues.

## Threat: [Unhandled Promise Rejection](./threats/unhandled_promise_rejection.md)

*   **Description:** An attacker sends a request that triggers an error within an asynchronous operation (represented by a Promise). If this Promise rejection is *not* explicitly handled with a `.catch()` block or the second argument to `.then()`, the entire ReactPHP process will terminate. This can be caused by seemingly minor errors, making it a significant and easily triggered DoS vulnerability.
    *   **Impact:** Application crash and complete unavailability (DoS) for all users.
    *   **Affected ReactPHP Component:** Directly affects any code using Promises, which is pervasive in ReactPHP applications. This includes core components like `react/http`, `react/socket`, `react/dns`, `react/filesystem`, and any custom asynchronous logic.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Handle all rejections:**  Always use `.catch()` or the second argument to `.then()` to handle *every* Promise rejection.
        *   **Global handler:** Implement a global unhandled rejection handler to catch any missed rejections and log them or gracefully shut down.
        *   **Thorough testing:** Rigorously test all asynchronous code paths, including all potential error scenarios.
        *   **Linters/Static Analysis:** Use linters and static analysis tools to detect potential unhandled rejections.

## Threat: [Resource Exhaustion (File Descriptors)](./threats/resource_exhaustion__file_descriptors_.md)

*   **Description:** An attacker opens a large number of connections to the ReactPHP server (e.g., WebSocket connections or persistent HTTP requests) and keeps them open without properly closing them. If the application does not correctly manage and release these connections, it can exhaust the available file descriptors, preventing new connections and leading to a DoS. This is directly related to how ReactPHP handles concurrency.
    *   **Impact:** Denial of service (DoS). New connections are refused. Existing connections may also be affected if the system runs out of file descriptors.
    *   **Affected ReactPHP Component:** Directly affects `react/socket` and `react/http` when handling many concurrent connections. Also affects any component that opens file handles (e.g., `react/filesystem`) if not managed correctly.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Explicitly close resources:** Always explicitly close connections, streams, and file handles when they are no longer needed. Use `finally()` blocks in Promises to ensure cleanup even on errors.
        *   **Connection limits:** Implement limits on the maximum number of concurrent connections *within the ReactPHP application itself*.
        *   **Backpressure:** Implement backpressure mechanisms to prevent the server from being overwhelmed.
        *   **System limits:** Set appropriate system limits (e.g., `ulimit -n`) for the maximum number of open file descriptors (although this is a system-level mitigation, it's relevant).
        *   **Monitoring:** Monitor file descriptor usage to detect potential exhaustion.

## Threat: [Resource Exhaustion (Memory)](./threats/resource_exhaustion__memory_.md)

*   **Description:** An attacker sends a very large request (e.g., a massive file upload) or a series of requests designed to cause the application to allocate excessive memory. If the application does not properly handle large data or release memory, it can exhaust available memory, leading to a crash or DoS. This is directly related to how ReactPHP handles data streams and buffering.
    *   **Impact:** Denial of service (DoS) or application crash due to out-of-memory errors.
    *   **Affected ReactPHP Component:** Potentially affects any component, but particularly `react/http` (for handling large requests/responses) and `react/stream` (for processing data streams). Also affects any custom code that allocates large amounts of memory without proper management.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Streaming:** Use ReactPHP's streaming capabilities (`react/stream`) to process data in chunks, *avoiding* loading entire requests or responses into memory.
        *   **Request/Response size limits:** Implement limits on the maximum size of requests and responses *within the ReactPHP application*.
        *   **Buffering:** Use appropriate buffering strategies to manage memory usage effectively.
        *   **Memory monitoring:** Monitor memory usage and set appropriate limits.
        *   **Garbage Collection:** Ensure proper garbage collection in long-running ReactPHP processes.

## Threat: [Unencrypted Communication (Plain TCP)](./threats/unencrypted_communication__plain_tcp_.md)

*   **Description:** An attacker intercepts network traffic between a client and a ReactPHP server. If the server is configured to use plain TCP (without TLS encryption) via `react/socket`, *all* communication is unencrypted, exposing sensitive data to eavesdropping and potential man-in-the-middle attacks.
    *   **Impact:** Data confidentiality and integrity are completely compromised. Man-in-the-middle attacks are easily possible.
    *   **Affected ReactPHP Component:** `react/socket` when used to create a plain TCP server (i.e., *without* using `SecureServer`).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use TLS:**  *Always* use `react/socket`'s `SecureServer` to establish encrypted connections using TLS. Never expose a plain TCP server.
        *   **Strong ciphers:** Use strong TLS ciphers and protocols.
        *   **Certificate validation:** Properly validate TLS certificates to prevent man-in-the-middle attacks.

