# Attack Surface Analysis for reactphp/reactphp

## Attack Surface: [1. Event Loop Starvation](./attack_surfaces/1__event_loop_starvation.md)

**Description:**  Execution of long-running, synchronous operations within the ReactPHP event loop, blocking other tasks and leading to denial of service.
    *   **How ReactPHP Contributes:** ReactPHP's single-threaded, event-driven nature is the *core reason* this is a critical vulnerability.  A single blocking call halts *all* processing within the event loop.
    *   **Example:** A database query executed *synchronously* within an event loop callback (e.g., using a traditional blocking database driver instead of `react/mysql`). Or, computationally intensive task without using `react/child-process`.
    *   **Impact:** Complete denial of service. The application becomes unresponsive to all clients.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strictly Avoid Blocking Operations:** Use ReactPHP's asynchronous components (e.g., `react/mysql`, `react/filesystem`, `react/http`) for *all* I/O.  This is the most important mitigation.
        *   **Offload CPU-Intensive Tasks:** Use `react/child-process` to move heavy computations to separate processes.
        *   **Timeouts:** Implement timeouts for *all* asynchronous operations using `Promise\Timer`.
        *   **Profiling:** Regularly profile the application to identify and eliminate any blocking code.

## Attack Surface: [2. Uncontrolled Resource Consumption (Streams)](./attack_surfaces/2__uncontrolled_resource_consumption__streams_.md)

**Description:**  Attackers sending excessively large or infinitely long streams of data, leading to memory exhaustion, disk space exhaustion, or other resource depletion.
    *   **How ReactPHP Contributes:** ReactPHP's stream-based architecture, while powerful, is *directly* involved in handling the data flow.  Without proper limits, this inherent capability is exploitable.
    *   **Example:** An attacker uploads a multi-terabyte file to a server that doesn't implement size limits on incoming streams using ReactPHP's stream handling. Or, a malicious client sends an endless stream of data to a proxy server built with ReactPHP.
    *   **Impact:** Denial of service due to resource exhaustion (OOM, disk full). Potential data loss if temporary files are involved.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Size Limits:** Enforce maximum sizes for incoming streams (e.g., file uploads) *using ReactPHP's stream handling capabilities*.
        *   **Backpressure:** Use `pause()` and `resume()` on ReactPHP streams to control data flow based on processing capacity. This is a *direct* use of ReactPHP's API.
        *   **Temporary File Management:** If writing to disk, use temporary files and monitor/limit disk space usage, cleaning up temporary files promptly.
        *   **Resource Monitoring:** Monitor memory and disk usage, and set appropriate limits.

## Attack Surface: [3. Slowloris-Type Attacks (Asynchronous Variant)](./attack_surfaces/3__slowloris-type_attacks__asynchronous_variant_.md)

**Description:**  Attackers establishing many connections and sending data *very* slowly, tying up server resources (file descriptors, stream buffers) without triggering timeouts.
    *   **How ReactPHP Contributes:** ReactPHP's non-blocking I/O model, while designed to handle many connections, still has finite resources.  The attack exploits ReactPHP's connection management.
    *   **Example:** An attacker opens hundreds of connections to a ReactPHP server and sends a single byte every few seconds, keeping the connections alive and consuming resources managed by ReactPHP.
    *   **Impact:** Denial of service due to resource exhaustion (file descriptors, memory). Reduced capacity to handle legitimate clients.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Aggressive Timeouts:** Implement short timeouts for both reading and writing on ReactPHP streams using `Promise\Timer`. This is a *direct* use of ReactPHP's features.
        *   **Connection Limits:** Limit the maximum number of concurrent connections *managed by ReactPHP's socket server*.
        *   **Idle Connection Monitoring:** Detect and close connections that are idle or sending data too slowly, interacting directly with ReactPHP's connection objects.
        *   **Rate Limiting:** Limit the number of connections and/or requests from a single IP address.

## Attack Surface: [4. Command Injection (Child Processes)](./attack_surfaces/4__command_injection__child_processes_.md)

**Description:** Attackers injecting malicious commands into the arguments of child processes spawned by the application.
    *   **How ReactPHP Contributes:** This is *directly* related to the use of `react/child-process`, a core ReactPHP component for managing external processes. The vulnerability arises from how this component is used.
    *   **Example:** The application uses user-provided input to construct a shell command executed via `react/child-process` without proper sanitization. An attacker injects malicious code.
    *   **Impact:** Arbitrary code execution on the server. Complete system compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid Shell Commands:** Use the array form of the `Process` constructor (provided by `react/child-process`) to pass arguments separately, *never* as a single string. This is a *direct* mitigation using ReactPHP's API.
        *   **Strict Input Validation:** Thoroughly validate and sanitize *any* user input used to construct command arguments.
        *   **Least Privilege:** Run child processes with the lowest possible privileges.

## Attack Surface: [5. Event Queue Overflow](./attack_surfaces/5__event_queue_overflow.md)

**Description:** Attackers flooding the application with requests faster than the event loop can process them, leading to unbounded queue growth and memory exhaustion.
    *   **How ReactPHP Contributes:** This attack directly targets the core mechanism of ReactPHP - its event loop. The vulnerability is inherent to how ReactPHP processes events sequentially.
    *   **Example:** An attacker sends a massive burst of requests to a ReactPHP-based API server, exceeding its processing capacity and filling the event queue.
    *   **Impact:** Denial of service due to memory exhaustion (OOM). Application crash.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Rate Limiting:** Limit the number of requests from a single client or IP address.
        *   **Backpressure:** Implement backpressure mechanisms to slow down data ingestion when the server is overloaded, using ReactPHP's stream `pause()` and `resume()` methods.
        *   **Connection Limits:** Limit the maximum number of concurrent connections handled by ReactPHP's server components.
        *   **Resource Monitoring:** Monitor memory usage and set appropriate limits.

