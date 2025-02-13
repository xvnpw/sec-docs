# Attack Surface Analysis for badoo/reaktive

## Attack Surface: [1. Resource Exhaustion via Unbounded Streams](./attack_surfaces/1__resource_exhaustion_via_unbounded_streams.md)

*   **Description:** Attackers trigger the creation of excessively large or infinite data streams, leading to resource depletion (memory, CPU, threads).
*   **How Reaktive Contributes:** Reaktive's core functionality revolves around creating and processing data streams. Its asynchronous nature and powerful operators, if misused, can easily lead to unbounded resource consumption. This is inherent to the reactive paradigm.
*   **Example:** An attacker sends a flood of malicious requests to an API endpoint. This endpoint creates a Reaktive `Observable` that emits an item for *each* request. Without backpressure or limiting, the `Observable` consumes memory indefinitely, crashing the application.
*   **Impact:** Denial of Service (DoS), application crash, system instability.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Implement backpressure using operators like `sample`, `throttle`, `onBackpressureBuffer`, `onBackpressureDrop`, or `onBackpressureLatest`.
        *   Use finite streams whenever possible. If infinite streams are necessary, bound them by time or other criteria.
        *   Apply rate limiting to external inputs that feed into Reaktive streams.
        *   Set timeouts on stream operations using `timeout`.
        *   Use `take` or `takeUntil` to limit the number of emitted items.

## Attack Surface: [2. Thread Pool Starvation](./attack_surfaces/2__thread_pool_starvation.md)

*   **Description:** Long-running or blocking operations on inappropriate Reaktive Schedulers exhaust thread pools, preventing other tasks from executing.
*   **How Reaktive Contributes:** Reaktive *directly* provides and manages Schedulers (thread pools) for concurrency. Misuse of these Schedulers is a Reaktive-specific concern.
*   **Example:** A developer uses the `computation` scheduler (for short, CPU-bound tasks) for a long-running network request within a `flatMap` operator. This blocks a `computation` pool thread, preventing other CPU-bound tasks from running.  Sufficient requests block the entire pool.
*   **Impact:** Denial of Service (DoS), application responsiveness degradation, potential deadlocks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Use the correct Scheduler: `io` for blocking I/O, `computation` for CPU-bound tasks, `single` for sequential tasks.
        *   Avoid blocking operations on the `computation` scheduler. Offload blocking I/O to the `io` scheduler using `subscribeOn(Schedulers.io())`.
        *   Use non-blocking APIs whenever possible.
        *   Consider custom Schedulers with bounded thread pools.

## Attack Surface: [3. Race Conditions due to Unsynchronized Shared State](./attack_surfaces/3__race_conditions_due_to_unsynchronized_shared_state.md)

*   **Description:** Multiple threads (managed by Reaktive Schedulers) access and modify shared mutable state without proper synchronization, leading to data corruption.
*   **How Reaktive Contributes:** Reaktive's asynchronous and concurrent nature, *facilitated by its Schedulers*, significantly increases the likelihood of race conditions if shared state is not handled carefully.  The concurrency model is a core part of Reaktive.
*   **Example:** Two `Observable` streams, on different Schedulers, update a shared counter without synchronization. The counter's final value is unpredictable and likely incorrect.
*   **Impact:** Data corruption, unpredictable behavior, potential security vulnerabilities (e.g., bypassing security checks).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Prefer immutable data structures.
        *   Use synchronization (locks, atomic variables, concurrent data structures) for shared mutable state.
        *   Use `observeOn` and `subscribeOn` to control thread execution and serialize access to shared state.
        *   Thoroughly test concurrent code.

