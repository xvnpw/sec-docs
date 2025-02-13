# Threat Model Analysis for badoo/reaktive

## Threat: [Race Condition due to Unsynchronized Shared Mutable State](./threats/race_condition_due_to_unsynchronized_shared_mutable_state.md)

*   **1. Threat: Race Condition due to Unsynchronized Shared Mutable State**

    *   **Description:** While an attacker can't directly *inject* code to *create* a race condition, they can exploit an existing one.  If multiple threads, managed by Reaktive's schedulers (`subscribeOn`, `observeOn`), access and modify shared, mutable data without proper synchronization (locks, atomics, etc.), the application's behavior becomes unpredictable.  An attacker might attempt to trigger specific actions or sequences of events that are more likely to expose the race condition, leading to data corruption.
    *   **Impact:** Data corruption, inconsistent application state, crashes, potentially leading to denial of service or, in rare but severe cases, unexpected code execution if the corrupted data influences control flow (e.g., altering a flag that determines authorization).
    *   **Affected Reaktive Component:** `subscribeOn`, `observeOn`, any operator that interacts with shared mutable state without proper synchronization (e.g., custom operators, `onNext` handlers).  Schedulers themselves are the mechanism by which this threat manifests.
    *   **Risk Severity:** High to Critical (depending on the nature of the shared state and the consequences of corruption; critical if it affects security-sensitive data).
    *   **Mitigation Strategies:**
        *   **Prefer Immutability:**  Prioritize immutable data structures. This is the most effective mitigation.
        *   **Atomic Operations:** If mutability is *required*, use atomic operations (e.g., `AtomicReference`, `AtomicInteger`) for thread-safe updates.
        *   **Synchronization (Use Sparingly):**  Use explicit synchronization (e.g., `synchronized` blocks, locks) only when absolutely necessary, and ensure correct lock granularity.  Incorrect synchronization can lead to deadlocks.
        *   **Thread Confinement:**  Confine mutable state to a single thread whenever possible, using `subscribeOn` and `observeOn` strategically.
        *   **Concurrency Testing:**  Use specialized concurrency testing tools to detect race conditions during development.

## Threat: [Deadlock due to Blocking Operations within Streams](./threats/deadlock_due_to_blocking_operations_within_streams.md)

*   **2. Threat: Deadlock due to Blocking Operations within Streams**

    *   **Description:** An attacker cannot directly inject code to cause a deadlock. However, if the application is vulnerable (due to improper use of blocking operations within Reaktive streams), an attacker might be able to trigger conditions that make a deadlock more likely.  If a thread within a Reaktive stream blocks (waiting for a lock, I/O, etc.) while holding a resource needed by another thread in the same or a related stream, a deadlock occurs.
    *   **Impact:** Application hangs indefinitely, requiring a restart.  This results in a complete denial of service.
    *   **Affected Reaktive Component:** `subscribeOn`, `observeOn`, any operator that performs blocking operations (especially custom operators that might not be properly designed). Schedulers are involved in managing the threads that become deadlocked.
    *   **Risk Severity:** High to Critical.
    *   **Mitigation Strategies:**
        *   **Avoid Blocking Operations:**  The primary mitigation is to minimize or eliminate blocking operations *within* Reaktive operators.
        *   **Non-Blocking Alternatives:**  Use non-blocking I/O libraries and asynchronous APIs whenever possible.
        *   **Offload Blocking Tasks:** If blocking operations are *unavoidable*, offload them to a separate, dedicated thread pool *outside* the main Reaktive stream. Use `subscribeOn` with a specific, bounded scheduler for this purpose.
        *   **Timeouts:**  Use timeouts on *any* blocking operation to prevent indefinite waiting.
        *   **Deadlock Detection:**  Use debugging and profiling tools to detect and diagnose deadlocks during development.

## Threat: [Thread Pool Exhaustion (Resource Starvation)](./threats/thread_pool_exhaustion__resource_starvation_.md)

*   **3. Threat: Thread Pool Exhaustion (Resource Starvation)**

    *   **Description:** An attacker can attempt to trigger a large number of concurrent operations that consume threads from Reaktive's schedulers.  If the application doesn't have proper backpressure mechanisms or resource limits, this can lead to thread pool exhaustion, making the application unresponsive.
    *   **Impact:** Application becomes unresponsive; new events are not processed; existing operations are delayed or fail.  This is a denial-of-service vulnerability.
    *   **Affected Reaktive Component:** Schedulers (e.g., `computationScheduler`, `ioScheduler`, `singleScheduler`), operators that can create new threads or tasks (e.g., `flatMap`, `parallel`).
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   **Bounded Thread Pools:**  Use bounded thread pools (schedulers) with sizes appropriate for the expected workload and available system resources.  Avoid unbounded thread pools.
        *   **Backpressure:**  Implement backpressure mechanisms (e.g., `onBackpressureBuffer`, `onBackpressureDrop`, `onBackpressureLatest`) to handle situations where the downstream cannot keep up with the upstream. This is crucial for preventing uncontrolled resource consumption.
        *   **Rate Limiting:**  Limit the rate at which new tasks are submitted to the schedulers.
        *   **Monitoring:**  Monitor thread pool usage and performance metrics to detect and respond to potential exhaustion.

## Threat: [Stream Flooding (DoS)](./threats/stream_flooding__dos_.md)

*   **4. Threat: Stream Flooding (DoS)**

    *   **Description:** An attacker sends a large volume of data to a Reaktive stream, overwhelming the system and causing a denial of service. This directly exploits the asynchronous nature of Reaktive if backpressure or rate limiting is not properly implemented at the point where external data enters the stream.
    *   **Impact:** Application becomes unresponsive; resources are exhausted; legitimate requests are not processed.  Denial of service.
    *   **Affected Reaktive Component:** Any `Observable` or `Flowable` that receives data from an external source (e.g., network connection, user input, message queue). The vulnerability exists in how the stream is *constructed* and *subscribed to*, not in a specific operator itself.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   **Backpressure:**  Implement backpressure mechanisms *at the source* of the stream (e.g., `onBackpressureBuffer`, `onBackpressureDrop`, `onBackpressureLatest`). This is the most important mitigation.
        *   **Rate Limiting:** Implement rate limiting *before* data enters the Reaktive stream, if possible (e.g., at the network layer or using a token bucket algorithm).
        *   **Buffering (with Caution):** Use buffering strategies to handle bursts of data, but be very careful about memory usage; excessive buffering can lead to memory exhaustion.
        *   **Input Validation:** Validate the size and frequency of incoming data *before* it enters the stream to prevent excessively large or frequent messages.
        *   **Monitoring:** Monitor the stream for unusually high data rates and implement alerts.

