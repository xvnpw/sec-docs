# Attack Surface Analysis for dotnet/reactive

## Attack Surface: [Uncontrolled Resource Consumption via Subscriptions (DoS)](./attack_surfaces/uncontrolled_resource_consumption_via_subscriptions__dos_.md)

*   **Description:** Attackers can exploit Rx.NET's subscription mechanism to cause excessive resource usage (CPU, memory, threads, network connections), leading to a Denial of Service.
*   **How Reactive Contributes:** This is *inherent* to Rx.NET's core design.  Observables and subscriptions are the fundamental building blocks.  Uncontrolled subscriptions, long-lived subscriptions without disposal, or rapidly created subscriptions are direct attack vectors.
*   **Example:** An attacker repeatedly sends requests that trigger new subscriptions to a long-running observable (e.g., a continuous network stream or a `Subject` being flooded with data) without ever unsubscribing.  This exhausts server resources.
*   **Impact:** Denial of Service (DoS), application unresponsiveness, potential server crashes.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Subscription Limits:** Enforce strict, *low* limits on the number of concurrent subscriptions per user/client/IP address. This is *crucial*.
    *   **Mandatory Unsubscription:** Ensure *all* subscriptions are *always* disposed of using `Dispose()`, `using` statements, or `CompositeDisposable`.  This is a fundamental Rx.NET best practice.
    *   **Timeouts on Subscriptions:** Implement timeouts on *all* subscriptions, especially those to external resources or long-running operations. Use the `Timeout()` operator.
    *   **Cancellation Tokens:** Utilize `CancellationTokenSource` extensively to allow for graceful cancellation of subscriptions and associated operations.
    *   **Rate Limiting (Observable Creation):** Implement rate limiting on the *creation* of observables, especially if they are tied to external resources.
    *   **Bounded Schedulers:** Use schedulers with configured resource limits (e.g., a custom `TaskPoolScheduler` with a maximum degree of parallelism) to prevent thread exhaustion.
    *   **Backpressure (for High-Frequency Sources):** Implement backpressure mechanisms (`Buffer`, `Throttle`, `Sample`, `Window`) for high-frequency data sources *if and only if* the use case allows for dropping or aggregating data.  Incorrect backpressure can *also* be a DoS vector.
    *   **Monitoring:** Monitor resource usage (CPU, memory, threads, *active subscription count*) to detect anomalies.

## Attack Surface: [Race Conditions from Concurrent Observable Operations](./attack_surfaces/race_conditions_from_concurrent_observable_operations.md)

*   **Description:** Concurrent access to shared, mutable state from *within* observable operators (without proper synchronization) leads to data corruption and inconsistent application behavior.
*   **How Reactive Contributes:** Rx.NET's asynchronous and potentially multi-threaded nature *directly* creates the possibility of race conditions if shared state is accessed within operators like `Select`, `Where`, `Subscribe`, etc., without proper safeguards.  This is a core concurrency concern amplified by Rx.NET.
*   **Example:** Multiple observers concurrently modify a shared list (a non-thread-safe collection) within a `Select` operator, or a `Subject`'s `OnNext` is called from multiple threads concurrently, modifying shared state without locks.
*   **Impact:** Data corruption, unpredictable application behavior, potential security vulnerabilities if the corrupted data affects security-critical logic.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Immutability (Preferred):** *Strongly prefer* immutable data structures within observable chains. This eliminates the need for synchronization entirely.
    *   **Synchronization (If Mutable State is Unavoidable):** If mutable shared state is *absolutely necessary*, use appropriate synchronization:
        *   `lock` statements (for short, critical sections, used *very* sparingly).
        *   `Interlocked` operations (for atomic updates of simple types).
        *   *Thread-safe* collections (e.g., `ConcurrentQueue`, `ConcurrentDictionary`).  *Never* use non-thread-safe collections in this context.
    *   **Thread Affinity (Careful Use):** Use `ObserveOn` and `SubscribeOn` *judiciously* and with a *deep understanding* of their behavior.  Ensure operations that modify shared state are executed on the correct thread/context to *minimize* the need for explicit synchronization, but don't rely on this alone.
    *   **Code Review (Crucial):** Thoroughly review code for potential race conditions, *especially* in areas where shared state is accessed within observable chains. This requires expertise in both Rx.NET and concurrent programming.

## Attack Surface: [Unhandled Exceptions Crashing Observable Chains](./attack_surfaces/unhandled_exceptions_crashing_observable_chains.md)

*   **Description:** Exceptions thrown within observable operators or `Subscribe` handlers that are *not* caught by an `OnError` handler can terminate the observable sequence and potentially crash the application.
*   **How Reactive Contributes:** Rx.NET's error handling model is different from traditional `try-catch` blocks.  Exceptions propagate through the `OnError` channel of the `IObserver`.  Failure to handle them *specifically* within the Rx.NET context leads to unhandled exceptions.
*   **Example:** An exception is thrown within a `Select` operator due to invalid input, and the `Subscribe` call lacks an `OnError` handler.  The observable sequence terminates, and the exception may crash the application (depending on the host environment).
*   **Impact:** Application crashes (potentially), denial of service, unexpected termination of observable sequences, potential loss of data.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Mandatory `OnError` Handlers:** *Always* provide an `OnError` handler in *every* `Subscribe` call. This is a non-negotiable best practice for Rx.NET.
    *   **`Catch` Operator (for Recovery):** Use the `Catch` operator *within* the observable chain to handle specific exceptions and *potentially* recover from them (e.g., retry, provide a default value, switch to a fallback observable).
    *   **`try-catch` within Operators (Limited Use):** Use `try-catch` blocks *inside* operators (like `Select`, `Where`) *only* when you need to handle exceptions *immediately* and transform them into a different value or error *within the operator itself*.  This should *not* be the primary error handling mechanism.
    *   **Logging (Essential):** Log *all* exceptions, including those handled within observable chains (both in `OnError` handlers and within operators), for debugging and auditing.

## Attack Surface: [Deadlocks from Blocking Operations within Observables](./attack_surfaces/deadlocks_from_blocking_operations_within_observables.md)

*   **Description:** Using blocking calls (e.g., `Task.Wait()`, `Task.Result`, blocking synchronization primitives) within observable operators can lead to deadlocks, especially when combined with schedulers.
*   **How Reactive Contributes:** Rx.NET is designed for asynchronous, non-blocking operations.  Introducing blocking calls *directly* violates this principle and creates a high risk of deadlocks, particularly when interacting with schedulers.
*   **Example:** A `Select` operator uses `Task.Result` to synchronously wait for a task that is scheduled on the same scheduler (e.g., the UI thread), creating a classic deadlock scenario.
*   **Impact:** Application freeze, denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid Blocking Calls (Absolute Rule):** *Never* use `Wait()`, `Result`, or other blocking methods on `Task` objects within observable operators.  This is a fundamental rule for avoiding deadlocks in Rx.NET.
    *   **Asynchronous Alternatives:** Use asynchronous alternatives (e.g., `await` within an `async` operator, `SelectMany` to compose asynchronous operations).
    *   **Asynchronous Synchronization:** If synchronization is *absolutely* required, use *asynchronous* synchronization primitives (e.g., `SemaphoreSlim`) instead of blocking ones (e.g., `Monitor`, `Mutex`).
    *   **Scheduler Awareness:** Have a *deep understanding* of how schedulers work in Rx.NET and how they interact with synchronization.  Avoid scenarios where a task scheduled on a scheduler is blocked waiting for another task on the same scheduler.

