# Mitigation Strategies Analysis for ruby-concurrency/concurrent-ruby

## Mitigation Strategy: [Atomic Operations (using `concurrent-ruby`)](./mitigation_strategies/atomic_operations__using__concurrent-ruby__.md)

*   **Description:**
    1.  **Identify Simple Shared Variables:** Find shared variables that are subject to simple, atomic updates (e.g., incrementing a counter, setting a flag).
    2.  **Use `concurrent-ruby` Atomic Types:** Replace direct access to these variables with `concurrent-ruby`'s atomic primitives:
        *   `Concurrent::AtomicFixnum`: For integer counters.
        *   `Concurrent::AtomicBoolean`: For boolean flags.
        *   `Concurrent::AtomicReference`: For holding references to other objects (use with caution, ensures atomic *reference* updates, not object mutability).  This is crucial for atomically swapping out entire objects.
    3.  **Understand Atomic Operations:** Be aware of the specific atomic operations provided by each type (e.g., `increment`, `decrement`, `compare_and_set`, `update`). Use the correct operation for your needs.  The `compare_and_set` (CAS) operation is particularly important for implementing more complex lock-free algorithms.
    4.  **Avoid Non-Atomic Operations:** Do *not* combine atomic operations with non-atomic operations on the same variable.  For example, `if atomic_counter.value > 0 then atomic_counter.decrement end` is *not* atomic and still needs external synchronization.

*   **Threats Mitigated:**
    *   **Data Races (Severity: High):** Guarantees that simple updates to shared variables are performed atomically, preventing data corruption.
    *   **Lost Updates (Severity: Medium):** Ensures that updates from multiple threads are not lost due to concurrent access.

*   **Impact:**
    *   **Data Races:** Risk significantly reduced for simple variable updates.
    *   **Lost Updates:** Risk significantly reduced.

*   **Currently Implemented:**
    *   `Concurrent::AtomicFixnum` is used to track the number of active requests in the `RequestCounter` module.

*   **Missing Implementation:**
    *   A boolean flag indicating whether the system is in maintenance mode is currently a regular instance variable and is not updated atomically.

## Mitigation Strategy: [Thread-Safe Data Structures (using `concurrent-ruby`)](./mitigation_strategies/thread-safe_data_structures__using__concurrent-ruby__.md)

*   **Description:**
    1.  **Identify Shared Collections:** Find shared data structures like arrays, hashes, or maps that are accessed and modified by multiple threads.
    2.  **Use `concurrent-ruby` Collections:** Replace standard Ruby collections with `concurrent-ruby`'s thread-safe equivalents:
        *   `Concurrent::Array`
        *   `Concurrent::Hash`
        *   `Concurrent::Map` (often the best choice for general-purpose concurrent hash tables)
    3.  **Read Documentation Carefully:** Understand the thread-safety guarantees of each collection and its methods.  Some operations might not be fully atomic, particularly those involving multiple steps.
    4.  **Avoid Check-Then-Act:** Be particularly cautious of "check-then-act" sequences (e.g., checking if a key exists in a `Concurrent::Map` and then inserting a value).  These are *not* atomic and require additional synchronization (often using `compute_if_absent` or similar methods).  `Concurrent::Map` provides methods like `put_if_absent`, `compute_if_absent`, `compute_if_present`, and `merge` that can help with these scenarios.

*   **Threats Mitigated:**
    *   **Data Races (Severity: High):** Provides thread-safe access to collections, preventing data corruption.
    *   **ConcurrentModificationException (Severity: Medium):** Eliminates the risk of exceptions caused by modifying a collection while it's being iterated over by another thread.

*   **Impact:**
    *   **Data Races:** Risk significantly reduced for collection operations.
    *   **ConcurrentModificationException:** Risk eliminated.

*   **Currently Implemented:**
    *   `Concurrent::Map` is used to store cached database query results in the `QueryCache` module.

*   **Missing Implementation:**
    *   A list of active user sessions is currently stored in a regular Ruby `Array` and is accessed by multiple threads without proper synchronization.

## Mitigation Strategy: [Thread Pool Management (using `concurrent-ruby`)](./mitigation_strategies/thread_pool_management__using__concurrent-ruby__.md)

*   **Description:**
    1.  **Avoid Raw Threads:** Do not create threads directly using `Thread.new` unless absolutely necessary.  Raw threads offer no management or resource control.
    2.  **Use `concurrent-ruby` Thread Pools:** Utilize `concurrent-ruby`'s thread pool implementations:
        *   `Concurrent::ThreadPoolExecutor`: The most general-purpose and configurable thread pool.
        *   `Concurrent::FixedThreadPool`: A pool with a fixed number of threads.
        *   `Concurrent::CachedThreadPool`: A pool that creates threads as needed and reuses them, suitable for short-lived tasks.
        *   `Concurrent::SingleThreadExecutor`: Executes tasks sequentially in a single background thread.
        *   `Concurrent::ImmediateExecutor`: Executes tasks immediately in the calling thread (useful for testing or when concurrency is not desired).
    3.  **Configure Pool Size:** Carefully configure the thread pool size based on:
        *   The number of available CPU cores.
        *   The nature of the tasks (CPU-bound vs. I/O-bound).  I/O-bound tasks can often use a larger pool size.
        *   Available system memory.
    4.  **Monitor Resource Usage:** Monitor the application's resource usage (CPU, memory, threads) to ensure that the thread pool is not over- or under-provisioned.  Use tools like `concurrent-ruby`'s built-in instrumentation or external monitoring systems.
    5.  **Consider Adaptive Pools:** Explore `concurrent-ruby`'s `Concurrent::ThreadPoolExecutor` with auto-trimming features, which can dynamically adjust the number of threads based on load.
    6.  **Shutdown Pools Gracefully:** When shutting down the application, ensure that thread pools are shut down gracefully using `#shutdown` and `#wait_for_termination`.  This allows running tasks to complete before the application exits.
    7. **Use `post` method:** Use `post` method to add tasks to the thread pool.

*   **Threats Mitigated:**
    *   **Resource Exhaustion (Severity: Medium):** Prevents the creation of too many threads, which can lead to resource exhaustion (memory, CPU, file descriptors).
    *   **Thread Starvation (Severity: Low):** Helps ensure that tasks are executed in a timely manner by managing the allocation of threads.

*   **Impact:**
    *   **Resource Exhaustion:** Risk significantly reduced.
    *   **Thread Starvation:** Risk moderately reduced.

*   **Currently Implemented:**
    *   A `Concurrent::FixedThreadPool` is used for handling background tasks related to email sending.

*   **Missing Implementation:**
    *   Several parts of the application still create threads directly using `Thread.new`, without any resource management.
    *   The `Concurrent::FixedThreadPool` for email sending is not properly shut down when the application exits.

## Mitigation Strategy: [Exception Handling with `Future` and `Promise` (using `concurrent-ruby`)](./mitigation_strategies/exception_handling_with__future__and__promise___using__concurrent-ruby__.md)

*   **Description:**
    1.  **Use `Future` or `Promise`:** Wrap asynchronous operations in `Concurrent::Future` or `Concurrent::Promise` objects.  These provide a way to manage the result of an asynchronous computation.
    2.  **Use `rescue`:** Use the `#rescue` method (or its alias `#rescue_with`) on the `Future` or `Promise` to handle exceptions that occur during the asynchronous execution.  This is *essential* for preventing unhandled exceptions from silently terminating threads.
        *   `future.rescue { |reason| ... }`
    3.  **Chain Operations:** Use methods like `#then`, `#chain`, and `#flat_map` to chain together asynchronous operations and handle their results (and potential errors) in a controlled manner.
    4.  **Handle Results:** Use `#value` to get result of the `Future` or `Promise`. Use `#wait` method before getting the value.

*   **Threats Mitigated:**
    *   **Silent Thread Termination (Severity: High):** Prevents asynchronous tasks from failing silently due to unhandled exceptions.
    *   **Inconsistent Application State (Severity: Medium):** Allows for graceful handling of errors in asynchronous operations, preventing the application from entering an inconsistent state.

*   **Impact:**
    *   **Silent Thread Termination:** Risk significantly reduced.
    *   **Inconsistent Application State:** Risk moderately reduced.

*   **Currently Implemented:**
    *   `Future` objects are used in some parts of the code for fetching data from external APIs, but their `rescue` methods are not consistently used.

*   **Missing Implementation:**
    *   Comprehensive exception handling using `#rescue` is missing in several `Future` implementations.

## Mitigation Strategy: [Using `ThreadPoolExecutor#error_callback` (using `concurrent-ruby`)](./mitigation_strategies/using__threadpoolexecutor#error_callback___using__concurrent-ruby__.md)

*   **Description:**
  1.  **Use `ThreadPoolExecutor`:** Ensure you are using `Concurrent::ThreadPoolExecutor` for managing your thread pool.
  2.  **Set `error_callback`:** When creating the `ThreadPoolExecutor`, set the `error_callback` option to a lambda or a method that will be invoked whenever a task submitted to the pool raises an unhandled exception.
      ```ruby
      executor = Concurrent::ThreadPoolExecutor.new(
        # ... other options ...
        error_callback: ->(job, reason) {
          Rails.logger.error("Error in thread pool task: #{reason}, job: #{job.inspect}")
          # Potentially notify an error tracking service
        }
      )
      ```
  3.  **Handle the Exception:** Within the `error_callback`, you have access to the task (`job`) and the exception (`reason`).  Log the error, potentially notify an error tracking service, and decide whether to take any corrective action.

*   **Threats Mitigated:**
    *   **Silent Task Failures (Severity: High):** Prevents tasks submitted to a `ThreadPoolExecutor` from failing silently due to unhandled exceptions.
    *   **Loss of Diagnostic Information (Severity: Medium):** Provides a centralized place to log and handle exceptions from background tasks, improving debugging and monitoring.

*   **Impact:**
    *   **Silent Task Failures:** Risk significantly reduced.
    *   **Loss of Diagnostic Information:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Not currently implemented. The existing `FixedThreadPool` does not have an `error_callback`.

*   **Missing Implementation:**
    *   The `ThreadPoolExecutor` used for background tasks does not have an `error_callback` configured. This is a critical missing piece for robust error handling.

## Mitigation Strategy: [Actor Model (using `concurrent-ruby`)](./mitigation_strategies/actor_model__using__concurrent-ruby__.md)

*   **Description:**
    1.  **Identify Concurrency Problems:** Determine if the Actor model is a good fit for your problem. It excels in situations with complex interactions between concurrent entities.
    2.  **Define Actors:** Define your actors using `Concurrent::Actor::Context`. Each actor encapsulates its own state and behavior.
    3.  **Message Passing:** Actors communicate exclusively through message passing. Define the messages that each actor can receive and how it should respond to them. Use `!` (tell) to send messages asynchronously.
    4.  **Avoid Shared State:** Actors should *not* share mutable state. All communication should happen through messages.
    5.  **Supervision:** Consider using `Concurrent::Actor::Supervisor` to manage the lifecycle of your actors and handle failures.
    6. **Use `ask` method:** Use `ask` method to send message and receive result.

*   **Threats Mitigated:**
    *   **Data Races (Severity: High):** Eliminates shared mutable state by design, preventing data races.
    *   **Deadlocks (Severity: High):** Reduces the risk of deadlocks by avoiding explicit locking.
    *   **Complexity (Severity: Medium):** Can simplify reasoning about concurrency by providing a higher-level abstraction.

*   **Impact:**
    *   **Data Races:** Risk significantly reduced (near elimination).
    *   **Deadlocks:** Risk significantly reduced.
    *   **Complexity:** Can *increase* initial complexity but *reduce* long-term complexity for suitable problems.

*   **Currently Implemented:**
    *   Not currently used.

*   **Missing Implementation:**
    *   The Actor model could be a good fit for managing user sessions and handling concurrent requests for the same user, replacing the current mutable `Session` object. This would require a significant refactoring.

