# Threat Model Analysis for facebook/folly

## Threat: [Unbounded Executor Queue Growth Leading to Resource Exhaustion](./threats/unbounded_executor_queue_growth_leading_to_resource_exhaustion.md)

*   **Description:** An attacker submits a large number of tasks to a `folly::Executor` (e.g., `folly::CPUThreadPoolExecutor`, `folly::IOThreadPoolExecutor`) that are slow to process or never complete.  If the executor's queue is unbounded, these tasks accumulate, consuming memory and potentially other resources (e.g., file descriptors if tasks involve I/O) until the application crashes or becomes unresponsive.  The attacker might exploit a vulnerability in the application logic that allows them to trigger the creation of these slow tasks.
    *   **Impact:** Denial of Service (DoS). The application becomes unavailable to legitimate users.
    *   **Folly Component Affected:** `folly::Executor`, specifically implementations like `folly::CPUThreadPoolExecutor`, `folly::IOThreadPoolExecutor`, and any custom executors.  The `folly::futures::Future` and `folly::futures::Promise` APIs are also relevant, as they are often used in conjunction with executors.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use Bounded Queues:** Configure executors with bounded queues (e.g., using `setMaxQueueSize()` or similar methods).  Reject new tasks when the queue is full (consider returning an error or using a backpressure mechanism).
        *   **Implement Timeouts:** Set timeouts on tasks submitted to the executor.  If a task exceeds the timeout, cancel it and release any associated resources.  Use `folly::futures::sleep()` or `folly::futures::via()` to manage timeouts within futures.
        *   **Rate Limiting:** Implement rate limiting on the application logic that submits tasks to the executor.  Prevent a single user or source from submitting an excessive number of tasks.
        *   **Monitoring:** Monitor queue sizes and task execution times.  Alert on unusual growth or delays.

## Threat: [Deadlock in Asynchronous Operations](./threats/deadlock_in_asynchronous_operations.md)

*   **Description:**  Improper use of `folly::futures::Future`, `folly::futures::Promise`, and synchronization primitives (e.g., `folly::SharedMutex`, `folly::Synchronized`) leads to a deadlock.  Two or more futures are waiting for each other to complete, resulting in a permanent hang.  This can be triggered by complex interactions between asynchronous operations, especially if shared resources are involved.
    *   **Impact:** Denial of Service (DoS).  The affected part of the application, or potentially the entire application, becomes unresponsive.
    *   **Folly Component Affected:** `folly::futures::Future`, `folly::futures::Promise`, `folly::SharedMutex`, `folly::Synchronized`, and other synchronization primitives in `folly/synchronization`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Careful Design:** Design asynchronous operations to avoid circular dependencies between futures.  Minimize the use of shared mutable state.
        *   **Lock Ordering:** If multiple locks are required, establish a consistent lock acquisition order to prevent deadlocks.
        *   **Timeout on Waits:** Use timeouts when waiting on futures or locks (e.g., `wait_for()`, `wait_until()`).  This can help break potential deadlocks.
        *   **Deadlock Detection Tools:** Use tools that can help detect potential deadlocks during development (e.g., debuggers, static analysis tools).
        *   **Avoid Blocking in Callbacks:**  Avoid performing long-running or blocking operations within callbacks attached to futures.  This can tie up executor threads and increase the risk of deadlocks.

## Threat: [Slowloris-Style Attack on `folly::AsyncSocket`](./threats/slowloris-style_attack_on__follyasyncsocket_.md)

*   **Description:** An attacker establishes a large number of connections to the application using `folly::AsyncSocket` but sends data very slowly or keeps connections open without sending any data.  This consumes server resources (e.g., file descriptors, memory) and prevents legitimate clients from connecting.
    *   **Impact:** Denial of Service (DoS).  The application's network services become unavailable.
    *   **Folly Component Affected:** `folly::AsyncSocket`, `folly::AsyncTransport`, and related networking components in `folly/io`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Connection Timeouts:** Implement timeouts for both connection establishment and data transfer.  Close connections that are idle for too long.  Use `folly::AsyncSocket::setIdleTimeout()` and related methods.
        *   **Connection Limits:** Limit the number of concurrent connections from a single IP address or source.
        *   **Request Timeouts:**  Set timeouts for processing individual requests.
        *   **Resource Monitoring:** Monitor the number of open connections, active sockets, and resource usage.

## Threat: [Use-After-Free in `folly::IOBuf` Handling](./threats/use-after-free_in__follyiobuf__handling.md)

*   **Description:** Incorrect handling of `folly::IOBuf` objects, particularly when sharing them between threads or asynchronous operations, leads to a use-after-free vulnerability.  An attacker might be able to trigger this by manipulating network input or exploiting race conditions.  This could lead to a crash or potentially arbitrary code execution.
    *   **Impact:**  Denial of Service (DoS), Potential Remote Code Execution (RCE).
    *   **Folly Component Affected:** `folly::IOBuf`, and related classes in `folly/io`.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Careful Ownership:**  Clearly define the ownership and lifetime of `IOBuf` objects.  Use `IOBuf::clone()` or `IOBuf::copy()` appropriately to create independent copies when sharing data.
        *   **Reference Counting:**  Use `IOBuf::share()` to create shared ownership of `IOBuf` data.  Ensure that all references are released before the underlying memory is freed.
        *   **Memory Safety Tools:** Use AddressSanitizer (ASan) or Valgrind to detect use-after-free errors during development and testing.
        *   **Avoid Raw Pointers:** Minimize the use of raw pointers to access `IOBuf` data.  Use the provided methods (e.g., `IOBuf::data()`, `IOBuf::writableData()`) with caution.

