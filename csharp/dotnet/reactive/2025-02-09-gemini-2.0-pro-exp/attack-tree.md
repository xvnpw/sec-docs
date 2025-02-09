# Attack Tree Analysis for dotnet/reactive

Objective: DoS/Resource Exhaustion OR Sensitive Data Leakage via Rx.NET

## Attack Tree Visualization

Goal: DoS/Resource Exhaustion OR Sensitive Data Leakage via Rx.NET
├── 1. Denial of Service / Resource Exhaustion [HIGH RISK]
│   ├── 1.1 Uncontrolled Subscription Growth [HIGH RISK]
│   │   ├── 1.1.2  Leaked Subscriptions (No Unsubscription) {CRITICAL} [HIGH RISK]
│   │   │   └── Exploit:  Trigger many subscriptions without proper disposal.
│   ├── 1.2  Expensive Operations in Observables
│   │   ├── 1.2.1  Blocking Operations on Scheduler Threads {CRITICAL} [HIGH RISK]
│   │   │   └── Exploit:  Inject input causing blocking operations within Rx operators.
│   │   └── 1.2.3  Unbounded Buffering [HIGH RISK]
│   │       └── Exploit: Use buffering operators without size/time limits.
├── 2. Sensitive Data Leakage
    ├── 2.1  Side Effects in Observables
    │   ├── 2.1.1  Logging Sensitive Data [HIGH RISK]
    │   │   └── Exploit: Log data within Rx operators without sanitization.

## Attack Tree Path: [1. Denial of Service / Resource Exhaustion [HIGH RISK]](./attack_tree_paths/1__denial_of_service__resource_exhaustion__high_risk_.md)

*   **Overall Rationale:** This branch represents the most significant threat due to the relative ease of exploiting Rx.NET to cause resource exhaustion or application crashes.

## Attack Tree Path: [1.1 Uncontrolled Subscription Growth [HIGH RISK]](./attack_tree_paths/1_1_uncontrolled_subscription_growth__high_risk_.md)

*   **Overall Rationale:**  Improper subscription management is a common source of errors in Rx.NET applications, leading to memory leaks and performance degradation.

## Attack Tree Path: [1.1.2 Leaked Subscriptions (No Unsubscription) {CRITICAL} [HIGH RISK]](./attack_tree_paths/1_1_2_leaked_subscriptions__no_unsubscription__{critical}__high_risk_.md)

*   **Exploit:** Trigger many subscriptions without proper disposal, leading to memory leaks and eventual application crash. (e.g., event handler repeatedly adds subscriptions but never removes them).
*   **Likelihood:** High (Common mistake in Rx.NET development)
*   **Impact:** High (Memory leaks, eventual application crash)
*   **Effort:** Low (Easy to trigger accidentally)
*   **Skill Level:** Novice
*   **Detection Difficulty:** Medium (Requires memory profiling and monitoring)
*   **Mitigation:**
    *   Always ensure subscriptions are disposed of when no longer needed.
    *   Use `DisposeWith` or `AddTo` (composite disposables) to manage subscription lifetimes.
    *   Avoid creating subscriptions within loops or event handlers without corresponding disposal logic.
    *   Conduct code reviews to identify potential subscription leaks.

## Attack Tree Path: [1.2 Expensive Operations in Observables](./attack_tree_paths/1_2_expensive_operations_in_observables.md)

*   **Overall Rationale:**  Performing computationally expensive or blocking operations within Rx operators can severely impact application performance and responsiveness.

## Attack Tree Path: [1.2.1 Blocking Operations on Scheduler Threads {CRITICAL} [HIGH RISK]](./attack_tree_paths/1_2_1_blocking_operations_on_scheduler_threads_{critical}__high_risk_.md)

*   **Exploit:** Inject input that causes a long-running, blocking operation (e.g., `Thread.Sleep`, heavy computation, synchronous I/O) to be executed within an Rx operator (like `Select`, `Where`, `Subscribe`) on a shared scheduler (e.g., `TaskPoolScheduler`, `ThreadPoolScheduler`). This blocks the scheduler, preventing other Rx operations from executing.
*   **Likelihood:** Medium (Common mistake, but good practices mitigate it)
*   **Impact:** High (Application unresponsiveness, thread starvation)
*   **Effort:** Low (Easy to trigger accidentally)
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Medium (Requires thread profiling and monitoring)
*   **Mitigation:**
    *   Avoid blocking operations within Rx operators.
    *   Use asynchronous versions of I/O operations (`async`/`await`).
    *   Offload long-running computations to a separate thread or process *before* entering the Rx pipeline.
    *   Use `ObserveOn` with an appropriate scheduler (e.g., `TaskPoolScheduler` for CPU-bound work).

## Attack Tree Path: [1.2.3 Unbounded Buffering [HIGH RISK]](./attack_tree_paths/1_2_3_unbounded_buffering__high_risk_.md)

*   **Exploit:** Use operators like `Buffer` or `Window` without appropriate size or time limits, causing the application to accumulate large amounts of data in memory if the downstream processing is slower than the input rate.
*   **Likelihood:** Medium (Requires specific use of buffering operators)
*   **Impact:** High (Memory exhaustion, application crash)
*   **Effort:** Low (If buffering operators are used without limits)
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Medium (Requires memory profiling)
*   **Mitigation:**
    *   Always specify size or time limits when using `Buffer`, `Window`, or similar operators.
    *   Consider using backpressure mechanisms (e.g., `Sample`, `Throttle`) to control the flow of data.
    *   Monitor memory usage to detect potential unbounded buffering issues.

## Attack Tree Path: [2. Sensitive Data Leakage](./attack_tree_paths/2__sensitive_data_leakage.md)

*   **Overall Rationale:** While less likely than DoS, data leakage can have severe consequences.

## Attack Tree Path: [2.1 Side Effects in Observables](./attack_tree_paths/2_1_side_effects_in_observables.md)

*   **Overall Rationale:** Performing side effects within Rx operators can inadvertently expose sensitive data.

## Attack Tree Path: [2.1.1 Logging Sensitive Data [HIGH RISK]](./attack_tree_paths/2_1_1_logging_sensitive_data__high_risk_.md)

*   **Exploit:** If the application logs data within an Rx operator (e.g., `Do`, `Subscribe`) without proper sanitization, sensitive information flowing through the stream might be exposed in logs.
*   **Likelihood:** Medium (Depends on logging practices)
*   **Impact:** High (Exposure of sensitive information)
*   **Effort:** Low (If logging is already in place)
*   **Skill Level:** Novice
*   **Detection Difficulty:** Medium (Requires log analysis)
*   **Mitigation:**
    *   Avoid logging sensitive data directly within Rx operators.
    *   Sanitize or redact sensitive information before logging.
    *   Implement strict logging policies and review them regularly.
    *   Use a secure logging infrastructure that protects log data from unauthorized access.

