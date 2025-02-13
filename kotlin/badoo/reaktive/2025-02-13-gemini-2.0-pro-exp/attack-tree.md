# Attack Tree Analysis for badoo/reaktive

Objective: DoS or ACE in Application Using Reaktive

## Attack Tree Visualization

Goal: DoS or ACE in Application Using Reaktive

├── 1. Denial of Service (DoS) [HIGH-RISK]
│   ├── 1.1 Resource Exhaustion [HIGH-RISK]
│   │   ├── 1.1.1 Uncontrolled Thread Creation [HIGH-RISK]
│   │   │   └── 1.1.1.1 Exploit Misconfigured Scheduler [CRITICAL] [HIGH-RISK]
│   │   ├── 1.1.2 Memory Exhaustion [HIGH-RISK]
│   │   │   ├── 1.1.2.1 Exploit Unbounded Buffers/Caches [CRITICAL] [HIGH-RISK]
│   │   │   └── 1.1.2.2 Exploit Leaked Observers/Disposables [HIGH-RISK]
│   │   └── 1.1.3.2 Exploit Blocking Operations on Main Thread [CRITICAL] [HIGH-RISK]

## Attack Tree Path: [1. Denial of Service (DoS) [HIGH-RISK]](./attack_tree_paths/1__denial_of_service__dos___high-risk_.md)

*   **Description:** The attacker aims to make the application unavailable to legitimate users. This is the most likely and easily achievable attack category within the context of Reaktive.
*   **Overall Likelihood:** High
*   **Overall Impact:** High

## Attack Tree Path: [1.1 Resource Exhaustion [HIGH-RISK]](./attack_tree_paths/1_1_resource_exhaustion__high-risk_.md)

*   **Description:** The attacker attempts to consume excessive system resources (CPU, memory, threads), leading to a denial of service.
*   **Overall Likelihood:** High
*   **Overall Impact:** High

## Attack Tree Path: [1.1.1 Uncontrolled Thread Creation [HIGH-RISK]](./attack_tree_paths/1_1_1_uncontrolled_thread_creation__high-risk_.md)

*   **Description:** The attacker triggers operations that create a large number of threads, overwhelming the system's thread pool and potentially causing the application to crash or become unresponsive.
*   **Overall Likelihood:** Medium
*   **Overall Impact:** High

## Attack Tree Path: [1.1.1.1 Exploit Misconfigured Scheduler [CRITICAL] [HIGH-RISK]](./attack_tree_paths/1_1_1_1_exploit_misconfigured_scheduler__critical___high-risk_.md)

*   **Action:** The attacker triggers operations that, due to a misconfigured or default (unbounded) scheduler, create new threads without any limits. This can rapidly exhaust system resources.
*   **Likelihood:** Medium (Common misconfiguration)
*   **Impact:** High (System-wide DoS)
*   **Effort:** Low (Simple requests can trigger this)
*   **Skill Level:** Novice
*   **Detection Difficulty:** Medium (Requires monitoring thread counts)
*   **Mitigation:** *Always* use a bounded scheduler (e.g., `Schedulers.boundedElastic`, `Schedulers.computation(maxSize)`). Configure the maximum number of threads appropriately. Implement rate limiting and circuit breakers.

## Attack Tree Path: [1.1.2 Memory Exhaustion [HIGH-RISK]](./attack_tree_paths/1_1_2_memory_exhaustion__high-risk_.md)

*   **Description:** The attacker causes the application to consume excessive memory, leading to out-of-memory errors and application crashes.
*   **Overall Likelihood:** High
*   **Overall Impact:** High

## Attack Tree Path: [1.1.2.1 Exploit Unbounded Buffers/Caches [CRITICAL] [HIGH-RISK]](./attack_tree_paths/1_1_2_1_exploit_unbounded_bufferscaches__critical___high-risk_.md)

*   **Action:** The attacker sends a large volume of data or triggers operations that fill unbounded buffers or caches within Reaktive operators. This can quickly consume all available memory.
*   **Likelihood:** Medium (Common misconfiguration)
*   **Impact:** High (System-wide DoS)
*   **Effort:** Low (Large requests can trigger this)
*   **Skill Level:** Novice
*   **Detection Difficulty:** Medium (Requires monitoring memory usage)
*   **Mitigation:** *Always* use bounded buffers and caches (e.g., `buffer(count)`, `window(count)`). Configure buffer sizes based on expected data and available memory. Use backpressure mechanisms.

## Attack Tree Path: [1.1.2.2 Exploit Leaked Observers/Disposables [HIGH-RISK]](./attack_tree_paths/1_1_2_2_exploit_leaked_observersdisposables__high-risk_.md)

*   **Action:** The attacker triggers operations that create observers or disposables, but due to a programming error, these resources are never properly disposed of. This leads to a gradual memory leak, eventually causing a denial of service.
*   **Likelihood:** Medium (Common programming error)
*   **Impact:** Medium/High (Gradual DoS, potentially system-wide)
*   **Effort:** Low (Repeated requests can trigger this)
*   **Skill Level:** Novice
*   **Detection Difficulty:** Hard (Requires memory leak analysis)
*   **Mitigation:** Ensure *all* `Disposable` objects are properly disposed of. Use `using` blocks or `autoDispose` to automate resource cleanup. Implement memory leak detection tools.

## Attack Tree Path: [1.1.3.2 Exploit Blocking Operations on Main Thread [CRITICAL] [HIGH-RISK]](./attack_tree_paths/1_1_3_2_exploit_blocking_operations_on_main_thread__critical___high-risk_.md)

*   **Action:** The attacker triggers long-running or blocking operations that are incorrectly executed on the main thread (often the UI thread). This freezes the application's user interface, making it unresponsive.
*   **Likelihood:** Medium (Common programming error)
*   **Impact:** High (Application freeze, UI unresponsiveness)
*   **Effort:** Low (Simple requests can trigger this)
*   **Skill Level:** Novice
*   **Detection Difficulty:** Easy (UI freeze is immediately obvious)
*   **Mitigation:** *Never* perform blocking operations on the main thread. Use appropriate schedulers (e.g., `Schedulers.io`) for I/O-bound or long-running tasks. Use asynchronous operations and callbacks.

