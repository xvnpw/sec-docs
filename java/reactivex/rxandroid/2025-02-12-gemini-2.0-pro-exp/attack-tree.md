# Attack Tree Analysis for reactivex/rxandroid

Objective: To cause a denial-of-service (DoS) or leak sensitive data within an Android application by exploiting RxAndroid-specific vulnerabilities or misconfigurations.

## Attack Tree Visualization

```
                                      +-------------------------------------------------+
                                      |  Compromise Android App using RxAndroid (DoS/Data Leak) [!] |
                                      +-------------------------------------------------+
                                                        |
          +----------------------------------------------------------------------------------------------------------------+
          |                                                                                                                |
+-------------------------+                                                                                +-------------------------+
|  Denial of Service (DoS) [!] |                                                                                |     Sensitive Data Leak [!]    |
+-------------------------+                                                                                +-------------------------+
          |                                                                                                                |
+---------------------+---------------------+---------------------+                                  +---------------------+
|  Resource Exhaustion |  Scheduler Abuse   |  Backpressure Issues |                                  |  Improper Error Handling|
+---------------------+---------------------+---------------------+                                  +---------------------+
          |                     |                     |                                                  |
+-------+               +-------+-------+     +-------+                                           +-------+-------+
|  Long-|               |  Inap-|  Block-|     |  Miss-|                                           |  Ex-  |  Log   |
|  Run- |               |  pro- |  ing   |     |  ing  |                                           |  pose |  Sen-  |
|  ning |               |  pri- |  Sched-|     |  Hand-|                                           |  Err- |  sitive|
|  Ob-  |               |  ate  |  uler  |---> |  ler  |                                           |  ors  |  Data  |
|  serv-|               |  Sched-|  Calls |     |  [!]  |                                           |  with |  in    |
|  ables|               |  uler |  [!]  |     |       |                                           |  Info |  Error |
|  [!]  |               |  [!]  |        |     |       |                                           |  [!]  |  Mes-  |
|       |               |       |        |     |       |                                           |       |  sages |
|       |               |       |        |     |       |                                           |       |  [!]  |
+-------+               +-------+-------+     +-------+                                           +-------+-------+
    ^                       ^
    |                       |-------------------------------------------------------------------------------|
    |-----------------------|
          |
+-------+
|  Un-   |
|  bound|
|  Ob-  |
|  serv-|
|  ables|
|  [!]  |
+-------+
          |
          |
+-------+
|  Race  |
|  Con-  |
|  di-   |
|  tions |
|  [!]  |
+-------+
```

## Attack Tree Path: [1. Denial of Service (DoS) [!]](./attack_tree_paths/1__denial_of_service__dos___!_.md)

*   **1.1 Resource Exhaustion**

    *   **1.1.1 Long-Running Observables [!]**
        *   **Description:** The attacker triggers operations that create Observables which run for an extremely long time or never complete, tying up resources (CPU, memory, threads).
        *   **Example:** Malicious input to an image processing Observable causes an infinite loop or processing of a huge, malformed image.
        *   **Likelihood:** Medium
        *   **Impact:** High
        *   **Effort:** Low to Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium

    *   **1.1.2 Unbounded Observables [!]**
        *   **Description:** The attacker triggers the creation of Observables that emit an infinite or extremely large number of items without backpressure control, overwhelming the subscriber and consuming memory.
        *   **Example:** A manipulated server response causes a network request Observable to continuously emit data.
        *   **Likelihood:** Low to Medium
        *   **Impact:** High
        *   **Effort:** Low to Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium

*   **1.2 Scheduler Abuse**

    *   **1.2.1 Inappropriate Scheduler [!]**
        *   **Description:** The attacker influences the application to use an inappropriate Scheduler (e.g., the main thread) for a long-running or blocking operation.
        *   **Example:** Manipulated input forces a CPU-intensive task onto `AndroidSchedulers.mainThread()`, causing UI freezes.
        *   **Likelihood:** Medium
        *   **Impact:** Medium to High
        *   **Effort:** Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium

    *   **1.2.2 Blocking Scheduler Calls [!]**
        *   **Description:** The attacker crafts input that causes blocking operations on a critical Scheduler (like the main thread), leading to unresponsiveness.
        *   **Example:** A synchronous network call is forced onto the main thread via a misused `subscribeOn` or `observeOn`.
        *   **Likelihood:** Low to Medium
        *   **Impact:** High
        *   **Effort:** Medium to High
        *   **Skill Level:** Intermediate to Advanced
        *   **Detection Difficulty:** Medium

*   **1.3 Backpressure Issues**
    * **1.3.1 Missing Handler [!]**
        *   **Description:** The attacker triggers a fast-producing Observable where the subscriber lacks backpressure handling, leading to `MissingBackpressureException` or `OutOfMemoryError`.
        *   **Example:** A rapid stream of network events overwhelms a subscriber that doesn't use `onBackpressureBuffer`, `onBackpressureDrop`, etc.
        *   **Likelihood:** Low
        *   **Impact:** High
        *   **Effort:** Low
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Easy to Medium

## Attack Tree Path: [2. Sensitive Data Leak [!]](./attack_tree_paths/2__sensitive_data_leak__!_.md)

*   **2.1 Improper Error Handling**

    *   **2.1.1 Expose Errors with Info [!]**
        *   **Description:** The attacker triggers an error, and the poorly implemented error handling (e.g., `onError`) exposes sensitive information in error messages, logs, or the UI.
        *   **Example:** A crafted SQL injection (interacting with RxJava) throws an error revealing database schema details.
        *   **Likelihood:** Medium
        *   **Impact:** Medium to High
        *   **Effort:** Very Low
        *   **Skill Level:** Novice
        *   **Detection Difficulty:** Easy to Medium

    *   **2.1.2 Log Sensitive Data in Error Messages [!]**
        *   **Description:** Sensitive data is inadvertently included in error messages that are logged, and an attacker gains access to the logs.
        *   **Example:** User credentials or API keys are accidentally logged during an error.
        *   **Likelihood:** Medium
        *   **Impact:** Medium to High
        *   **Effort:** Very Low
        *   **Skill Level:** Novice
        *   **Detection Difficulty:** Hard

*   **2.2 Unintended Side Effects**
    *   **2.2.1 Race Conditions [!]**
        *  **Description:** Multiple Observables or Subjects interact without proper synchronization, leading to unpredictable behavior, including data corruption or exposure of intermediate, sensitive data.
        *   **Example:** Concurrent modifications to a shared data structure within different Observable chains lead to inconsistent state and potential data leaks.
        *   **Likelihood:** Low
        *   **Impact:** Medium to High
        *   **Effort:** High
        *   **Skill Level:** Expert
        *   **Detection Difficulty:** Very Hard

