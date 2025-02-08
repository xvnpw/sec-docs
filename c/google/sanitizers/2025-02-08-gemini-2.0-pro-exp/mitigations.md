# Mitigation Strategies Analysis for google/sanitizers

## Mitigation Strategy: [Selective Sanitization](./mitigation_strategies/selective_sanitization.md)

**1. Mitigation Strategy: Selective Sanitization**

*   **Description:**
    1.  **Identify Critical Code Paths:** Analyze application architecture to pinpoint security-critical and stability-critical modules/functions (e.g., memory management, network I/O, input parsing).
    2.  **Prioritize Sanitizers:**  Match sanitizers to code sections based on likely vulnerabilities:
        *   **AddressSanitizer (ASan):** Memory-intensive operations, pointer arithmetic, potential buffer overflows.
        *   **ThreadSanitizer (TSan):** Concurrent code, shared data access, potential race conditions.
        *   **MemorySanitizer (MSan):** Handling uninitialized memory, especially from external sources.
        *   **UndefinedBehaviorSanitizer (UBSan):** Complex arithmetic, bitwise operations, type conversions.
        *   **LeakSanitizer (LSan):** Periodically, especially before releases, to find memory leaks.
    3.  **Configure Build System:**  Modify the build system (CMake, Make, etc.) to enable/disable sanitizers for specific targets or files.  Use compiler flags (`-fsanitize=address` for specific files) or environment variables (`ASAN_OPTIONS=include=my_module.so`).
    4.  **Create Test Suites:**  Develop separate test suites or configurations for different sanitizer combinations (e.g., "fast" tests without sanitizers, an "ASan" suite, a "TSan" suite).
    5.  **Automate:** Integrate sanitizer runs into the CI pipeline, scheduling them strategically (e.g., ASan on every commit to critical modules, TSan nightly).

*   **Threats Mitigated:**
    *   **Performance Degradation (High Severity):**  Reduces the slowdown caused by running all sanitizers constantly.
    *   **Resource Exhaustion (Medium Severity):**  Minimizes memory usage, preventing out-of-memory errors during testing.
    *   **Delayed Feedback (Medium Severity):**  Shortens test run times, providing faster feedback.

*   **Impact:**
    *   **Performance Degradation:** Reduces overhead by 50-90% (depending on selectivity).
    *   **Resource Exhaustion:** Reduces memory usage by 40-80% (especially for ASan).
    *   **Delayed Feedback:**  Provides faster feedback.

*   **Currently Implemented:**
    *   Partially. ASan is enabled for the `memory_management` module in CI. TSan is used manually for concurrent features.

*   **Missing Implementation:**
    *   No systematic approach for other modules.
    *   No automated scheduling of different sanitizer runs in CI.
    *   Lack of dedicated test suites for specific sanitizer configurations.
    *   UBSan and MSan are not used consistently.

## Mitigation Strategy: [Optimized Sanitized Builds](./mitigation_strategies/optimized_sanitized_builds.md)

**2. Mitigation Strategy: Optimized Sanitized Builds**

*   **Description:**
    1.  **Create Separate Build Configuration:**  Define a new build configuration (e.g., "SanitizedDebug") in the build system.
    2.  **Set Optimization Level:**  Set the optimization level to `-O1` or `-O2`.  *Avoid* `-O3` as it can interfere with sanitizer accuracy.
    3.  **Enable Sanitizers:**  Enable the desired sanitizers (e.g., `-fsanitize=address,thread`) in this configuration.
    4.  **Link with Sanitizer Runtime:** Ensure the build links with the correct sanitizer runtime libraries.
    5. **Adjust Debugging Features (Optional):** If performance is critical, consider using a lower level of debug info (e.g., `-g1` instead of full `-g`).

*   **Threats Mitigated:**
    *   **Performance Degradation (High Severity):** Optimized builds reduce sanitizer overhead.
    *   **False Negatives (Medium Severity):**  Excessive optimization (`-O3`) can cause missed errors. `-O1` or `-O2` improves accuracy.
    *   **Inaccurate Stack Traces (Low Severity):** Higher optimization can make stack traces less informative.

*   **Impact:**
    *   **Performance Degradation:** Reduces overhead by 10-30% compared to unoptimized sanitized builds.
    *   **False Negatives:** Improves accuracy.
    *   **Inaccurate Stack Traces:** Provides more detailed stack traces.

*   **Currently Implemented:**
    *   Partially. A "SanitizedDebug" configuration exists but isn't consistently used.

*   **Missing Implementation:**
    *   "SanitizedDebug" isn't automatically used in CI or by all developers.
    *   The optimization level for "SanitizedDebug" isn't consistently `-O1` or `-O2`.

## Mitigation Strategy: [Suppression Files (with Rigorous Review)](./mitigation_strategies/suppression_files__with_rigorous_review_.md)

**3. Mitigation Strategy: Suppression Files (with Rigorous Review)**

*   **Description:**
    1.  **Identify False Positives:** Run tests with sanitizers and carefully analyze each report. Determine if it's a genuine bug or a false positive.
    2.  **Create Suppression File:** Create a text file (e.g., `sanitizer_suppressions.txt`) listing false positives. Use the correct syntax for the specific sanitizer (check documentation).  Example (ASan):
        ```
        interceptor_via_fun:some_third_party_function
        leak:some_library_internal_allocation
        ```
    3.  **Document Rationale:** *Crucially*, add comments explaining *why* each suppression is necessary. Include:
        *   The specific function/code.
        *   The reason it's benign (e.g., known third-party issue, harmless data race).
        *   Relevant bug reports or documentation links.
    4.  **Configure Sanitizers:** Use the appropriate environment variable to point the sanitizer to the suppression file (e.g., `ASAN_OPTIONS=suppressions=sanitizer_suppressions.txt`).
    5.  **Regular Review:** Establish a process for regularly reviewing and updating the suppression file:
        *   After major code changes.
        *   When upgrading third-party libraries.
        *   On a fixed schedule (e.g., monthly).
    6. **Automated Checks (Optional):** Consider CI checks to detect unused or invalid suppressions.

*   **Threats Mitigated:**
    *   **False Positives (Medium Severity):** Prevents false positives from cluttering results.
    *   **Wasted Development Time (Low Severity):** Reduces time spent investigating known issues.
    *   **Desensitization to Errors (Medium Severity):** *Reduces* risk if suppressions are used judiciously; *increases* risk if used carelessly.

*   **Impact:**
    *   **False Positives:** Eliminates noise from known false positives.
    *   **Wasted Development Time:** Saves time.
    *   **Desensitization to Errors:** Reduces/increases risk depending on usage.

*   **Currently Implemented:**
    *   Partially. A suppression file exists for ASan, but lacks detailed documentation and regular review.

*   **Missing Implementation:**
    *   Comprehensive documentation for each suppression.
    *   Formal process for review and updates.
    *   Automated checks for unused/invalid suppressions.
    *   Suppression files for other sanitizers (TSan, UBSan, MSan).

## Mitigation Strategy: [Signal Handling Awareness](./mitigation_strategies/signal_handling_awareness.md)

**4. Mitigation Strategy: Signal Handling Awareness**

* **Description:**
    1. **Identify Signal Usage:** Review the application code to identify all places where signals are used (e.g., `signal()`, `sigaction()`).
    2. **Understand Sanitizer Signals:** Consult the documentation for each sanitizer to understand which signals it uses internally.
    3. **Avoid Conflicts:**
        * If possible, avoid using the same signals as the sanitizers.
        * If signal usage is unavoidable, use `sigaction()` with the `SA_SIGINFO` flag to get more information about the signal and determine if it originated from the sanitizer or the application.
        * Consider using `sigaltstack()` to provide a separate signal stack for the application or the sanitizers, preventing stack overflow issues.
    4. **Test Signal Handling:** Write specific tests to verify that signal handling works correctly in the presence of sanitizers.

* **Threats Mitigated:**
    * **Application Crashes (High Severity):** Conflicts between application signal handlers and sanitizer signal handlers can lead to unexpected crashes.
    * **Sanitizer Malfunction (Medium Severity):** Interfering with the sanitizer's internal signal handling can prevent it from detecting errors or reporting them correctly.
    * **Non-deterministic behavior (Low severity):** Signal handling can introduce non-deterministic behavior, especially in multi-threaded applications.

* **Impact:**
    * **Application Crashes:** Prevents crashes caused by signal conflicts.
    * **Sanitizer Malfunction:** Ensures that sanitizers function correctly.
    * **Non-deterministic behavior:** Improves the reliability and predictability of the application.

* **Currently Implemented:**
    * Not implemented. The application uses signals for handling specific events, but there is no specific consideration for sanitizer compatibility.

* **Missing Implementation:**
    * No review of signal usage in relation to sanitizer signals.
    * No use of `sigaltstack()` or `SA_SIGINFO`.
    * No dedicated tests for signal handling with sanitizers.

## Mitigation Strategy: [Sanitizer Runtime Configuration Tuning](./mitigation_strategies/sanitizer_runtime_configuration_tuning.md)

**5. Mitigation Strategy: Sanitizer Runtime Configuration Tuning**

*   **Description:**
    1.  **Review Sanitizer Documentation:** Thoroughly read the documentation for each sanitizer being used (ASan, TSan, etc.) to understand all available runtime options.
    2.  **Identify Relevant Options:** Based on the application's characteristics and testing needs, identify options that can be tuned to improve performance, reduce false positives, or enhance detection capabilities. Examples:
        *   **ASan:** `detect_leaks`, `fast_unwind_on_malloc`, `quarantine_size_mb`, `allocator_may_return_null`, `detect_stack_use_after_return`.
        *   **TSan:** `history_size`, `report_atomic_races`, `second_deadlock_stack`.
        *   **MSan:** `poison_in_dtors`, `wrap_signals`.
        *   **UBSan:** `print_stacktrace`.
    3.  **Experiment and Measure:**  Experiment with different option values, carefully measuring the impact on performance, memory usage, and the number of reported errors.
    4.  **Set Options:**  Set the chosen options using environment variables (e.g., `ASAN_OPTIONS`, `TSAN_OPTIONS`).
    5. **Document Configuration:** Clearly document the chosen sanitizer runtime configuration and the rationale behind each setting.

*   **Threats Mitigated:**
    *   **Performance Degradation (High Severity):** Tuning options can significantly reduce sanitizer overhead.
    *   **False Positives (Medium Severity):** Some options can help reduce false positives by adjusting the sanitizer's sensitivity.
    *   **Resource Exhaustion (Medium Severity):** Options like `quarantine_size_mb` (ASan) can help control memory usage.
    *   **Missed Errors (Medium Severity):** Some options can enhance detection capabilities (e.g., `detect_stack_use_after_return` in ASan).

*   **Impact:**
    *   **Performance Degradation:** Can reduce overhead by 10-50% depending on the options and application.
    *   **False Positives:** Can reduce the number of false positives.
    *   **Resource Exhaustion:** Can help manage resource usage.
    *   **Missed Errors:** Can improve detection of certain types of errors.

*   **Currently Implemented:**
    *   Not implemented. Default sanitizer options are used.

*   **Missing Implementation:**
    *   No systematic review of sanitizer runtime options.
    *   No experimentation with different option values.
    *   No documented sanitizer runtime configuration.

