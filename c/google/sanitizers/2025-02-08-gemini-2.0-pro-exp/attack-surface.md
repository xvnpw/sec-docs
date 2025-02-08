# Attack Surface Analysis for google/sanitizers

## Attack Surface: [Slowdown Attacks (DoS)](./attack_surfaces/slowdown_attacks__dos_.md)

*   **Description:**  Attacker crafts input to trigger worst-case performance within the sanitizers, slowing down the application significantly.
*   **Sanitizer Contribution:** Sanitizers add runtime overhead; specific code paths within the *sanitizers themselves* can be targeted.
*   **Example:**  Repeatedly allocating and deallocating many small objects to stress ASan's shadow memory and metadata management.  Or, crafting input that triggers many UBSan checks on a hot code path.
*   **Impact:**  Denial of Service; application becomes unresponsive or unusable.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Implement robust input validation and rate limiting *before* the input reaches code heavily instrumented by sanitizers.  Profile the application with sanitizers enabled to identify performance bottlenecks.  Consider using less aggressive sanitizer options (e.g., `detect_leaks=0` for LSan in production if leaks are a lower risk). Optimize code to reduce the number of sanitizer checks triggered.
    *   **User:** (Limited direct mitigation) Ensure the application is running on a system with sufficient resources.

## Attack Surface: [Memory Exhaustion (DoS via Sanitizer Overhead)](./attack_surfaces/memory_exhaustion__dos_via_sanitizer_overhead_.md)

*   **Description:** Attacker exploits the increased memory usage of sanitizers (especially ASan/MSan) to cause an Out-Of-Memory (OOM) condition.
*   **Sanitizer Contribution:** ASan and MSan significantly increase memory usage due to shadow memory and metadata.
*   **Example:**  Allocating large blocks of memory, even if legitimately used and freed, to exhaust the shadow memory space used by ASan.
*   **Impact:**  Denial of Service; application crashes due to OOM.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:**  Set realistic memory limits for the application (e.g., using `ulimit` or containerization).  Monitor memory usage, including sanitizer overhead.  Consider using a less memory-intensive sanitizer configuration if appropriate.  Optimize memory allocation patterns.
    *   **User:**  Ensure the application is running on a system with sufficient memory, considering the increased requirements of sanitizers.

## Attack Surface: [Incorrect Suppression File Usage](./attack_surfaces/incorrect_suppression_file_usage.md)

*   **Description:** Overly broad or incorrect suppression files mask real vulnerabilities.
*   **Sanitizer Contribution:** Suppression files are a feature of sanitizers to ignore known issues.
*   **Example:** Suppressing all `heap-use-after-free` errors in a library instead of specific, analyzed instances.
*   **Impact:**  Vulnerabilities remain undetected and exploitable.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:**  Carefully review and audit suppression files.  Use the most specific suppressions possible (e.g., targeting specific functions and line numbers).  Regularly re-evaluate and update suppression files as the codebase evolves.  Document the rationale for each suppression.
    *   **User:** (No direct mitigation)

