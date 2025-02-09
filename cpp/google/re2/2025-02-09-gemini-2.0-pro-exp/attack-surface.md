# Attack Surface Analysis for google/re2

## Attack Surface: [Algorithmic Complexity Attacks (Resource Exhaustion)](./attack_surfaces/algorithmic_complexity_attacks__resource_exhaustion_.md)

**Description:**  Attackers craft input strings and/or regular expressions that, while technically processed in linear time by re2, still consume excessive CPU or memory resources, leading to performance degradation or denial of service.
    *   **How re2 Contributes:** re2's linear time guarantee prevents *catastrophic* backtracking, but doesn't guarantee *fast* execution for all inputs.  The constant factor in the linear time complexity can be large, and complex regexes or very long inputs can still lead to significant resource consumption.
    *   **Example:**
        *   Input String: A very long string (e.g., 1MB) of repeating characters like "aaaaaaaa...".
        *   Regular Expression:  A seemingly simple regex like `a?a?a?a?a?a?a?a?a?a?aaaaaaaaaa` (repeated many times).  Or, a regex with many alternations: `(a|b|c|d|e|f|g|h|i|j|...){100}`.
    *   **Impact:**  Application slowdown, denial of service (DoS), potential for resource exhaustion on the server.
    *   **Risk Severity:** High (Potentially Critical if resource limits are not properly configured)
    *   **Mitigation Strategies:**
        *   **Strict Input Length Limits:** Impose very strict limits on the length of both the input string and the regular expression (if user-supplied).  Prioritize this mitigation.
        *   **Regular Expression Complexity Limits:** Limit the number of operators, nesting depth, and use of lookarounds in regular expressions.  If user-supplied, use a strict whitelist.
        *   **re2 Memory Limits:** Configure re2's `max_mem` option to set a hard limit on memory allocation.
        *   **Resource Monitoring and Throttling:** Monitor CPU/memory usage and terminate re2 operations that exceed thresholds.
        *   **Profiling and Benchmarking:** Test with a variety of inputs, including malicious ones, to identify performance bottlenecks.

## Attack Surface: [Large Intermediate State (Memory Exhaustion)](./attack_surfaces/large_intermediate_state__memory_exhaustion_.md)

*   **Description:**  Certain regular expressions, even without backtracking, can cause re2 to create a large internal state (DFA/NFA), consuming significant memory.
    *   **How re2 Contributes:** re2's internal state machine size depends on the complexity of the regular expression.  Certain constructs, even if handled linearly, can lead to a large state.
    *   **Example:** A regular expression with many alternations or character classes, especially if nested: `([abcde...xyz]|[12345...7890])([abcde...xyz]|[12345...7890])...` (repeated).
    *   **Impact:**  Memory exhaustion, application crashes, potential for denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Regex Complexity Limits:** Limit the number of operators, nesting, and character classes.
        *   **re2 Memory Limits:** (Crucial) Use `re2::RE2::Options` and set `max_mem` to a reasonable value.
        *   **Avoid Unnecessary Capturing Groups:** Use non-capturing groups `(?:...)` whenever possible.

## Attack Surface: [Unsafe Use of User-Provided Regular Expressions](./attack_surfaces/unsafe_use_of_user-provided_regular_expressions.md)

*   **Description:** The application allows users to input their own regular expressions without adequate sanitization or validation.
    *   **How re2 Contributes:** While re2 mitigates many traditional ReDoS attacks, user-provided regexes still pose a risk of resource exhaustion or unexpected behavior, even if not a full ReDoS.  The *combination* of user input and re2 creates this risk.
    *   **Example:** A user provides a regex with a very large number of alternations or nested quantifiers, designed to consume excessive resources, even if it doesn't cause exponential backtracking.
    *   **Impact:**  Denial of service, resource exhaustion, potential for unexpected application behavior.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid User-Supplied Regexes:** This is the *best* mitigation.  Use predefined options or a more controlled input method.
        *   **Strict Whitelisting (if unavoidable):**  Implement a very restrictive whitelist of allowed characters and constructs.
        *   **Complexity Limits:** Enforce strict limits on length and complexity.
        *   **Sandboxing (Advanced):** Run re2 matching in a sandboxed environment with limited resources.

