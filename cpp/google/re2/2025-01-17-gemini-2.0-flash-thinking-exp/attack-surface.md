# Attack Surface Analysis for google/re2

## Attack Surface: [Maliciously Crafted Regular Expressions](./attack_surfaces/maliciously_crafted_regular_expressions.md)

*   **Description:** An attacker provides a specially crafted regular expression intended to cause excessive resource consumption during compilation or matching. While `re2` is designed to prevent catastrophic backtracking, other resource exhaustion scenarios are possible.
    *   **How `re2` Contributes to the Attack Surface:** `re2` is the engine responsible for parsing and executing the provided regular expression. Its internal algorithms and data structures are used to process the regex. Complex or deeply nested regexes can still strain `re2`'s resources.
    *   **Example:** An attacker provides a regex with a very large number of capturing groups or alternations, like `(a|b|c|d|...){1000}`. While it won't cause infinite loops, compiling or matching this against a large input could consume significant CPU and memory.
    *   **Impact:** Denial of Service (DoS) due to resource exhaustion, potentially making the application unresponsive or crashing it.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Validation:** Implement strict validation and sanitization of user-provided regular expressions. Limit the complexity (e.g., maximum length, number of alternations, nesting depth) of allowed regexes.
        *   **Timeouts:** Set timeouts for `re2` compilation and matching operations. If an operation takes too long, terminate it.
        *   **Resource Limits:** Configure resource limits (e.g., CPU time, memory usage) for the processes or threads executing `re2`.
        *   **Sandboxing:** If possible, execute `re2` operations in a sandboxed environment to limit the impact of resource exhaustion.

## Attack Surface: [Use of Untrusted Regular Expression Sources](./attack_surfaces/use_of_untrusted_regular_expression_sources.md)

*   **Description:** If the application allows users or external sources to provide regular expressions that are then used by `re2`, this introduces a significant risk as attackers can directly control the regex being executed.
    *   **How `re2` Contributes to the Attack Surface:** `re2` will faithfully execute any valid regular expression provided to it. If that regex is malicious, `re2` becomes the tool for the attack.
    *   **Example:** A web application allows users to define custom search filters using regular expressions. An attacker provides a regex designed to consume excessive resources or exploit a potential vulnerability in `re2`.
    *   **Impact:** Denial of Service, potential for exploiting vulnerabilities in `re2`, or unintended data exposure depending on how the matching results are used.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid Untrusted Regex Sources:**  Ideally, avoid allowing users or external sources to provide arbitrary regular expressions.
        *   **Predefined Regexes:** Use a predefined set of safe and well-tested regular expressions.
        *   **Regex Sanitization/Analysis (Limited Effectiveness):** Attempt to sanitize or analyze user-provided regexes for potentially dangerous patterns, but this is difficult to do reliably.
        *   **Sandboxing and Resource Limits (Crucial):** If untrusted regexes must be used, execute `re2` operations in a heavily sandboxed environment with strict resource limits and timeouts.

