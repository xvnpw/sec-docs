# Attack Tree Analysis for humanizr/humanizer

Objective: DoS or Code Execution via Humanizer

## Attack Tree Visualization

```
                                     Attacker Goal:
                                 DoS or Code Execution via Humanizer
                                              |
                                 ---------------------------------
                                 |                               |
                      1. Input-Based Attacks          2. Resource Exhaustion Attacks
                                 |                               |
          --------------------------               --------------------------
          |                                        |                        |
1.1 Format String                  1.2 Regular Expression          2.1 Large Input
    Vulnerability                      DoS (ReDoS)                    Strings
          |                                        |                        |
    --------------                        --------------           --------------
    |                                     |                        |            |
1.1.1 [CRITICAL]                     1.2.1 [HIGH RISK]          2.1.1        2.1.2
Uncontrolled                          Unvetted                   Very Long    Very Long
Format String                         Regex in                   Numbers      Strings
in Humanizer                          Humanizer                  [HIGH RISK]  [HIGH RISK]
Functions                             Functions
```

## Attack Tree Path: [1.1 Format String Vulnerability](./attack_tree_paths/1_1_format_string_vulnerability.md)

*   **1.1.1 Uncontrolled Format String in Humanizer Functions [CRITICAL]**
    *   **Description:** The attacker gains control over the format string argument passed to a Humanizer function (or a function Humanizer uses internally, like `String.Format` if used improperly). This allows them to inject format specifiers that can read from or write to arbitrary memory locations.
    *   **Likelihood:** Very Low. .NET's string formatting is generally safe, and it's highly improbable that Humanizer would expose this vulnerability.
    *   **Impact:** Very High. Could lead to arbitrary code execution, complete system compromise.
    *   **Effort:** Medium. Requires finding the vulnerability (if it exists) and crafting a complex exploit.
    *   **Skill Level:** High. Requires deep understanding of format string vulnerabilities and .NET internals.
    *   **Detection Difficulty:** Medium. Static analysis tools *might* detect this, but it could be missed. Runtime detection would likely be through crashes or unexpected behavior.
    *   **Mitigation:** Ensure that Humanizer *never* uses user-supplied input as the format string argument to `String.Format` or similar functions.  Thorough code review and static analysis are crucial.

## Attack Tree Path: [1.2 Regular Expression DoS (ReDoS)](./attack_tree_paths/1_2_regular_expression_dos__redos_.md)

*   **1.2.1 Unvetted Regex in Humanizer Functions [HIGH RISK]**
    *   **Description:** Humanizer uses a regular expression internally that is vulnerable to catastrophic backtracking. The attacker crafts input that triggers this backtracking, causing the regex engine to consume excessive CPU time and potentially hang the application.
    *   **Likelihood:** Medium. This is a common vulnerability in applications that use regular expressions.
    *   **Impact:** Medium. Leads to a Denial-of-Service (DoS) – the application becomes unresponsive.
    *   **Effort:** Low to Medium. Requires identifying a vulnerable regex (through code review or fuzzing) and crafting input to trigger the worst-case behavior.
    *   **Skill Level:** Medium. Requires understanding of ReDoS vulnerabilities and regular expression syntax.
    *   **Detection Difficulty:** Medium. Can be detected by specialized ReDoS analysis tools, fuzz testing, or monitoring for high CPU usage.
    *   **Mitigation:**
        *   Thoroughly review all regular expressions used in Humanizer for ReDoS vulnerabilities.
        *   Use ReDoS analysis tools to identify and fix vulnerable regexes.
        *   Rewrite vulnerable regexes to be more efficient and avoid nested quantifiers or overlapping character classes.
        *   Consider using a regex engine with built-in ReDoS protection (if available and feasible).
        *   Implement timeouts for regex operations.

## Attack Tree Path: [2.1 Large Input Strings](./attack_tree_paths/2_1_large_input_strings.md)

*   **2.1.1 Very Long Numbers [HIGH RISK]**
    *   **Description:** The attacker provides an extremely large number as input to a Humanizer function (e.g., `number.ToWords()`). This causes excessive CPU usage or memory allocation, leading to a DoS.
    *   **Likelihood:** Medium. Some Humanizer functions might not have adequate input length limits.
    *   **Impact:** Medium. Leads to a Denial-of-Service (DoS).
    *   **Effort:** Low. Simply providing a very large number.
    *   **Skill Level:** Low. No special skills required.
    *   **Detection Difficulty:** Medium. Detected by monitoring for high CPU or memory usage.
    *   **Mitigation:**
        *   Implement strict input validation to limit the length of numeric input.
        *   Set reasonable maximum values for numbers processed by Humanizer.
        *   Use timeouts and resource limits to prevent excessive resource consumption.

*   **2.1.2 Very Long Strings [HIGH RISK]**
    *   **Description:** Similar to 2.1.1, but the attacker provides an extremely long string as input to a Humanizer function (e.g., `string.Humanize()`).
    *   **Likelihood:** Medium.
    *   **Impact:** Medium. Leads to a Denial-of-Service (DoS).
    *   **Effort:** Low.
    *   **Skill Level:** Low.
    *   **Detection Difficulty:** Medium.
    *   **Mitigation:**
        *   Implement strict input validation to limit the length of string input.
        *   Set reasonable maximum lengths for strings processed by Humanizer.
        *   Use timeouts and resource limits.

