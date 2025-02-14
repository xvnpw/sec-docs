# Attack Surface Analysis for doctrine/lexer

## Attack Surface: [1. Resource Exhaustion (Lexer-Specific)](./attack_surfaces/1__resource_exhaustion__lexer-specific_.md)

*   **Description:** Attackers craft input designed to cause excessive resource consumption (memory or CPU) *within the lexer itself*.
    *   **Lexer Contribution:** The lexer's handling of specific input patterns (e.g., very long tokens, deeply nested structures) leads directly to the resource exhaustion.  This is a *direct* vulnerability of the lexer's implementation.
    *   **Example:**
        *   **Extremely Long String Literal:** Input containing a string literal that is gigabytes in size, directly impacting the lexer's memory allocation.
        *   **Deeply Nested Comments:** Input with deeply nested comments (e.g., `/* /* /* ... */ */ */`) if the lexer supports nested comments, potentially causing stack overflow within the lexer.
    *   **Impact:** Denial of Service (DoS) – the application becomes unresponsive or crashes due to the lexer's resource consumption.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Token Length Limits:** Enforce strict limits on the maximum length of any individual token *within the lexer's code*. This is a *direct* mitigation within the lexer.
        *   **Nesting Depth Limits:** If the lexer handles nested structures, implement a limit on the maximum nesting depth *within the lexer*.
        *   **Memory Allocation Monitoring:** Monitor memory usage *during lexing* and terminate the process if it exceeds a predefined threshold. This is a proactive measure within the lexer's operation.
        * **Input size limit:** Limit input that is passed to lexer.

## Attack Surface: [2. Regular Expression Denial of Service (ReDoS)](./attack_surfaces/2__regular_expression_denial_of_service__redos_.md)

*   **Description:** If the lexer uses regular expressions internally, attackers can craft input that triggers catastrophic backtracking, causing the lexer to consume excessive CPU time.
    *   **Lexer Contribution:** The lexer's *internal* use of vulnerable regular expressions is the *direct* cause of the vulnerability. The attacker exploits the lexer's implementation.
    *   **Example:** A regex like `(a+)+$` within the lexer's code, combined with input like "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!", can cause exponential backtracking *within the lexer*.
    *   **Impact:** Denial of Service (DoS) – the application becomes unresponsive due to the lexer's excessive CPU usage.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Regex Auditing:** Carefully audit all regular expressions *used within the lexer* for potential ReDoS vulnerabilities.
        *   **Regex Timeout:** Implement a timeout mechanism for regular expression evaluation *within the lexer*.
        *   **Regex Simplification/Refactoring:** Rewrite vulnerable regular expressions *within the lexer's code* to avoid backtracking issues.
        *   **Alternative Lexing Techniques:** Consider using alternative lexing techniques that don't rely on regular expressions *within the lexer*.

