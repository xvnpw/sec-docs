# Threat Model Analysis for google/re2

## Threat: [Threat 1: CPU-Based Regular Expression Denial of Service (ReDoS)](./threats/threat_1_cpu-based_regular_expression_denial_of_service__redos_.md)

*   **Description:** An attacker crafts a malicious regular expression *or* a malicious input string (or a combination of both) that, while not causing exponential backtracking (which re2 prevents), still forces the re2 engine to consume a large amount of CPU time.  The attacker submits this input to the application where re2 is used for processing.  The attacker's goal is to make the application unresponsive, denying service to legitimate users.  This leverages the fact that re2's linear time guarantee is relative to input size, and complex regexes can have large constant factors.
    *   **Impact:** The application becomes slow or completely unresponsive.  This can lead to a denial of service, preventing legitimate users from accessing the application's functionality.  Depending on the application's architecture, this could also impact other services or systems.
    *   **re2 Component Affected:** The core matching engine of re2 (`re2::RE2::Match`, `re2::RE2::FullMatch`, `re2::RE2::PartialMatch`, and related functions). The DFA (Deterministic Finite Automaton) and NFA (Nondeterministic Finite Automaton) construction and execution components are involved.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Input Validation (Regex):** If user-supplied regexes are allowed, implement *very* strict validation.  Prefer whitelisting known-safe regexes.  If whitelisting isn't possible, limit regex length, character sets, and complexity (e.g., disallow nested quantifiers, backreferences, and lookarounds if not absolutely necessary).
        *   **Input Length Limits (Text):** Limit the length of the input string being matched.  A long input string can cause performance issues even with a "safe" regex.
        *   **Resource Limits (Per-Execution):** Implement resource limits (CPU time, potentially memory) *per regular expression execution*.  This requires application-level code (e.g., using timeouts, process monitoring) as re2 doesn't provide this directly.
        *   **Monitoring:** Continuously monitor application performance (CPU usage, response times) to detect potential ReDoS attacks.
        *   **Avoid Regex When Possible:** Use simpler string operations (e.g., `string.find()`, `string.startswith()`) if they can achieve the same result.

## Threat: [Threat 2: Memory-Based Regular Expression Denial of Service (ReDoS) - *Elevated to High*](./threats/threat_2_memory-based_regular_expression_denial_of_service__redos__-_elevated_to_high.md)

*   **Description:** Similar to the CPU-based ReDoS, but the attacker focuses on causing excessive memory allocation. While re2 is *generally* memory-efficient, a complex regular expression, especially one with many capturing groups or alternations, *combined with a carefully crafted input string*, could potentially lead to large memory allocations, *especially if re2's internal limits are not carefully considered or if the application doesn't impose its own limits*. The attacker aims to exhaust available memory, causing the application to crash or become unresponsive. *I've elevated this to High because, while less common than CPU-based ReDoS with re2, the potential for a complete application crash makes the impact severe.*
    *   **Impact:** Application crashes due to out-of-memory errors. This results in a denial of service. In severe cases, it could potentially affect the stability of the entire system.
    *   **re2 Component Affected:** The memory allocation components within re2, particularly those related to DFA/NFA construction and state management. Functions like `re2::RE2::Match` and related matching functions are the entry points.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Validation (Regex & Text):** Same as for CPU-based ReDoS – strict validation of both the regular expression and the input string is crucial.
        *   **Memory Limits (Per-Execution):** Implement application-level limits on the amount of memory that can be allocated during a single regular expression execution.  This is more challenging to implement than CPU timeouts but provides a stronger defense. *Crucially, understand and potentially configure re2's internal memory limits (if exposed through the API or configuration options) to prevent excessive allocation within re2 itself.*
        *   **Monitoring:** Monitor memory usage to detect potential memory exhaustion attacks.
        *   **Limit Capturing Groups:** If possible, use non-capturing groups `(?:...)` instead of capturing groups `(...)` when the captured values are not needed. Each capturing group adds overhead.
        *  **re2 Configuration:** Investigate if the specific re2 version and bindings you are using offer any configuration options related to memory usage limits. If so, configure these appropriately.

