# Threat Model Analysis for nikic/php-parser

## Threat: [AST Injection Leading to RCE](./threats/ast_injection_leading_to_rce.md)

*   **Description:** An attacker provides malicious input that, when parsed and subsequently used to *reconstruct* PHP code, results in the execution of arbitrary attacker-controlled code. The attacker crafts input that manipulates the AST nodes (e.g., adding a `Node\Expr\Eval_` node or modifying existing nodes) in a way that introduces malicious code when the AST is converted back into PHP. This is the most significant threat when using the parser for code generation.
    *   **Impact:** Complete system compromise; Remote Code Execution (RCE). The attacker gains full control over the application and potentially the underlying server.
    *   **Affected Component:** `PhpParser\NodeTraverser`, `PhpParser\PrettyPrinter\Standard` (or any custom `PrettyPrinter`), and any custom code that modifies the AST *before* code generation. The vulnerability lies in the *combination* of parsing, AST manipulation, and code generation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **AST Whitelisting (Post-Parsing):**  After parsing, implement a strict whitelist of allowed AST node types and structures.  Reject any AST that contains unexpected or disallowed nodes.  This is a crucial mitigation.
        *   **Context-Aware Escaping (During Code Generation):**  When using the `PrettyPrinter`, ensure that any user-supplied data inserted into the generated code is properly escaped *for the specific context* within the AST.  This requires a deep understanding of PHP's syntax and escaping rules.  Consider using a dedicated AST-aware code generation library if available.
        *   **Avoid Dynamic Code Generation:** If possible, refactor the application to avoid generating new PHP code from the AST altogether.  This is the most secure approach.
        *   **Principle of Least Privilege:** Ensure that the generated code runs with the minimum necessary privileges. Use sandboxing if feasible.

## Threat: [Denial of Service via Malformed Input (Targeting Parser)](./threats/denial_of_service_via_malformed_input__targeting_parser_.md)

*   **Description:** An attacker submits extremely large or deeply nested PHP code specifically designed to consume excessive resources (CPU, memory) *during the parsing phase* itself. This exploits the complexity of the parsing algorithm within `nikic/php-parser`.
    *   **Impact:** Application unavailability; Denial of Service (DoS).
    *   **Affected Component:** `PhpParser\Parser` (specifically, the lexer and parser components).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Size Limits:** Enforce strict limits on the size (in bytes) of the input PHP code that can be submitted for parsing. This directly limits the parser's workload.
        *   **PHP Resource Limits:** Configure PHP (and the web server) with appropriate memory limits (`memory_limit`) and execution time limits (`max_execution_time`).
        *   **Parsing Timeouts:** Implement a timeout mechanism *specifically* for the parsing process (using `set_time_limit` or similar, but be aware of its limitations). If parsing takes longer than a predefined threshold, terminate the operation. This is crucial for mitigating DoS attacks targeting the parser.

## Threat: [Unsafe PrettyPrinter Configuration Leading to Injection](./threats/unsafe_prettyprinter_configuration_leading_to_injection.md)

* **Description:** The application uses a custom `PrettyPrinter` configuration that disables or incorrectly implements escaping mechanisms *inherent to the PrettyPrinter*. An attacker provides input that, when pretty-printed with this unsafe configuration, results in the injection of malicious code. This is a direct threat related to the misuse of a core `php-parser` component.
    * **Impact:** Code injection, potentially leading to Remote Code Execution (RCE).
    * **Affected Component:** `PhpParser\PrettyPrinter\Standard` (if misconfigured) or a custom `PhpParser\PrettyPrinterAbstract` implementation.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Use Default PrettyPrinter:**  Strongly prefer the default `PrettyPrinter\Standard` configuration, which is designed to be secure.
        * **Thoroughly Review Custom Configurations:** If a custom `PrettyPrinter` is absolutely necessary, *extremely carefully* review its implementation to ensure that all necessary escaping is performed correctly. Pay close attention to how user-supplied data is handled, and understand the implications of each configuration option.
        * **Validate PrettyPrinter Output:** Implement validation checks on the *output* of the `PrettyPrinter` to ensure it conforms to expected patterns. This is a defense-in-depth measure.

