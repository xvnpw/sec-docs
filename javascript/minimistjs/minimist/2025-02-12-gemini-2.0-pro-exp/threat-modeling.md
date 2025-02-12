# Threat Model Analysis for minimistjs/minimist

## Threat: [Prototype Pollution](./threats/prototype_pollution.md)

*   **Threat:** Prototype Pollution Injection
*   **Description:** An attacker crafts malicious command-line arguments using keys like `__proto__`, `constructor.prototype`, or `prototype` to inject properties into the global `Object.prototype`. The attacker passes arguments like `--__proto__.polluted=true`. This leverages `minimist`'s (pre-1.2.6) lack of sanitization for these special property names.
*   **Impact:**
    *   Denial of Service (DoS): Application crash or malfunction.
    *   Remote Code Execution (RCE): Execution of arbitrary attacker-controlled code, leading to complete system compromise.
    *   Security Bypass: Circumvention of security checks.
    *   Data Leakage: Exposure of sensitive data.
*   **Minimist Component Affected:** The core argument parsing logic in `minimist` (versions *prior to* 1.2.6) that handles key-value pairs without sanitizing reserved property names (`__proto__`, `constructor.prototype`, `prototype`).
*   **Risk Severity:** Critical (prior to 1.2.6), Low (1.2.6 and later, *if and only if* proper mitigations are also in place; otherwise, still a potential risk).
*   **Mitigation Strategies:**
    *   **Upgrade Minimist:** *Crucially*, use `minimist` version 1.2.6 or later. This is the *primary and most important* mitigation.
    *   **Input Validation:**  Even with a patched version, validate and sanitize all command-line arguments as a defense-in-depth measure.
    *   **Use `--` Separator:** Use `--` to signal the end of options.
    *   **Use `opts.string` and `opts.boolean`:** Explicitly define argument types.
    *   **Use `opts.unknown`:** Implement a handler for unknown options.
    *  **Avoid Dynamic Code Evaluation:** Do not use `eval` or `new Function` with data derived from user input.

