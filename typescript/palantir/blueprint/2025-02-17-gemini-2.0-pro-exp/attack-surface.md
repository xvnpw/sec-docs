# Attack Surface Analysis for palantir/blueprint

## Attack Surface: [Prop Injection/Manipulation (High/Critical)](./attack_surfaces/prop_injectionmanipulation__highcritical_.md)

*   **Description:** Attackers inject malicious values into props passed to Blueprint components, aiming to alter component behavior or trigger exploits. This is the *primary* direct attack vector.
    *   **Blueprint Contribution:** Blueprint's reliance on props for configuration and data makes this a central attack surface. The library *itself* doesn't validate the *semantic* meaning of props; it's the application's responsibility.
    *   **Example:**
        *   Injecting HTML/JavaScript into a `content` prop (e.g., `Tooltip`, `Popover`, `Dialog`) if the application doesn't sanitize, leading to XSS.
        *   Manipulating `min`/`max` on `NumericInput` to bypass intended input restrictions *if* the server doesn't re-validate.
        *   Providing an invalid or malicious URL to a component expecting a URL prop *if* that URL is used unsafely by the application.
        *   Altering callback-related props (if the application allows this dynamically) to point to malicious functions.
    *   **Impact:**  Ranges from XSS (very common) to potentially arbitrary code execution (less common, but possible if the application uses the prop in an extremely unsafe way, like `eval()`). Data leakage is also a significant risk.
    *   **Risk Severity:** High to Critical.
    *   **Mitigation Strategies:**
        *   **Server-Side Validation (Mandatory):**  *Always* validate *all* props on the server-side. Treat them as untrusted input. Use a schema validation library.
        *   **Client-Side Validation (for UX):** Validate on the client-side for immediate feedback, but *never* rely on it for security.
        *   **HTML Sanitization:**  Use a robust HTML sanitization library (e.g., DOMPurify) for *any* prop that might contain HTML, *before* passing it to Blueprint.
        *   **Type Safety (TypeScript):**  Use TypeScript to enforce strong typing for props, reducing the chance of passing incorrect data types.
        *   **Principle of Least Privilege:** Only pass the *necessary* props.

## Attack Surface: [Callback Exploitation (High/Critical)](./attack_surfaces/callback_exploitation__highcritical_.md)

*   **Description:** Attackers exploit vulnerabilities *within* the application-provided callback functions (event handlers) passed to Blueprint components. The vulnerability is in the *application's* code, but Blueprint provides the *entry point*.
    *   **Blueprint Contribution:** Blueprint components extensively use callbacks (`onChange`, `onClick`, etc.). These callbacks are executed when specific events occur, providing a direct path for attackers to trigger application code.
    *   **Example:**
        *   An `onChange` handler for a `TextInput` directly uses the input value in a database query without proper escaping (SQL injection).
        *   An `onClick` handler for a `Button` performs a sensitive operation without proper authorization checks.
        *   A callback exposes sensitive data due to improper error handling or insecure direct object references.
    *   **Impact:**  Highly dependent on the callback's logic. Can range from data leakage and privilege escalation to SQL injection, command injection, and other severe vulnerabilities.
    *   **Risk Severity:** High to Critical.
    *   **Mitigation Strategies:**
        *   **Input Validation (Inside Callbacks):**  Treat *all* data received from Blueprint component callbacks as untrusted input. Validate and sanitize it *within* the callback function.
        *   **Secure Coding Practices:**  Apply secure coding principles *within* callbacks. Avoid using user-provided data directly in sensitive operations. Use parameterized queries, prepared statements, and appropriate escaping.
        *   **Authorization Checks:**  Ensure that callbacks that perform sensitive actions include proper authorization checks.
        *   **Error Handling:** Implement robust error handling to prevent information disclosure.

