# Attack Surface Analysis for lodash/lodash

## Attack Surface: [Prototype Pollution](./attack_surfaces/prototype_pollution.md)

*   **Description:** Prototype pollution occurs when an attacker can manipulate the prototype of built-in JavaScript objects (like `Object.prototype`) by injecting properties. This can lead to unexpected behavior, denial of service, or even client-side code execution.
*   **Lodash Contribution:** Lodash's deep object manipulation functions, specifically `_.merge`, `_.mergeWith`, `_.defaultsDeep`, `_.set`, `_.setWith`, and `_.cloneDeep`, are the primary contributors within lodash to this attack surface. When used with untrusted input, these functions can be exploited to pollute prototypes due to their recursive nature and handling of object properties.
*   **Example:**
    ```javascript
    // Vulnerable code using lodash _.merge
    const user = {};
    const maliciousPayload = JSON.parse('{"__proto__":{"isAdmin": true}}');
    _.merge(user, maliciousPayload);

    // Now, all objects inherit isAdmin = true due to prototype pollution
    console.log({}.isAdmin); // Output: true
    ```
*   **Impact:**
    *   Denial of Service (DoS): Application crashes or malfunctions due to unexpected object properties across the application.
    *   Client-Side Code Execution (in browser environments): If application logic relies on polluted prototypes in insecure ways, attackers might execute arbitrary JavaScript code within the user's browser.
    *   Security Bypass: Circumvention of security checks or access control mechanisms that rely on assumptions about the standard, unpolluted state of JavaScript objects.
*   **Risk Severity:** **High** to **Critical**
*   **Mitigation Strategies:**
    *   **Input Validation and Sanitization:**  Rigorous validation and sanitization of all user-provided input before using it with lodash's vulnerable deep object manipulation functions.  Specifically, reject or sanitize input containing properties like `__proto__`, `constructor.prototype`, or `prototype`.
    *   **Object Freezing (with caution):** Freeze critical objects or prototypes that should remain immutable, especially in security-sensitive contexts.  `Object.freeze(Object.prototype);` can be used, but with extreme caution as it can break compatibility with other libraries or code relying on prototype modifications.
    *   **Use Safer Alternatives:**  When processing untrusted data, consider avoiding lodash's deep merge/set operations altogether. Implement custom, safer logic that avoids recursive merging or setting based on potentially malicious keys.
    *   **Regular Lodash Updates:**  Maintain lodash at the latest version. Security patches addressing prototype pollution vulnerabilities are frequently released in newer versions of the library.
    *   **`Object.create(null)` for Untrusted Data:** Create objects using `Object.create(null)` when dealing with untrusted data that will be processed by lodash's deep manipulation functions. Objects created this way do not inherit from `Object.prototype`, preventing prototype pollution attacks.

