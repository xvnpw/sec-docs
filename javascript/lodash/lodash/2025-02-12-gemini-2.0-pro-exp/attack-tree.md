# Attack Tree Analysis for lodash/lodash

Objective: To execute arbitrary code on the server or client-side, or to cause a Denial of Service (DoS), by exploiting vulnerabilities in the application's use of Lodash.

## Attack Tree Visualization

```
                                     +-------------------------------------------------+
                                     |  Attacker Goal: Execute Arbitrary Code or DoS  |
                                     |  via Lodash Vulnerabilities in the Application  |
                                     +-------------------------------------------------+
                                                        |
          +----------------------------------------------------------------------------------------------------------------+
          |                                                                                                                |
+-------------------------+ [HR]                                                                              +---------------------------------+
|  Prototype Pollution     |                                                                              |  Untrusted Input to Sensitive  |
|  (Client or Server-Side) |                                                                              |  Lodash Functions             |
+-------------------------+                                                                              +---------------------------------+
          |
+---------------------+ [CN]                                                                                            +---------------------+ [CN]
|  _.merge            |                                                                                            |  _.template         |
|  (CVE-2018-16487)   |                                                                                            |  (with user input)  |
+---------------------+                                                                                            +---------------------+
          |
+---------------------+ [CN]                                                                                            +---------------------+ [CN]
|  _.set              |                                                                                            |  _.set              |
|  (CVE-2020-28500)   |                                                                                            |  (with user input)  |
+---------------------+                                                                                            +---------------------+
          |
+---------------------+ [CN]
|  _.setWith          |
|  (CVE-2021-23337)   |
+---------------------+
          |
+---------------------+
|  Other functions    |
|  vulnerable to      |
|  prototype pollution|
|  (if not patched)   |
+---------------------+
```

## Attack Tree Path: [1. High-Risk Path: Prototype Pollution](./attack_tree_paths/1__high-risk_path_prototype_pollution.md)

*   **Description:** Prototype pollution is a vulnerability where an attacker can inject properties into the `Object.prototype` in JavaScript. This affects all objects in the application, potentially leading to unexpected behavior, denial of service, or even remote code execution. Lodash functions that recursively merge or set object properties are particularly susceptible.

*   **Critical Nodes:**
    *   **`_.merge (CVE-2018-16487)`:**
        *   **Vulnerability:** Allows an attacker to inject properties into `Object.prototype` via a crafted object passed to `_.merge`.
        *   **Exploitation:** The attacker provides a malicious object with a `__proto__` property containing the desired payload. When `_.merge` recursively merges this object, it pollutes the prototype.
        *   **Example:**
            ```javascript
            const maliciousPayload = JSON.parse('{"__proto__": {"polluted": "yes"}}');
            _.merge({}, maliciousPayload);
            console.log({}.polluted); // Output: "yes" (if vulnerable)
            ```
        *   **Likelihood:** Low (if patched), Medium (if unpatched and exposed)
        *   **Impact:** High (RCE or significant data corruption)
        *   **Effort:** Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium

    *   **`_.set (CVE-2020-28500)`:**
        *   **Vulnerability:** Allows prototype pollution through crafted object keys.
        *   **Exploitation:** The attacker uses a key like `"__proto__.polluted"` in the object passed to `_.set`.
        *   **Example:**
            ```javascript
            _.set({}, "__proto__.polluted", "yes");
            console.log({}.polluted); // Output: "yes" (if vulnerable)
            ```
        *   **Likelihood:** Low (if patched), Medium (if unpatched and exposed)
        *   **Impact:** High (RCE or significant data corruption)
        *   **Effort:** Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium

    *   **`_.setWith (CVE-2021-23337)`:**
        *   **Vulnerability:** Similar to `_.set`, allows prototype pollution via crafted object keys, even with customizers.
        *   **Exploitation:** Similar to `_.set`, but may bypass some naive checks.
        *   **Example:** Similar to `_.set`, exploiting the customizer function if present.
        *   **Likelihood:** Low (if patched), Medium (if unpatched and exposed)
        *   **Impact:** High (RCE or significant data corruption)
        *   **Effort:** Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium

    *   **`Other functions vulnerable to prototype pollution (if not patched)`:**
        *   **Vulnerability:** Any Lodash function that recursively modifies object properties without proper sanitization could be vulnerable.
        *   **Exploitation:** Depends on the specific function and how it handles nested objects and user input.
        *   **Likelihood:** Low (if patched and input validated), Medium (if unpatched or poor input validation)
        *   **Impact:** High (RCE or significant data corruption)
        *   **Effort:** Medium to High
        *   **Skill Level:** Intermediate to Advanced
        *   **Detection Difficulty:** Medium to Hard

## Attack Tree Path: [2. High-Risk Path: Untrusted Input to Sensitive Lodash Functions](./attack_tree_paths/2__high-risk_path_untrusted_input_to_sensitive_lodash_functions.md)

*   **Description:** This category covers scenarios where user-provided data is directly used in Lodash functions that can be manipulated to cause harm, even without known CVEs.

*   **Critical Nodes:**
    *   **`_.template (with user input)`:**
        *   **Vulnerability:**  Allows arbitrary code execution if user input is included in the template string without proper escaping or sanitization.
        *   **Exploitation:** The attacker injects JavaScript code into the template string.
        *   **Example:**
            ```javascript
            // Vulnerable code:
            let userInput = "<% console.log('Hacked!'); %>";
            let compiled = _.template("<div>" + userInput + "</div>");
            let result = compiled({}); // Executes the attacker's code
            ```
        *   **Likelihood:** Medium
        *   **Impact:** Very High (RCE)
        *   **Effort:** Low to Medium
        *   **Skill Level:** Novice to Intermediate
        *   **Detection Difficulty:** Easy to Medium

    *   **`_.set (with user input)`:**
        *   **Vulnerability:**  Allows an attacker to overwrite arbitrary object properties if both the path and value are user-controlled.  This is dangerous even *without* prototype pollution.
        *   **Exploitation:** The attacker provides a path that targets a sensitive property (e.g., a function, configuration setting) and a malicious value.
        *   **Example:**
            ```javascript
            // Vulnerable code (simplified):
            let obj = { config: { isAdmin: false } };
            let userPath = "config.isAdmin"; // From user input
            let userValue = true;          // From user input
            _.set(obj, userPath, userValue); // Attacker gains admin privileges
            ```
        *   **Likelihood:** Medium
        *   **Impact:** High (Data modification, potential privilege escalation, possibly RCE in specific contexts)
        *   **Effort:** Low to Medium
        *   **Skill Level:** Novice to Intermediate
        *   **Detection Difficulty:** Medium

