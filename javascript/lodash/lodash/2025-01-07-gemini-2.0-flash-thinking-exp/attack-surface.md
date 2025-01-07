# Attack Surface Analysis for lodash/lodash

## Attack Surface: [Prototype Pollution](./attack_surfaces/prototype_pollution.md)

* **Description:** The ability to inject properties into the `Object.prototype` in JavaScript. This can affect all objects in the application, leading to unexpected behavior or security vulnerabilities.
    * **How Lodash Contributes to the Attack Surface:** Lodash functions like `_.merge`, `_.assign`, `_.defaults`, `_.set`, and `_.extend` can be vulnerable if used with attacker-controlled input. These functions can recursively merge or set properties, potentially allowing the injection of `__proto__`, `constructor.prototype`, or similar properties.
    * **Example:**
        ```javascript
        const maliciousPayload = JSON.parse('{"__proto__": {"polluted": true}}');
        const obj = {};
        _.merge(obj, maliciousPayload);
        console.log(obj.polluted); // undefined
        console.log({}.polluted);  // true - prototype pollution!
        ```
    * **Impact:**
        * Denial of Service (DoS) by modifying critical object properties.
        * Potential Remote Code Execution (RCE) in specific scenarios if prototype properties are used in a vulnerable way.
        * Bypassing security checks that rely on default object properties.
    * **Risk Severity:** High to Critical
    * **Mitigation Strategies:**
        * Avoid using Lodash's deep merge/assign functions with untrusted input. Sanitize and validate input rigorously before using these functions.
        * Consider using alternatives that offer better protection against prototype pollution.
        * Freeze the prototype of objects where possible. `Object.freeze(Object.prototype)` can prevent modification, but it has significant compatibility implications and should be used with caution.
        * Implement input validation to disallow properties like `__proto__`, `constructor`, and `prototype` in user-provided data.

## Attack Surface: [Server-Side Template Injection (SSTI) via `_.template`](./attack_surfaces/server-side_template_injection__ssti__via____template_.md)

* **Description:** Allowing attackers to inject and execute arbitrary code on the server by manipulating template syntax.
    * **How Lodash Contributes to the Attack Surface:** The `_.template` function in Lodash allows for dynamic template rendering. If user-provided data is directly embedded within the template without proper sanitization, it can lead to SSTI.
    * **Example:**
        ```javascript
        const userInput = "<%- process.mainModule.require('child_process').execSync('whoami') %>";
        const template = _.template('User: <%= username %>, Command: <%= command %>');
        const output = template({ username: 'test', command: userInput });
        console.log(output); // Could execute the 'whoami' command on the server
        ```
    * **Impact:**
        * Remote Code Execution (RCE) on the server.
        * Data exfiltration and unauthorized access.
        * Server compromise.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * Never directly embed untrusted user input into `_.template` without thorough sanitization and encoding.
        * Prefer using safer templating engines that offer automatic escaping or sandboxing.
        * Implement a Content Security Policy (CSP) to mitigate the impact of successful SSTI.
        * Enforce strict input validation and output encoding.

