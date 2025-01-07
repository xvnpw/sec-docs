# Attack Surface Analysis for isaacs/inherits

## Attack Surface: [Prototype Pollution via Inherited Properties](./attack_surfaces/prototype_pollution_via_inherited_properties.md)

* **Description:** An attacker can manipulate the prototype of a constructor function involved in an inheritance chain established by `inherits`, injecting malicious properties or methods that are then inherited by all instances of child constructors.
    * **How inherits contributes to the attack surface:** The `inherits(A, B)` function explicitly sets `A.prototype.__proto__` to `B.prototype`. This direct manipulation of the prototype chain is the core mechanism that allows modifications to `B.prototype` to affect instances of `A`. If an attacker gains control over `B.prototype`, `inherits` facilitates the propagation of these malicious changes.
    * **Example:**
        * Consider a base class `Logger` with a method `log`.
        * `inherits(SpecialLogger, Logger)` is used.
        * An attacker finds a vulnerability allowing them to modify `Logger.prototype` to override the `log` method with malicious code that sends logs to an external server.
        * All instances of `SpecialLogger`, due to the inheritance set up by `inherits`, will now use the attacker's malicious `log` method.
    * **Impact:**
        * Bypassing security checks and authorization mechanisms within inherited classes.
        * Injecting malicious functionality into objects, potentially leading to remote code execution if inherited methods are invoked.
        * Data corruption or manipulation within objects inheriting from the compromised prototype.
    * **Risk Severity:** **High**
    * **Mitigation Strategies:**
        * **Employ strict object creation:**  Where inheritance is not strictly necessary, use `Object.create(null)` to create objects without the default `Object.prototype` in their prototype chain, reducing the potential impact of prototype pollution on that specific object.
        * **Sanitize and validate input used in constructors:**  Carefully validate any data used to construct objects involved in inheritance hierarchies defined by `inherits`, especially if the data originates from untrusted sources, to prevent injection of malicious properties that could later be inherited.
        * **Utilize JavaScript classes with caution:** While classes offer a more structured approach, they still rely on prototypal inheritance under the hood. Be mindful of potential prototype modifications even when using classes with `extends`.
        * **Freeze prototypes of base classes:**  Use `Object.freeze()` to prevent modifications to the prototypes of base constructor functions involved in `inherits` calls. This can prevent attackers from altering the behavior of inherited objects. Be aware that this can restrict further extension of these classes.
        * **Content Security Policy (CSP):** Implement a strong CSP to mitigate the potential for injected scripts to execute if prototype pollution is exploited to inject client-side code.
        * **Regularly audit code using `inherits`:**  Review code that utilizes `inherits` to ensure that prototypes are not being modified unexpectedly or in ways that could introduce vulnerabilities. Pay close attention to where the base constructors' prototypes might be mutable.

