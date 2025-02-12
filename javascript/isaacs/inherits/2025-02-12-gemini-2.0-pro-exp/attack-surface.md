# Attack Surface Analysis for isaacs/inherits

## Attack Surface: [Prototype Pollution (via `inherits` as the Propagation Mechanism)](./attack_surfaces/prototype_pollution__via__inherits__as_the_propagation_mechanism_.md)

**Description:** An attacker injects malicious properties into an object's prototype, and `inherits` propagates this pollution to the subclass, affecting all instances of the subclass.  This is distinct from general prototype pollution; here, `inherits` is *essential* for the attack to work as described.

**How `inherits` Contributes:** `inherits` is the *direct mechanism* that copies the polluted prototype from the superclass to the subclass. Without `inherits`, the pollution would be limited to the superclass (or its direct instances).

**Example:**
```javascript
const inherits = require('inherits');

function SuperClass() {}

// Attacker pollutes the *SuperClass.prototype* BEFORE inherits is called.
SuperClass.prototype.__proto__.polluted = "malicious";

function SubClass() {}
inherits(SubClass, SuperClass); // inherits propagates the pollution

let instance = new SubClass();
console.log(instance.polluted); // Outputs "malicious" - attack successful
```
Crucially, the pollution happens *before* `inherits` is called, but `inherits` is what makes the pollution affect `SubClass`. If `inherits` wasn't used, `SubClass` would not be affected (unless it also directly interacted with the polluted prototype).

**Impact:** Can lead to arbitrary code execution (ACE), denial of service (DoS), or data leakage/modification, depending on how the polluted property is used.

**Risk Severity:** **Critical** (if ACE is possible) or **High** (for DoS or significant data breaches).

**Mitigation Strategies:**
*   **`Object.freeze(SuperClass.prototype)`:**  The *most direct* mitigation, specific to this `inherits`-centric scenario, is to freeze the superclass prototype *before* calling `inherits`. This prevents any modifications to the prototype, blocking the propagation.  This is the key mitigation that directly addresses the role of `inherits`.
*   **`Object.create(null)` for Superclass:** If you control the creation of `SuperClass`, create it with `Object.create(null)` to prevent it from having a prototype chain to pollute in the first place. This is a strong preventative measure.
*   **Input Sanitization (Indirect, but Important):** While not *directly* related to `inherits`, rigorous input validation is crucial to prevent the initial pollution of *any* object that might later be used with `inherits`. This is a general best practice.
*   **Avoid Dynamic Inheritance (Indirect, but Important):** Avoid situations where the `superCtor` argument to `inherits` is determined by user input or external data.

