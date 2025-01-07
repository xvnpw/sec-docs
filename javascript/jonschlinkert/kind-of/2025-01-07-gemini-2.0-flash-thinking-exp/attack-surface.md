# Attack Surface Analysis for jonschlinkert/kind-of

## Attack Surface: [Indirect Prototype Pollution via Misclassified Objects](./attack_surfaces/indirect_prototype_pollution_via_misclassified_objects.md)

* **Description:**  While `kind-of` doesn't directly cause prototype pollution, its misclassification of an object's type can lead to vulnerabilities in other parts of the application that *do* manipulate prototypes based on the assumed type.
* **How `kind-of` Contributes to the Attack Surface:** If `kind-of` incorrectly identifies a malicious object as a benign type (e.g., a plain object), and the application then processes it assuming it's safe to iterate over its properties, it could be vulnerable to prototype pollution if the malicious object has properties designed to pollute the prototype chain.
* **Example:** An attacker crafts an object that `kind-of` misclassifies as a regular object. The application then iterates over this object's properties and blindly assigns them to another object, unknowingly copying properties that pollute the prototype.
* **Impact:** Potential for application-wide impact by modifying built-in object properties, leading to unexpected behavior, security vulnerabilities, or denial of service.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * **Avoid directly copying or assigning properties from untrusted objects, even if `kind-of` identifies them as a safe type.**
    * **Use safer object manipulation techniques that don't rely on iterating over potentially malicious properties.**
    * **Implement Content Security Policy (CSP) and other browser-level protections against prototype pollution.**

