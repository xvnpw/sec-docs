## Key Attack Surface List (High & Critical, Directly Involving `reflection-common`)

Here are the key attack surfaces with high or critical severity that directly involve the `phpdocumentor/reflection-common` library:

* **Attack Surface: Input Manipulation Leading to Unintended Reflection**
    * **Description:** An attacker can manipulate user-controlled input (e.g., query parameters, form data, configuration files) that is used by the application to determine which classes, methods, or properties to reflect upon using `reflection-common`.
    * **How `reflection-common` Contributes:** The library provides functions to inspect classes, methods, and properties based on names provided to it. If these names originate from untrusted input, the library directly facilitates the reflection of unintended targets.
    * **Example:** An application uses a query parameter `class_name` to dynamically display information about a class. An attacker could change `class_name` to a sensitive internal class, potentially revealing its structure and properties through reflection.
    * **Impact:** Information disclosure of sensitive application internals, potential for further exploitation by understanding the application's structure.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Input Validation:** Strictly validate and sanitize all user-provided input used to determine reflection targets. Use whitelisting of allowed class/method/property names.
        * **Abstraction Layers:** Introduce an abstraction layer that maps user-provided input to a predefined set of safe reflection targets, preventing direct use of untrusted input with `reflection-common`.

* **Attack Surface: Abuse of Dynamic Instantiation/Method Invocation via Reflected Information**
    * **Description:** While `reflection-common` doesn't directly instantiate objects or invoke methods, it provides the necessary information (class names, method names, parameters) that the *consuming application* can use for these actions. Attackers can manipulate input to influence these dynamic operations based on the reflected data.
    * **How `reflection-common` Contributes:** The library provides the metadata needed (e.g., class names, method signatures) for the application to perform dynamic instantiation or method calls. If this metadata is derived from attacker-influenced reflection facilitated by `reflection-common`, it can lead to abuse.
    * **Example:** An application uses reflection (using `reflection-common`) to determine the type of a data object and then dynamically instantiates it. An attacker could manipulate input to reflect on a different class than intended, leading to the instantiation of an unexpected object with potentially harmful side effects.
    * **Impact:** Arbitrary code execution if attacker-controlled data influences the instantiated class or invoked method and its arguments. Denial of service by instantiating resource-intensive objects.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Avoid Dynamic Instantiation/Invocation with Reflected Data:** If possible, avoid dynamic instantiation or method invocation based on reflection data derived from user input.
        * **Strict Validation Before Dynamic Operations:** If dynamic operations are necessary, implement extremely strict validation of the reflected class and method names before instantiation or invocation. Sanitize any arguments passed to dynamically invoked methods.
        * **Principle of Least Privilege:** Limit the classes and methods that can be targeted through reflection and dynamic operations.