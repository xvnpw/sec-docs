# Attack Tree Analysis for isaacs/inherits

Objective: Achieve ACE or DoS via 'inherits' library

## Attack Tree Visualization

Goal: Achieve ACE or DoS via 'inherits' library

└── 1. Manipulate Inheritance Chain
    └── 1.2. Prototype Pollution on Constructor Functions Used with `inherits` [HIGH RISK]
        ├── 1.2.1. Target `ctor.prototype` [CRITICAL]
        │   ├── 1.2.1.1. Add/Modify properties [CRITICAL] (ACE or DoS)
        │   └── 1.2.1.2.  Overwrite existing methods [CRITICAL] (ACE)
        └── 1.2.2. Target `superCtor.prototype` [CRITICAL]
            ├── 1.2.2.1. Add/Modify properties [CRITICAL] (ACE or DoS)
            └── 1.2.2.2. Overwrite existing methods [CRITICAL] (ACE)

## Attack Tree Path: [Manipulate Inheritance Chain](./attack_tree_paths/manipulate_inheritance_chain.md)

This is the overarching strategy – the attacker aims to disrupt the normal inheritance process established by the `inherits` library.

## Attack Tree Path: [Prototype Pollution on Constructor Functions Used with `inherits` [HIGH RISK]](./attack_tree_paths/prototype_pollution_on_constructor_functions_used_with__inherits___high_risk_.md)

*   **Description:** This is the core vulnerability. The attacker exploits a weakness in the application's input handling (or other vulnerable code) to inject or modify properties on the prototype of either the `ctor` (subclass) or `superCtor` (superclass) constructor functions that are passed to `inherits`.
*   **How it works:** JavaScript's prototype-based inheritance means that objects inherit properties from their prototypes. If an attacker can modify the prototype, they can affect all objects created from that constructor (or its subclasses).
*   **Example Scenario:**
    1.  An application takes user input (e.g., from a JSON payload) and uses it to create an object.
    2.  The attacker includes a malicious property like `"__proto__.pollutedProperty": "malicious_value"` in the input.
    3.  If the application doesn't properly sanitize the input, this property might be added to the prototype of an object.
    4.  Later, this object (or a related object) is used as a constructor with `inherits`.
    5.  The `pollutedProperty` is now inherited by instances of the class, and if the application uses this property in an unsafe way (e.g., in `eval`), it leads to ACE.

## Attack Tree Path: [Target `ctor.prototype` [CRITICAL]](./attack_tree_paths/target__ctor_prototype___critical_.md)

*   **Description:** The attacker specifically targets the prototype of the "subclass" constructor function.
*   **Why it's critical:** Modifying the `ctor.prototype` directly affects the objects created from the subclass, making it a direct path to influencing the behavior of newly created instances.

## Attack Tree Path: [Add/Modify properties [CRITICAL] (ACE or DoS)](./attack_tree_paths/addmodify_properties__critical___ace_or_dos_.md)

*   **Description:** The attacker adds a new property or modifies an existing property on the `ctor.prototype`.
*   **ACE Example:** If the application later uses this property in a string that's passed to `eval()`, the attacker can inject arbitrary code.
*   **DoS Example:** The attacker could add a property that causes an infinite loop or consumes excessive resources when accessed.
*   **Why it's critical:** This is a direct way to inject malicious data or behavior into the object's property chain.

## Attack Tree Path: [Overwrite existing methods [CRITICAL] (ACE)](./attack_tree_paths/overwrite_existing_methods__critical___ace_.md)

*   **Description:** The attacker replaces an existing method on the `ctor.prototype` with a malicious function.
*   **ACE Example:** The attacker overwrites a method like `toString()` with a function that executes arbitrary code when called.
*   **Why it's critical:** This is the most direct way to achieve ACE, as the attacker completely controls the behavior of a method that will be called on instances of the class.

## Attack Tree Path: [Target `superCtor.prototype` [CRITICAL]](./attack_tree_paths/target__superctor_prototype___critical_.md)

*   **Description:** The attacker targets the prototype of the "superclass" constructor function.
*   **Why it's critical:** Modifying the `superCtor.prototype` affects not only objects created directly from the superclass but also *all subclasses* that inherit from it. This can have a wider impact than polluting the `ctor.prototype`.

## Attack Tree Path: [Add/Modify properties [CRITICAL] (ACE or DoS)](./attack_tree_paths/addmodify_properties__critical___ace_or_dos_.md)

Similar to 1.2.1.1, but targeting the `superCtor.prototype`. The impact is potentially broader because it affects the superclass and all its subclasses.

## Attack Tree Path: [Overwrite existing methods [CRITICAL] (ACE)](./attack_tree_paths/overwrite_existing_methods__critical___ace_.md)

Similar to 1.2.1.2, but targeting the `superCtor.prototype`.  Again, the impact is potentially broader.

