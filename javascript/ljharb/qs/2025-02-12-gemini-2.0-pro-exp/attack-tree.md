# Attack Tree Analysis for ljharb/qs

Objective: Cause unexpected application behavior, data corruption, or denial of service via `qs`

## Attack Tree Visualization

                                      [[Attacker's Goal]]
                                                        |
                                      ===================
                                      ||
                      [[1. Prototype Pollution]]
                                      ||
                      ===================================
                      ||                                 ||
  [[1.1 Inject "__proto__" property]]   [[1.2 Inject "constructor" property]]
                      ||                                 ||
  ===================================                 ===================================
  ||
[[1.1.1 Modify global object defaults]]       [[1.2.1 Modify global object defaults]]

## Attack Tree Path: [[[1. Prototype Pollution]]](./attack_tree_paths/__1__prototype_pollution__.md)

*   **Description:** The attacker aims to modify the properties of the base `Object.prototype` or other built-in object prototypes. This affects all objects in the application, potentially leading to unexpected behavior, data corruption, or even arbitrary code execution. This is the most critical threat related to `qs`.
*   **Why Critical:** Successful prototype pollution grants the attacker significant control over the application's behavior.
*   **Why High-Risk:** `qs` historically had vulnerabilities related to this, and even with mitigations, application-level vulnerabilities can still lead to exploitation.

## Attack Tree Path: [[[1.1 Inject "__proto__" property]]](./attack_tree_paths/__1_1_inject___proto___property__.md)

*   **Description:** The attacker crafts a query string that includes the `__proto__` property.  The goal is to use this to directly modify the properties of `Object.prototype`.
*   **Example Query String:** `?__proto__[maliciousProperty]=maliciousValue` or nested variations like `?a[__proto__][maliciousProperty]=maliciousValue`.
*   **Why Critical:** This is a direct and well-known technique for achieving prototype pollution.
*   **Why High-Risk:** While `qs` attempts to block this, misconfigurations or application-level vulnerabilities can still allow it.

## Attack Tree Path: [[[1.2 Inject "constructor" property]]](./attack_tree_paths/__1_2_inject_constructor_property__.md)

*   **Description:** Similar to `__proto__`, the attacker uses the `constructor` property in the query string to attempt prototype pollution.
*   **Example Query String:** `?constructor[prototype][maliciousProperty]=maliciousValue`
*   **Why Critical:** This is another direct method for achieving prototype pollution, similar in severity to `__proto__` injection.
*   **Why High-Risk:** Similar reasons to `__proto__` injection; `qs` mitigations and application-level vulnerabilities are key factors.

## Attack Tree Path: [[[1.1.1 Modify global object defaults]]](./attack_tree_paths/__1_1_1_modify_global_object_defaults__.md)

*   **Description:** The attacker successfully modifies the default properties of `Object.prototype` via the `__proto__` injection. This affects *all* objects in the application.
*   **Example Impact:** Changing the default value of a commonly used property, adding a malicious method to all objects, or altering the behavior of existing methods.
*   **Why Critical:** This represents a successful, high-impact prototype pollution attack with widespread consequences.
*   **Why High-Risk:** This is the ultimate goal of the `__proto__` injection attack path.

## Attack Tree Path: [[[1.2.1 Modify global object defaults]]](./attack_tree_paths/__1_2_1_modify_global_object_defaults__.md)

*   **Description:** The attacker successfully modifies the default properties of `Object.prototype` (or other built-in prototypes) via the `constructor` injection. The impact is the same as 1.1.1.
*   **Example Impact:** Identical to 1.1.1; the difference is the injection method.
*   **Why Critical:** Same as 1.1.1 – a successful, high-impact attack.
*   **Why High-Risk:** This is the ultimate goal of the `constructor` injection attack path.

