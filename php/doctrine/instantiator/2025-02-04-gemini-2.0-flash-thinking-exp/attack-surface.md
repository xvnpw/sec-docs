# Attack Surface Analysis for doctrine/instantiator

## Attack Surface: [Bypassing Constructor-Based Security Checks](./attack_surfaces/bypassing_constructor-based_security_checks.md)

*   **Description:** Attackers can circumvent security measures implemented within class constructors by using `doctrine/instantiator` to create objects without constructor invocation.
*   **Instantiator Contribution:** `doctrine/instantiator`'s core functionality is to instantiate objects *without* calling their constructors, directly enabling the bypass.
*   **Example:** An application has a `User` class with a constructor that checks for admin privileges. An attacker uses `instantiator` to create a `User` object directly, bypassing the privilege check and potentially gaining admin access.
*   **Impact:** Unauthorized access, privilege escalation, data manipulation, security policy violations.
*   **Risk Severity:** **High** to **Critical**, depending on the criticality of the bypassed security checks.
*   **Mitigation Strategies:**
    *   **Reduce Reliance on Constructor-Only Security:** Implement security checks outside of constructors, such as in dedicated security middleware or access control lists.
    *   **Validate Object State Post-Instantiation:** If constructors are bypassed, implement explicit validation logic after object creation to ensure the object is in a secure and expected state.

## Attack Surface: [Object Injection via Class Name Manipulation](./attack_surfaces/object_injection_via_class_name_manipulation.md)

*   **Description:** If the application uses `doctrine/instantiator` to instantiate classes based on user-controlled input, attackers can inject malicious class names, leading to instantiation of arbitrary classes and potentially Remote Code Execution.
*   **Instantiator Contribution:** `doctrine/instantiator` provides the mechanism to dynamically instantiate classes based on names, making it the direct tool exploited in object injection scenarios when class names are derived from untrusted sources.
*   **Example:** An application takes a class name from a URL parameter to instantiate a logging class. An attacker modifies the parameter to point to a malicious class that executes system commands in its `__destruct()` method. When the application instantiates this class using `instantiator`, and the object is later destroyed, the malicious code executes.
*   **Impact:** Remote Code Execution (RCE), Denial of Service (DoS), Information Disclosure, Privilege Escalation.
*   **Risk Severity:** **Critical**, as it can lead to Remote Code Execution.
*   **Mitigation Strategies:**
    *   **Never Instantiate User-Controlled Classes Directly:** Avoid using `instantiator` (or any dynamic instantiation mechanism) with class names directly derived from user input or untrusted external sources.
    *   **Strict Whitelisting of Allowed Classes:** If dynamic instantiation is necessary, implement a strict whitelist of allowed class names. Only permit instantiation of classes that are explicitly intended for this purpose and are considered safe.

