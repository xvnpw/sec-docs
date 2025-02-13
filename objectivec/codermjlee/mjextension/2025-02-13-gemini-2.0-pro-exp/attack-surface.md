# Attack Surface Analysis for codermjlee/mjextension

## Attack Surface: [Object Instantiation Attacks (Deserialization)](./attack_surfaces/object_instantiation_attacks__deserialization_.md)

*Description:* Attackers craft malicious JSON to instantiate unauthorized or unexpected classes, potentially leading to code execution.
*MJExtension Contribution:* `MJExtension`'s core functionality is to create Objective-C objects based on JSON data, making it the direct mechanism for this attack.
*Example:* JSON designed to instantiate a hypothetical `SystemCommandExecutor` class instead of the expected `User` class.
*Impact:* Arbitrary code execution, complete system compromise.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Strict Class Whitelisting:** Implement a robust mechanism (e.g., configuration file, hardcoded list, custom `mj_objectClassInArray` implementation) to *explicitly* allow only specific, pre-approved classes to be instantiated by `MJExtension`. This is the *primary* defense.
    *   **Avoid Generic Object Creation:** Prefer strongly-typed model objects over generic `NSObject` or `NSDictionary` instances, reducing the attack surface.

## Attack Surface: [Property Manipulation Attacks (Deserialization)](./attack_surfaces/property_manipulation_attacks__deserialization_.md)

*Description:* Attackers modify property values within the JSON to alter application behavior or gain unauthorized access.
*MJExtension Contribution:* `MJExtension` sets property values based on the JSON data, providing the pathway for this manipulation.
*Example:* Setting an `isAdmin` property to `true` in the JSON to gain administrative privileges.
*Impact:* Privilege escalation, data modification, bypass of security controls.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Property-Level Validation:** Implement validation logic *within* model classes (e.g., in setters or custom validation methods) to enforce constraints on property values.
    *   **Read-Only Properties:** Use `readonly` for properties that should not be modified by external input.
    *   **`mj_ignoredPropertyNames`:** Explicitly ignore sensitive properties during deserialization.
    *   **Custom Key Mapping (`mj_replacedKeyFromPropertyName`):** Control how JSON keys map to properties.

## Attack Surface: [Information Disclosure (Serialization)](./attack_surfaces/information_disclosure__serialization_.md)

*Description:* Sensitive data is unintentionally exposed when `MJExtension` serializes objects to JSON.
*MJExtension Contribution:* `MJExtension`'s serialization functionality is the direct cause of this exposure if not configured correctly.
*Example:* Serializing a `User` object that includes a password hash or API key.
*Impact:* Exposure of sensitive data, potential for credential theft or unauthorized access.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **`mj_ignoredPropertyNames`:** *Explicitly* list properties to exclude from serialization. This is the *primary* mitigation.
    *   **Data Transfer Objects (DTOs):** Use separate DTO classes for serialization, containing only the data that is safe to expose.

