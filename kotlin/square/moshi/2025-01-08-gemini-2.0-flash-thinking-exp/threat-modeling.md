# Threat Model Analysis for square/moshi

## Threat: [Type Confusion during Deserialization](./threats/type_confusion_during_deserialization.md)

*   **Description:** An attacker crafts a JSON payload that, when deserialized by Moshi, results in an object of an unexpected type. This could be achieved by manipulating field names or structures to bypass type checks or exploit vulnerabilities in custom adapters. The attacker aims to cause the application to treat the object as a different type, leading to unexpected behavior.
*   **Impact:** Application crashes due to type casting exceptions, incorrect program logic execution based on the wrong object type, potential for exploitation if the incorrectly typed object is used in a security-sensitive operation.
*   **Affected Moshi Component:** `Moshi.adapter()` function, custom `TypeAdapter` implementations.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Explicitly define expected types for deserialization using concrete classes or `Types` utility.
    *   Implement robust error handling during deserialization to catch `ClassCastException` or similar errors.
    *   Thoroughly test custom `TypeAdapter` implementations for correct type handling and edge cases.
    *   Consider using sealed classes or enums where appropriate to limit the possible types.

## Threat: [Exploiting Vulnerabilities in Custom Adapters](./threats/exploiting_vulnerabilities_in_custom_adapters.md)

*   **Description:** If the application uses custom `TypeAdapter` implementations, an attacker can exploit vulnerabilities within these adapters. This could involve sending maliciously crafted JSON that triggers insecure logic within the adapter, leading to arbitrary code execution, data corruption, or information disclosure.
*   **Impact:** Arbitrary code execution on the server, data corruption or manipulation, leakage of sensitive information.
*   **Affected Moshi Component:** Custom `TypeAdapter` implementations.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Thoroughly review and security audit all custom `TypeAdapter` implementations.
    *   Follow secure coding practices when developing custom adapters, including input validation and sanitization.
    *   Avoid performing complex or security-sensitive operations within custom adapters if possible.
    *   Consider using well-tested and established libraries for common data transformations instead of implementing them from scratch in adapters.

## Threat: [Information Disclosure through Unintended Serialization](./threats/information_disclosure_through_unintended_serialization.md)

*   **Description:** Moshi might serialize sensitive information that was not intended to be included in the JSON output. This can happen if fields containing sensitive data are not properly marked as `@Transient` or excluded from serialization, or if custom adapters inadvertently expose internal state. An attacker intercepting the serialized data can gain access to this sensitive information.
*   **Impact:** Exposure of sensitive data such as credentials, personal information, internal system details, API keys, etc.
*   **Affected Moshi Component:** `Moshi.adapter()` function, `JsonWriter` during serialization, custom `TypeAdapter` implementations.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Carefully review the fields being serialized and mark sensitive fields with the `@Transient` annotation or use `@JsonIgnore`.
    *   Ensure custom adapters only serialize the necessary data and do not expose sensitive internal state.
    *   Use DTOs (Data Transfer Objects) that only contain the data intended for serialization, avoiding direct serialization of domain objects.
    *   Implement proper access control and encryption mechanisms to protect serialized data in transit and at rest.

