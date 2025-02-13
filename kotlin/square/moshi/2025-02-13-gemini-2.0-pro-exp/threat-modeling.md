# Threat Model Analysis for square/moshi

## Threat: [Polymorphic Deserialization to Unexpected Type](./threats/polymorphic_deserialization_to_unexpected_type.md)

*   **Description:** An attacker crafts a JSON payload that specifies a malicious concrete type for a field declared as an interface or abstract class.  Moshi, when configured for polymorphic deserialization (e.g., using sealed classes or `@JsonSubTypes`), instantiates the attacker-provided type. If this malicious type has undesirable side effects (e.g., executes code in its constructor, accesses restricted resources), it can lead to code execution or other security compromises.
*   **Impact:** Remote Code Execution (RCE), Denial of Service (DoS), privilege escalation, data breaches.
*   **Affected Moshi Component:** Polymorphic type handling mechanisms: `@JsonClass(generator = "sealed:...")`, `@JsonSubTypes`, custom `JsonAdapter` implementations handling interfaces/abstract classes.
*   **Risk Severity:** Critical (if RCE is possible), High (otherwise).
*   **Mitigation Strategies:**
    *   Use sealed classes/interfaces in Kotlin to strictly limit allowed subtypes.
    *   Implement robust validation within custom `JsonAdapter`'s `fromJson` method to verify the type and properties of the deserialized object *before* returning it.
    *   Avoid using polymorphic deserialization for untrusted input if possible.  Consider using a DTO with concrete types and explicit validation.
    *   If using `@JsonSubTypes`, ensure the list of allowed subtypes is minimal and well-vetted.

## Threat: [Custom Adapter `fromJson` Vulnerability](./threats/custom_adapter__fromjson__vulnerability.md)

*   **Description:** An attacker provides malicious JSON input that exploits a vulnerability in a custom `JsonAdapter`'s `fromJson` method. This could involve bypassing validation checks, triggering unexpected object creation, or causing resource exhaustion.  The vulnerability stems from developer error in the custom adapter code.
*   **Impact:** RCE, DoS, data corruption, logic errors, bypass of security controls.
*   **Affected Moshi Component:** Custom `JsonAdapter` implementations (specifically the `fromJson` method).
*   **Risk Severity:** Critical (if RCE is possible), High (otherwise, depending on the vulnerability).
*   **Mitigation Strategies:**
    *   Thoroughly review and test all custom `JsonAdapter` implementations, especially the `fromJson` method.
    *   Implement comprehensive input validation within `fromJson`, checking types, ranges, and formats of all data.
    *   Follow secure coding practices within the adapter, avoiding potentially dangerous operations.
    *   Use a "fail-fast" approach: throw exceptions immediately upon detecting invalid input.
    *   Consider using a linter or static analysis tool to identify potential vulnerabilities in the adapter code.

## Threat: [Sensitive Data Exposure via Serialization](./threats/sensitive_data_exposure_via_serialization.md)

*   **Description:** Sensitive data (e.g., passwords, API keys, internal state) is accidentally included in the serialized JSON output because it was not marked as `@Transient`.  This data is then exposed to unauthorized parties.
*   **Impact:** Data breach, unauthorized access, compromise of sensitive information.
*   **Affected Moshi Component:** Core Moshi serialization logic (handling of fields during `toJson`).  Custom `JsonAdapter` implementations (specifically the `toJson` method).
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   Carefully mark all sensitive fields with `@Transient` (or the Kotlin `transient` modifier).
    *   Use DTOs to explicitly define the data to be serialized, rather than serializing entire domain objects.
    *   Review custom `JsonAdapter` implementations to ensure they do not serialize sensitive data.

## Threat: [Unexpected Field Type Handling (Potentially High Severity Cases)](./threats/unexpected_field_type_handling__potentially_high_severity_cases_.md)

*   **Description:** A field is expected to be a primitive type, but the attacker provides a complex object. If a custom adapter or default Moshi behavior attempts to use this unexpected object in a way that interacts with external resources or performs sensitive operations *without proper validation*, it could lead to higher-severity issues. This is a more specific and higher-risk scenario than the general "logic error" case. For example, if the unexpected object is used to construct a file path or a database query without sanitization, it could lead to injection vulnerabilities.
*   **Impact:** Potential for injection vulnerabilities (e.g., file path traversal, SQL injection if the data is used in a query), data corruption, denial of service (if the unexpected type leads to resource exhaustion).
*   **Affected Moshi Component:** Core Moshi type handling, custom `JsonAdapter` implementations.
*   **Risk Severity:** High (depending on how the unexpected type is ultimately used).
*   **Mitigation Strategies:**
    *   **Strict Type Enforcement:** Use custom adapters to enforce strict type checking and reject unexpected types.
    *   **Input Validation:** Even if a type is technically allowed, validate its *contents* before using it in any sensitive operation (e.g., constructing file paths, database queries, etc.).
    *   **Principle of Least Privilege:** Ensure that code handling deserialized data operates with the minimum necessary privileges.

