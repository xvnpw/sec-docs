# Attack Surface Analysis for kotlin/kotlinx.serialization

## Attack Surface: [Arbitrary Code Execution (ACE) via Polymorphic Deserialization](./attack_surfaces/arbitrary_code_execution__ace__via_polymorphic_deserialization.md)

*   **Description:** An attacker crafts malicious input that, when deserialized, instantiates a class that executes arbitrary code on the target system. This is the most dangerous vulnerability type associated with deserialization.
*   **`kotlinx.serialization` Contribution:** The library's support for polymorphic serialization/deserialization (handling objects of different classes within a hierarchy) provides the *direct mechanism* for this attack if not properly secured. The `@SerialName` annotation and class discriminator handling are central to this.  The library's features *enable* this vulnerability if misused.
*   **Example:**
    *   Application expects a `Shape` interface with `Circle` and `Square` implementations.
    *   Attacker sends JSON with a class discriminator pointing to a malicious class `Exploit` (not part of the expected hierarchy) that implements `Shape` (or a common interface) and contains code in its constructor or a deserialization callback (e.g., using `@PostDeserialize`) to execute a shell command.
    *   If the application doesn't validate the class discriminator, `kotlinx.serialization` instantiates `Exploit`, and the malicious code runs.
*   **Impact:** Complete system compromise. The attacker can gain full control of the application and potentially the underlying system.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Whitelist Class Discriminators:** *Before* deserialization (ideally within a custom `DeserializationStrategy`), rigorously validate the class discriminator against a *whitelist* of allowed, trusted class names.  Do *not* rely solely on the library's built-in checks. This is the *primary* mitigation.
    *   **Sealed Classes/Interfaces:** Use sealed classes or interfaces whenever possible for polymorphic hierarchies. This restricts the possible subtypes known to the compiler, *but still requires validation* of the discriminator.
    *   **Controlled `SerializersModule`:** Use a carefully constructed `SerializersModule` that only registers serializers for the necessary, trusted types.  Avoid registering serializers for potentially dangerous classes or broad interfaces.  Consider separate modules for trusted vs. untrusted data.
    *   **Custom Deserialization Strategies:** Implement custom `DeserializationStrategy` instances to perform pre-deserialization validation of the class discriminator and potentially other input data *before* the library attempts to instantiate any object.
    *   **Input Validation:** Validate all input data *before* passing it to the `kotlinx.serialization` deserialization functions. Check for expected types, lengths, and values. This is a defense-in-depth measure, *not* a primary mitigation for ACE.

## Attack Surface: [Denial of Service (DoS) via Resource Exhaustion](./attack_surfaces/denial_of_service__dos__via_resource_exhaustion.md)

*   **Description:** An attacker sends specially crafted input designed to consume excessive resources (CPU, memory, stack) during deserialization, leading to application crashes or unresponsiveness.
    *   **`kotlinx.serialization` Contribution:** The library's deserialization process, particularly when handling complex object graphs or large data structures, can be *directly* manipulated to consume excessive resources if the input is not properly validated. The library's parsing and object creation logic are the attack surface.
    *   **Example:**
        *   Attacker sends JSON with a deeply nested object structure (e.g., an array containing another array, containing another array, etc., repeated many times).
        *   `kotlinx.serialization`'s deserialization attempts to create all these nested objects, potentially leading to a stack overflow or out-of-memory error.
        *   Alternatively, a very large string or a collection with millions of elements could be sent, causing excessive memory allocation by the library.
    *   **Impact:** Application unavailability. The application becomes unresponsive or crashes, preventing legitimate users from accessing it.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Size Limits:** Enforce strict limits on the overall size of the input data being deserialized *before* passing it to `kotlinx.serialization`.
        *   **Depth Limits:** Implement a mechanism to limit the nesting depth of objects during deserialization. This can be done within custom serializers or by using a custom `DeserializationStrategy` that tracks the nesting level and throws an exception if it exceeds a threshold. This directly mitigates the library's recursive descent parsing.
        *   **Collection Size Limits:** Limit the maximum number of elements allowed in collections (lists, maps, sets) during deserialization.  This can be enforced within custom serializers.
        *   **Timeouts:** Set timeouts for `kotlinx.serialization` deserialization operations to prevent them from running indefinitely.
        *   **Resource Monitoring:** Monitor resource usage (CPU, memory) during deserialization and terminate the process if limits are exceeded. This is a last resort, but can prevent complete system exhaustion.

