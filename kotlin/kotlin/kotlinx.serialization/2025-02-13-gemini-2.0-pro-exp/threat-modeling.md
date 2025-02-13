# Threat Model Analysis for kotlin/kotlinx.serialization

## Threat: [Arbitrary Class Instantiation via Polymorphic Deserialization](./threats/arbitrary_class_instantiation_via_polymorphic_deserialization.md)

*   **Description:** An attacker crafts a malicious JSON (or other format) payload that specifies a class name (`@type` or similar mechanism) not intended to be deserialized by the application.  If polymorphic deserialization is enabled without proper restrictions, `kotlinx.serialization` might instantiate this arbitrary class. If this class has side effects in its constructor, init block, or `@PostConstruct`-like methods (if any are supported in the target environment), the attacker can achieve code execution. This leverages the core polymorphic deserialization feature of the library.
*   **Impact:** Remote Code Execution (RCE), allowing the attacker to take complete control of the application or system.
*   **Affected Component:** `Json` (or other format) configuration with `serializersModule` that enables polymorphic deserialization (`polymorphic(...)`) without a strict whitelist of allowed subclasses. Specifically, the `decodeFromJsonElement` function (or equivalent for other formats) and the underlying polymorphic deserialization logic.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Class Whitelisting:** Use `SerializersModule` to *explicitly* register *only* the expected subclasses for each polymorphic base class.  Do *not* allow arbitrary class instantiation. This is the *primary* defense.
        ```kotlin
        val module = SerializersModule {
            polymorphic(BaseClass::class) {
                subclass(AllowedClass1::class)
                subclass(AllowedClass2::class)
                // ... ONLY allowed classes
            }
        }
        val format = Json { serializersModule = module }
        ```
    *   **Avoid Polymorphism Where Possible:** If polymorphism is not strictly required, use a non-polymorphic approach. This eliminates the risk entirely.
    *   **Input Validation (Pre-Deserialization):** If technically feasible, perform preliminary validation of the input *before* passing it to `kotlinx.serialization`. This might involve checking for known malicious patterns or restricting allowed `@type` values at the string level. This is a defense-in-depth measure, but whitelisting is more robust.
    *   **Sandboxing:** Consider deserializing untrusted data in a sandboxed environment (e.g., a separate process with limited privileges) to limit the impact of potential code execution. This is a more advanced mitigation.

## Threat: [Denial of Service via Deeply Nested Objects](./threats/denial_of_service_via_deeply_nested_objects.md)

*   **Description:** An attacker provides a JSON (or other format) payload with deeply nested objects or arrays.  Deserializing this structure can consume excessive stack space or memory, leading to a `StackOverflowError` or `OutOfMemoryError`, causing the application to crash or become unresponsive. This exploits the recursive nature of the deserialization process within `kotlinx.serialization`.
*   **Impact:** Denial of Service (DoS), rendering the application unavailable to legitimate users.
*   **Affected Component:** The parsing and deserialization logic within the chosen format (e.g., `Json`, `CBOR`, `ProtoBuf`). Specifically, the recursive descent parser used to handle nested structures *within the library*.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Size Limits:** Enforce strict limits on the overall size of the input data *before* it reaches the `kotlinx.serialization` deserialization functions. Reject any input exceeding this limit. This is the most practical and readily implementable mitigation.
    *   **Depth Limits (Custom Solution - Pre-processing):** `kotlinx.serialization` *does not* natively support depth limits. You *must* implement a custom solution *before* passing data to the library. This is crucial:
        *   **Pre-parsing with a SAX-style parser:** Use a separate, lightweight SAX (Simple API for XML) or similar event-based parser to count the nesting depth *without* fully deserializing the object. Reject the input if the depth exceeds a predefined threshold. This pre-processing step prevents the malicious input from reaching `kotlinx.serialization`.
    *   **Resource Monitoring:** Monitor CPU and memory usage during deserialization. If resource consumption spikes abnormally, terminate the operation. This is a reactive measure, best combined with proactive limits.
    *   **Timeouts:** Implement timeouts for deserialization operations. If deserialization takes longer than a predefined limit, terminate the process. Again, this is reactive and should be combined with proactive limits.

## Threat: [Sensitive Data Exposure via Default Serialization](./threats/sensitive_data_exposure_via_default_serialization.md)

*    **Description:** A class marked with `@Serializable` contains sensitive fields (passwords, API keys, etc.) that are not explicitly excluded. `kotlinx.serialization` will, by default, serialize these. If this serialized data is mishandled, sensitive information is exposed. This directly relates to how `kotlinx.serialization` handles fields without the `@Transient` annotation.
*    **Impact:** Information disclosure, potentially leading to credential theft or unauthorized access.
*    **Affected Component:** The core serialization mechanism of `kotlinx.serialization`. Any format is affected. The `@Serializable` annotation and the default behavior of serializing all non-transient fields.
*    **Risk Severity:** High
*    **Mitigation Strategies:**
    *    **`@Transient` Annotation:** Mark sensitive fields with `@Transient`. This is the *primary* and most direct mitigation, preventing serialization.
    *    **Data Transfer Objects (DTOs):** Use separate DTO classes for serialization, containing *only* safe-to-expose fields. Map between domain objects and DTOs before serialization.
    *    **Custom Serializers:** Create custom serializers to explicitly control which fields are included, offering fine-grained control but increasing complexity.
    *    **Code Review:** Carefully review all `@Serializable` classes to ensure no sensitive fields are unintentionally serialized.

