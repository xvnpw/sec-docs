# Threat Model Analysis for fasterxml/jackson-databind

## Threat: [Remote Code Execution (RCE) via Polymorphic Deserialization](./threats/remote_code_execution__rce__via_polymorphic_deserialization.md)

*   **Threat:** Remote Code Execution (RCE) via Polymorphic Deserialization

    *   **Description:** An attacker crafts a malicious JSON payload containing a type identifier (e.g., using `@JsonTypeInfo`) that points to a known "gadget" class present on the application's classpath. When `jackson-databind` deserializes this payload, it instantiates the gadget class.  The gadget's constructor, `readObject`, or `readResolve` method then executes arbitrary code provided by the attacker, often leveraging existing Java libraries in unintended ways. The attacker might use publicly available exploit payloads or craft custom ones.
    *   **Impact:** Complete system compromise. The attacker gains the privileges of the application user, allowing them to read, modify, or delete data, install malware, or pivot to other systems.
    *   **Affected Component:**
        *   `ObjectMapper` (specifically, methods related to deserialization: `readValue`, `readTree`, etc.)
        *   Polymorphic Type Handling mechanisms: `@JsonTypeInfo`, `@JsonSubTypes`, `DefaultTyping` (when enabled via `ObjectMapper.enableDefaultTyping()`).
        *   `com.fasterxml.jackson.databind.jsontype.impl.TypeDeserializerBase` and its subclasses.
        *   Potentially any class on the classpath that can be used as a gadget (this is not a Jackson component *per se*, but it's the target of the attack).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Disable Default Typing:** Avoid `ObjectMapper.enableDefaultTyping()`. This is the primary enabler of this vulnerability.
        *   **Whitelist Allowed Types:** If polymorphic deserialization is *required*, use `BasicPolymorphicTypeValidator` (or a custom validator) to create a strict whitelist of allowed classes.  This validator is configured on the `ObjectMapper`. Example:
            ```java
            BasicPolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType(MyAllowedClass.class)
                .allowIfSubType(AnotherAllowedClass.class)
                // ... add other allowed classes ...
                .build();

            ObjectMapper mapper = JsonMapper.builder()
                .activateDefaultTyping(ptv, DefaultTyping.NON_FINAL) // Or other appropriate DefaultTyping setting
                .build();
            ```
        *   **Update Jackson:** Use the latest version of `jackson-databind`.  Security fixes and improved default behaviors are frequently released.
        *   **Minimize Gadget Dependencies:** Reduce the number of libraries on the classpath that contain potential gadget classes.
        *   **Input Validation (Limited):** Validate the *structure* of the JSON before deserialization, but do *not* rely on this as a primary defense.

