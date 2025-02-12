# Threat Model Analysis for fasterxml/jackson-core

## Threat: [Remote Code Execution (RCE) via Polymorphic Deserialization](./threats/remote_code_execution__rce__via_polymorphic_deserialization.md)

*   **Description:** An attacker crafts a malicious JSON payload that includes type information (e.g., `@class`) pointing to a vulnerable "gadget" class. When Jackson deserializes this payload, it instantiates the gadget class, which executes arbitrary code during its initialization or deserialization process. The attacker can leverage publicly known gadget chains or discover new ones. This is the most significant threat to Jackson.
    *   **Impact:** Complete system compromise. The attacker gains the ability to execute arbitrary code with the privileges of the application, potentially leading to data theft, system modification, or further network compromise.
    *   **Affected Jackson-core Component:**
        *   `ObjectMapper` (specifically, methods like `readValue()`, `readTree()`, etc., when used with polymorphic type handling).
        *   `enableDefaultTyping()` (highly dangerous and should be avoided).
        *   `@JsonTypeInfo` annotation (when used with `Id.CLASS` or `Id.MINIMAL_CLASS` and insufficient whitelisting).
        *   `TypeResolverBuilder` and `TypeIdResolver` (if custom implementations are insecure).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid `enableDefaultTyping()`:** This is the most crucial step.
        *   **Strict Whitelisting:** Use `@JsonTypeInfo(use = Id.NAME)` with `@JsonSubTypes` to define a precise whitelist of allowed classes for deserialization.  *Never* use `Id.CLASS` without a very strict, manually maintained whitelist.
        *   **Gadget Class Blacklisting:** Use a `DeserializationProblemHandler` to block known vulnerable gadget classes. Maintain an up-to-date blacklist. This is a crucial defense-in-depth measure.
        *   **Input Validation (Defense in Depth):** Validate the structure and content of JSON input *before* deserialization to reject unexpected data. This is not a primary mitigation, but adds a layer of defense.
        *   **Regular Updates:** Keep Jackson and all related libraries up-to-date to benefit from the latest security patches.
        *   **SecurityManager (Deprecated):** Consider using a `SecurityManager` (though deprecated) to limit the capabilities of deserialized code, but be aware of its complexity and limitations.

## Threat: [Data Corruption via Invalid UTF-8 (Elevated to High in Specific Cases)](./threats/data_corruption_via_invalid_utf-8__elevated_to_high_in_specific_cases_.md)

*   **Description:** While typically medium severity, if the application relies on the *integrity* of deserialized data for security-critical decisions (e.g., authentication, authorization, or input validation for other systems), then mishandling of invalid UTF-8 can become a high-severity issue. An attacker could submit JSON with crafted invalid UTF-8 to bypass checks or inject unexpected data.
    *   **Impact:** In the worst-case scenario (where corrupted data influences security decisions), this could lead to authentication bypass, privilege escalation, or other security vulnerabilities. In less critical cases, it leads to data integrity issues and application malfunction.
    *   **Affected Jackson-core Component:**
        *   `JsonParser` (UTF-8 decoding logic).
        *   `StreamReadConstraints` (relevant for configuration).
    *   **Risk Severity:** High (in security-critical contexts), otherwise Medium.
    *   **Mitigation Strategies:**
        *   **Strict UTF-8 Validation:** This is *essential* in security-critical contexts. Configure Jackson to strictly validate UTF-8 input and reject any invalid sequences. Use `StreamReadConstraints` and set it to fail on invalid UTF-8.
        *   **Input Validation (Defense in Depth):** Validate input encoding before passing it to Jackson, although this is less reliable than Jackson's built-in validation.  This is particularly important if the data is used in security-sensitive operations.

