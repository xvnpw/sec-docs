# Attack Surface Analysis for square/moshi

## Attack Surface: [Deserialization of untrusted data leading to potential vulnerabilities.](./attack_surfaces/deserialization_of_untrusted_data_leading_to_potential_vulnerabilities.md)

*   **How Moshi Contributes to the Attack Surface:** Moshi is responsible for parsing and converting JSON data into Java/Kotlin objects. If the input JSON is malicious or crafted in unexpected ways, Moshi's deserialization process can be exploited.
    *   **Example:** An attacker sends a JSON payload with a deeply nested structure, potentially leading to a stack overflow exception during parsing by Moshi.
    *   **Impact:** Denial of service (DoS) through resource exhaustion (CPU, memory), unexpected application behavior, or potential for further exploitation if the application doesn't handle deserialization errors properly.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement input validation *before* deserialization to check for expected data types, formats, and ranges.
        *   Set limits on the depth and size of incoming JSON payloads to prevent resource exhaustion.
        *   Implement robust error handling around Moshi's deserialization process to gracefully handle exceptions and prevent application crashes.

## Attack Surface: [Exploiting vulnerabilities in custom Moshi adapters.](./attack_surfaces/exploiting_vulnerabilities_in_custom_moshi_adapters.md)

*   **How Moshi Contributes to the Attack Surface:** Moshi allows developers to create custom adapters for handling specific data types or complex deserialization logic. If these adapters contain security flaws, they can be exploited.
    *   **Example:** A custom adapter designed to deserialize a date format has a bug that allows an attacker to inject arbitrary code by providing a specially crafted date string.
    *   **Impact:** Data corruption, information disclosure, or potentially remote code execution depending on the vulnerability in the custom adapter.
    *   **Risk Severity:** High (can be critical depending on the adapter's functionality)
    *   **Mitigation Strategies:**
        *   Thoroughly review and test all custom Moshi adapters for potential vulnerabilities.
        *   Follow secure coding practices when developing custom adapters, including proper input validation and sanitization within the adapter logic.
        *   Consider using well-tested and established libraries for common data types instead of writing custom adapters from scratch.

## Attack Surface: [Polymorphic deserialization vulnerabilities.](./attack_surfaces/polymorphic_deserialization_vulnerabilities.md)

*   **How Moshi Contributes to the Attack Surface:** Moshi's support for polymorphic deserialization allows the application to deserialize JSON into different concrete types based on a type identifier in the JSON. If not carefully configured, an attacker might be able to influence the type of object instantiated.
    *   **Example:** An attacker manipulates the type identifier in the JSON to force Moshi to instantiate a class that has unintended side effects or known vulnerabilities in its constructor or other methods.
    *   **Impact:** Potential for arbitrary code execution or other malicious actions if the attacker can control the instantiated class.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use a whitelist approach for allowed polymorphic types, explicitly defining which classes can be instantiated during deserialization.
        *   Avoid using default implementations for polymorphic type resolution that rely solely on untrusted input.
        *   Carefully review the constructors and methods of classes that can be instantiated through polymorphic deserialization for potential security risks.

## Attack Surface: [Unintended serialization of sensitive data.](./attack_surfaces/unintended_serialization_of_sensitive_data.md)

*   **How Moshi Contributes to the Attack Surface:** Moshi, by default, serializes all public and non-transient fields of an object. If developers are not careful, sensitive information might be included in the serialized JSON output.
    *   **Example:** A developer forgets to mark a field containing a user's API key as `@Transient` or `@Json(ignore = true)`, and this key is included in the JSON response sent to a client.
    *   **Impact:** Information disclosure of sensitive data.
    *   **Risk Severity:** High (depending on the sensitivity of the exposed data)
    *   **Mitigation Strategies:**
        *   Explicitly control which fields are serialized using annotations like `@Transient` or `@Json(ignore = true)`.
        *   Review the serialization configuration and the structure of data classes to ensure no sensitive information is inadvertently included in the output.
        *   Consider using DTOs (Data Transfer Objects) that only contain the necessary data for serialization, avoiding the direct serialization of domain entities.

