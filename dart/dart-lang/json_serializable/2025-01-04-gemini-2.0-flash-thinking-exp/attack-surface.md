# Attack Surface Analysis for dart-lang/json_serializable

## Attack Surface: [Serialization of Sensitive Data](./attack_surfaces/serialization_of_sensitive_data.md)

* **Description:** The application unintentionally serializes sensitive data that should not be exposed in the JSON output.
    * **How `json_serializable` Contributes:** The generated `toJson` method automatically serializes all fields in the Dart model unless explicitly excluded. If sensitive data is included in the model without proper consideration, it will be part of the serialized JSON.
    * **Example:** A Dart model includes a `String passwordHash` field, and the generated `toJson` method serializes this hash, potentially exposing it if the JSON is transmitted insecurely.
    * **Impact:** Information disclosure, potential compromise of user credentials or other sensitive information.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Use `@JsonKey(ignore: true)` to exclude sensitive fields from serialization.
        * Create separate DTOs (Data Transfer Objects) for serialization.
        * Sanitize or redact sensitive data before serialization.

## Attack Surface: [Vulnerabilities in Custom `JsonConverter` Implementations](./attack_surfaces/vulnerabilities_in_custom__jsonconverter__implementations.md)

* **Description:** Developers implement custom `JsonConverter` classes to handle specific data types or formats, and these converters contain security vulnerabilities.
    * **How `json_serializable` Contributes:** `json_serializable` provides the framework for using custom converters. If these converters are not implemented securely, they can introduce vulnerabilities.
    * **Example:** A custom converter for handling dates might be vulnerable to format string bugs or might not properly handle invalid date formats, leading to errors or unexpected behavior. If the converter interacts with external systems based on the parsed data, vulnerabilities could be critical.
    * **Impact:** Varies depending on the vulnerability in the converter, could range from application crashes to remote code execution if the converter processes untrusted input unsafely.
    * **Risk Severity:** High (if converter handles external input).
    * **Mitigation Strategies:**
        * Thoroughly review and test custom `JsonConverter` implementations.
        * Avoid complex logic in converters if possible.
        * Sanitize and validate input within custom converters.
        * Follow secure coding practices when implementing converters.

