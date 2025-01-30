# Attack Surface Analysis for square/moshi

## Attack Surface: [Polymorphic Deserialization Type Confusion](./attack_surfaces/polymorphic_deserialization_type_confusion.md)

*   **Description:** When using Moshi's polymorphic deserialization, a malicious JSON payload can be crafted to trick the application into instantiating an unexpected object type. This can bypass intended security checks or lead to unexpected behavior.
*   **Moshi Contribution:** Moshi's `@JsonClass(polymorphic = true)` relies on type information within the JSON to determine which class to instantiate. This type information can be manipulated by an attacker.
*   **Example:**  An interface `Animal` with implementations `Dog` and `Cat`. JSON is expected to specify the `type` field to deserialize to either `Dog` or `Cat`. A malicious payload might provide a type value that is not intended or handled, potentially leading to unexpected object creation or errors.
*   **Impact:**  Bypass of security checks, unexpected application behavior, potential for further exploitation if the unexpected object type has vulnerabilities or is handled incorrectly by application logic.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strictly Validate Deserialized Objects:** After deserialization, perform thorough validation of the object type and its properties to ensure it matches the expected type and data.
    *   **Whitelist Allowed Types:** Explicitly define and whitelist the allowed types for polymorphic deserialization. Reject any JSON payloads that attempt to specify types outside of this whitelist.
    *   **Avoid Relying Solely on Type Information from JSON:**  If possible, use alternative methods to determine the object type that are less reliant on user-provided JSON data (e.g., based on endpoint or context).
    *   **Secure Default Type Handling:**  Carefully consider the default type handling in polymorphic deserialization. Ensure that the default case is secure and doesn't lead to unexpected or vulnerable object instantiation.

## Attack Surface: [Custom Adapter Vulnerabilities - Input Validation Failures](./attack_surfaces/custom_adapter_vulnerabilities_-_input_validation_failures.md)

*   **Description:** Developers creating custom `JsonAdapter` implementations might fail to properly validate input data from JSON. This can introduce vulnerabilities like injection flaws or logic errors if the adapter interacts with external systems or performs sensitive operations.
*   **Moshi Contribution:** Moshi allows developers to create custom adapters for complex or specific JSON handling. The security of these adapters is the responsibility of the developer.
*   **Example:** A custom adapter reads a string from JSON and directly uses it in an SQL query without sanitization, leading to SQL Injection.
*   **Impact:** Injection vulnerabilities (SQL Injection, Command Injection, etc.), data corruption, unauthorized access.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Implement Robust Input Validation in Custom Adapters:**  Thoroughly validate all input data received from JSON within custom adapters. Sanitize and escape data as needed before using it in external systems or sensitive operations.
    *   **Follow Secure Coding Practices:** Adhere to secure coding principles when developing custom adapters. Avoid using user-controlled data directly in commands or queries without proper validation and sanitization.
    *   **Use Parameterized Queries/Prepared Statements:** When interacting with databases in custom adapters, always use parameterized queries or prepared statements to prevent SQL Injection.
    *   **Code Reviews and Security Testing:** Conduct thorough code reviews and security testing of custom `JsonAdapter` implementations to identify and fix potential vulnerabilities.

## Attack Surface: [Accidental Serialization of Sensitive Data](./attack_surfaces/accidental_serialization_of_sensitive_data.md)

*   **Description:** Moshi might inadvertently serialize fields containing sensitive information (e.g., passwords, API keys, internal identifiers) in JSON responses if not properly configured. This can lead to information disclosure.
*   **Moshi Contribution:** Moshi's default serialization behavior might include fields that should be excluded for security reasons if developers are not careful about configuration and annotations.
*   **Example:** A `User` class containing a `passwordHash` field is serialized in a JSON response without explicitly excluding this field, exposing the password hash to unauthorized parties.
*   **Impact:** Information disclosure, privacy violation, potential for account compromise or further attacks if exposed data is sensitive enough.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use `@Json(ignore = true)` or `@Transient` Annotations:**  Explicitly annotate fields containing sensitive data with `@Json(ignore = true)` or `@Transient` to prevent them from being serialized by Moshi.
    *   **Carefully Review Serialized Objects:**  Thoroughly review the classes and objects being serialized by Moshi to identify and exclude any fields that should not be exposed in JSON responses.
    *   **Use Data Transfer Objects (DTOs):** Create dedicated DTO classes specifically for JSON serialization. These DTOs should only include the data that is intended to be exposed, avoiding accidental serialization of sensitive fields from domain objects.
    *   **Principle of Least Privilege in Serialization:** Only serialize the data that is absolutely necessary for the intended purpose. Avoid over-serialization.

