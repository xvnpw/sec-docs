# Mitigation Strategies Analysis for square/moshi

## Mitigation Strategy: [Strict Validation and Type Safety with Generated Adapters](./mitigation_strategies/strict_validation_and_type_safety_with_generated_adapters.md)

*   **Description:**
    1.  **Use `@JsonClass(generateAdapter = true)`:** Annotate all data classes intended for JSON serialization/deserialization with `@JsonClass(generateAdapter = true)`. This is the foundation of secure Moshi usage, enabling compile-time adapter generation.
    2.  **Kotlin Data Classes:** Define your data models using Kotlin data classes. This works seamlessly with generated adapters.
    3.  **Enforce `failOnUnknown()` (Custom Implementation):** Implement a custom `JsonAdapter.Factory` as detailed in previous responses. This factory intercepts deserialization, inspects the JSON for unknown fields, and throws a `JsonDataException` if any are found.  This is *essential* because the standard `JsonReader.setLenient(false)` is insufficient with generated adapters.  The custom factory must peek at the JSON structure *before* delegating to the generated adapter.  It also requires a rewindable `JsonReader` (like Okio's `Buffer`).
    4.  **Non-Nullable Types:** Declare fields as non-nullable whenever possible (e.g., `val name: String` instead of `val name: String?`). This leverages Kotlin's null safety to enforce the presence of required fields, causing Moshi to throw an exception if a required field is missing.
    5.  **Custom Adapters for Complex Validation:** For fields with specific validation requirements (email format, date ranges, etc.), create custom `JsonAdapter` implementations.  In the `fromJson` method, perform the validation and throw a `JsonDataException` if the input is invalid. Register these custom adapters with your `Moshi.Builder`.
    6.  **`@JsonQualifier` for Reusable Validation:** Define custom annotations using `@JsonQualifier` to encapsulate specific validation rules. Apply these annotations to fields in your data classes. Create corresponding `JsonAdapter` implementations that handle these qualified types and perform the validation. This promotes code reuse and keeps validation logic centralized.

*   **List of Threats Mitigated:**
    *   **Threat:** Arbitrary Code Execution (through type confusion/deserialization gadgets).
        *   **Severity:** Critical
    *   **Threat:** Data Injection (injecting unexpected fields or values).
        *   **Severity:** High
    *   **Threat:** Denial of Service (through resource exhaustion with *malformed* JSON, *not* large JSON).
        *   **Severity:** High
    *   **Threat:** Information Disclosure (leaking internal data through lenient parsing).
        *   **Severity:** Medium

*   **Impact:**
    *   **Arbitrary Code Execution:** Risk significantly reduced. Generated adapters and strict type checking make exploitation much harder.
    *   **Data Injection:** Risk significantly reduced. `failOnUnknown()` and custom adapters prevent processing of unexpected/invalid data.
    *   **Denial of Service:** Risk partially reduced (specifically for malformed JSON structure, not large payloads).
    *   **Information Disclosure:** Risk reduced. Strict parsing and non-nullable types help prevent accidental data exposure.

*   **Currently Implemented:**
    *   `@JsonClass(generateAdapter = true)` and Kotlin data classes are used in `src/main/kotlin/com/example/models`.
    *   Non-nullable types are partially used.
    *   An ineffective `failOnUnknown()` attempt exists.
    *   No custom adapters for validation.

*   **Missing Implementation:**
    *   The robust custom `failOnUnknown()` `JsonAdapter.Factory` is *critically* missing.
    *   Custom `JsonAdapter` implementations for specific field validation are missing.
    *   `@JsonQualifier` usage is missing.
    *   Comprehensive review for non-nullable types.

## Mitigation Strategy: [Limit Data Exposure (Moshi-Specific Aspects)](./mitigation_strategies/limit_data_exposure__moshi-specific_aspects_.md)

*   **Description:**
    1.  **Identify Sensitive Fields:** Review all data classes.
    2.  **Use `@Transient` or `@Json(ignore = true)`:** Annotate sensitive fields with `@Transient` (standard Kotlin) or `@Json(ignore = true)` (Moshi-specific) to prevent serialization/deserialization. This is the Moshi-specific part of limiting data exposure. While DTOs are a best practice, they are not *directly* related to Moshi configuration.

*   **List of Threats Mitigated:**
    *   **Threat:** Information Disclosure (leaking sensitive data in API responses).
        *   **Severity:** High to Critical

*   **Impact:**
    *   **Information Disclosure:** Risk significantly reduced. `@Transient` and `@Json(ignore = true)` prevent sensitive data from being included in JSON.

*   **Currently Implemented:**
    *   `@Transient` is used on a few fields in `src/main/kotlin/com/example/models/User.kt`.

*   **Missing Implementation:**
    *   Comprehensive review of all data classes to identify and annotate *all* sensitive fields.

## Mitigation Strategy: [Defensive Deserialization (Depth Limiting)](./mitigation_strategies/defensive_deserialization__depth_limiting_.md)

*   **Description:**
    1.  **Depth Limiting (Custom Adapter):** Create a custom `JsonAdapter.Factory` (as detailed in previous responses) that tracks the nesting depth of the JSON during deserialization. If the depth exceeds a predefined limit, throw a `JsonDataException`. This is a Moshi-specific mitigation because it involves creating a custom adapter.

*   **List of Threats Mitigated:**
    *   **Threat:** Denial of Service (through resource exhaustion with deeply nested JSON).
        *   **Severity:** High

*   **Impact:**
    *   **Denial of Service:** Risk significantly reduced. Depth limiting prevents attackers from crafting deeply nested JSON to cause stack overflow errors or excessive memory consumption.

*   **Currently Implemented:**
    *   No depth limiting is implemented.

*   **Missing Implementation:**
    *   Implementation of the depth-limiting `JsonAdapter.Factory`. This is a *high-priority* missing implementation if the application handles potentially complex JSON structures.

## Mitigation Strategy: [Safe Polymorphic Deserialization](./mitigation_strategies/safe_polymorphic_deserialization.md)

*   **Description:**
    1.  **Identify Polymorphic Types:** Identify any fields representing polymorphic types.
    2.  **Use `PolymorphicJsonAdapterFactory`:** Use Moshi's `PolymorphicJsonAdapterFactory` to explicitly define how to handle these types. Specify a "type label" field and map each label value to the corresponding class. This is *crucial* for secure polymorphic deserialization.
    3. **Avoid Polymorphism if Possible:** Consider redesign to avoid it.

*   **List of Threats Mitigated:**
    *   **Threat:** Arbitrary Code Execution (through type confusion in polymorphic scenarios).
        *   **Severity:** Critical
    *   **Threat:** Data Injection (injecting unexpected types).
        *   **Severity:** High

*   **Impact:**
    *   **Arbitrary Code Execution:** Risk significantly reduced.  `PolymorphicJsonAdapterFactory` enforces explicit type mapping.
    *   **Data Injection:** Risk significantly reduced.

*   **Currently Implemented:**
    *   The application does *not* currently use polymorphic types.

*   **Missing Implementation:**
    *   None, as polymorphism is not currently used.  However, if introduced, `PolymorphicJsonAdapterFactory` is *mandatory*.

## Mitigation Strategy: [Keep Moshi Updated](./mitigation_strategies/keep_moshi_updated.md)

* **Description:**
    1. Use dependency management tool.
    2. Regularly check and update Moshi to the latest stable version.

*   **List of Threats Mitigated:**
    *   **Threat:** Exploitation of known vulnerabilities in older Moshi versions.
        *   **Severity:** Varies

*   **Impact:**
    *   **Exploitation of Known Vulnerabilities:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Gradle is used.
    *   Moshi version is `1.13.0`.

*   **Missing Implementation:**
    *   Automated dependency checks are not configured.
    *   Formal update process is not documented.

