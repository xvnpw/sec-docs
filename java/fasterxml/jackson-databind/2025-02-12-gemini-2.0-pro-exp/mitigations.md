# Mitigation Strategies Analysis for fasterxml/jackson-databind

## Mitigation Strategy: [1. Keep `jackson-databind` Updated](./mitigation_strategies/1__keep__jackson-databind__updated.md)

*   *Description:*
    1.  Identify the current `jackson-databind` version (check `pom.xml`, `build.gradle`, etc.).
    2.  Find the latest *patch* release for your *minor* version on GitHub or Maven Central.
    3.  Update the dependency in your project's build file.
    4.  Run a full build and test suite.
    5.  Configure a dependency management tool (Dependabot, Snyk, etc.) for automatic updates (at least weekly).

*   *Threats Mitigated:*
    *   **Remote Code Execution (RCE) (Critical):** Updates often patch RCE vulnerabilities.
    *   **Denial of Service (DoS) (High):** Some vulnerabilities can cause crashes or unresponsiveness.
    *   **Information Disclosure (Medium):** Less common, but some vulnerabilities might leak information.

*   *Impact:*
    *   **RCE:** Significantly reduces risk. Risk reduction: High.
    *   **DoS:** Reduces risk. Risk reduction: Medium.
    *   **Information Disclosure:** Reduces risk. Risk reduction: Low.

*   *Currently Implemented:*
    *   Check the project's build file for the current version.
    *   Check for a dependency management tool configuration.
    *   Example: `pom.xml` shows version 2.12.3. Dependabot is configured, but checks monthly.

*   *Missing Implementation:*
    *   Ensure *all* instances of `jackson-databind` are updated (including subprojects).
    *   Increase update frequency (e.g., to weekly).
    *   Example: A microservice uses an older version. Dependabot checks are missing for that microservice.

## Mitigation Strategy: [2. Minimize Polymorphic Deserialization](./mitigation_strategies/2__minimize_polymorphic_deserialization.md)

*   *Description:*
    1.  Review code for `@JsonTypeInfo`, `@JsonSubTypes`, and related annotations.
    2.  Analyze if polymorphic deserialization is *truly* necessary. Could concrete types or composition be used?
    3.  If possible, refactor to remove the annotations and use concrete types.
    4.  If unavoidable, document *why* and proceed to other mitigations (especially PTV).

*   *Threats Mitigated:*
    *   **RCE (Critical):** Addresses the root cause of most `jackson-databind` RCE vulnerabilities.
    *   **DoS (High):** Reduces the attack surface for DoS.

*   *Impact:*
    *   **RCE:** The most significant impact. Risk reduction: Very High.
    *   **DoS:** Moderate impact. Risk reduction: Medium.

*   *Currently Implemented:*
    *   Check for the presence of the relevant annotations.
    *   Review design documents for justification of polymorphism.
    *   Example: Several data models use `@JsonTypeInfo` without clear justification.

*   *Missing Implementation:*
    *   Identify classes/modules where refactoring to remove polymorphism is feasible.
    *   Example: The `Event` class hierarchy uses `@JsonTypeInfo` but could use a single `Event` class with an `eventType` field.

## Mitigation Strategy: [3. Use a Safe Default Typing Strategy](./mitigation_strategies/3__use_a_safe_default_typing_strategy.md)

*   *Description:*
    1.  Locate where the `ObjectMapper` is configured.
    2.  Check if `activateDefaultTyping` (or `enableDefaultTyping`) is used.
    3.  Examine the `DefaultTyping` enum value. If it's `OBJECT_AND_NON_CONCRETE` or `NON_FINAL`, it's unsafe.
    4.  Change it to `NON_CONCRETE_AND_ARRAYS` or, preferably, use a custom `TypeResolverBuilder` with a `PolymorphicTypeValidator` (see next point).
    5.  Thoroughly test the application.

*   *Threats Mitigated:*
    *   **RCE (Critical):** Limits types that can be automatically deserialized.
    *   **DoS (High):** Indirectly helps by reducing complexity.

*   *Impact:*
    *   **RCE:** Moderate impact on its own, but *essential* with a `PolymorphicTypeValidator`. Risk reduction: Medium (High with PTV).
    *   **DoS:** Low impact. Risk reduction: Low.

*   *Currently Implemented:*
    *   Check `ObjectMapper` configuration for `activateDefaultTyping` or `enableDefaultTyping`.
    *   Example: `ObjectMapper` is configured with `DefaultTyping.NON_FINAL`.

*   *Missing Implementation:*
    *   Change the `DefaultTyping` setting.
    *   Implement a `PolymorphicTypeValidator` (crucial).
    *   Example: Change `DefaultTyping` and implement a PTV.

## Mitigation Strategy: [4. Implement a `PolymorphicTypeValidator` (PTV)](./mitigation_strategies/4__implement_a__polymorphictypevalidator___ptv_.md)

*   *Description:*
    1.  Create a `PolymorphicTypeValidator` instance (`BasicPolymorphicTypeValidator` is a good start).
    2.  Configure it to *whitelist* allowed base types and subtypes. Be restrictive. Use methods like:
        *   `allowIfSubType(String prefix)`
        *   `allowIfSubType(Class<?> clazz)`
        *   `allowIfBaseType(Class<?> clazz)`
        *   `allowIfSubType(Predicate<Class<?>> predicate)`
    3.  Pass the validator to `ObjectMapper`'s `activateDefaultTyping`.
    4.  Thoroughly test, adjusting the whitelist as needed.

*   *Threats Mitigated:*
    *   **RCE (Critical):** The *most effective* mitigation when polymorphism is required. Prevents deserialization of unauthorized classes.
    *   **DoS (High):** Indirectly helps by limiting allowed types.

*   *Impact:*
    *   **RCE:** Very high impact. Risk reduction: Very High.
    *   **DoS:** Low impact. Risk reduction: Low.

*   *Currently Implemented:*
    *   Check `ObjectMapper` configuration for any `PolymorphicTypeValidator`.
    *   Example: No `PolymorphicTypeValidator` is configured.

*   *Missing Implementation:*
    *   *Critical* missing piece. A PTV *must* be implemented if polymorphism is used.
    *   Create a `BasicPolymorphicTypeValidator` with a strict whitelist.
    *   Example: Create a PTV to allow only specific subtypes within `com.example.app.models`.

## Mitigation Strategy: [5. Disable Problematic Features](./mitigation_strategies/5__disable_problematic_features.md)

*   *Description:*
    1.  Review the `ObjectMapper` configuration.
    2.  Disable unnecessary features that could increase the attack surface. Consider:
        *   `DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES`
        *   `MapperFeature.USE_GETTERS_AS_SETTERS`
        *   `MapperFeature.AUTO_DETECT_CREATORS`, `AUTO_DETECT_FIELDS`, `AUTO_DETECT_GETTERS`, `AUTO_DETECT_IS_GETTERS`, `AUTO_DETECT_SETTERS`
    3.  Thoroughly test after disabling features.

*   *Threats Mitigated:*
    *   **RCE (Critical):** Reduces the attack surface.
    *   **DoS (High):** Can help prevent some DoS attacks.
    *   **Information Disclosure (Medium):** Can reduce information leaked through errors.

*   *Impact:*
    *   **RCE:** Low to moderate impact. Risk reduction: Low-Medium.
    *   **DoS:** Low impact. Risk reduction: Low.
    *   **Information Disclosure:** Low impact. Risk reduction: Low.

*   *Currently Implemented:*
    *   Check `ObjectMapper` configuration for disabled features.
    *   Example: No features are explicitly disabled.

*   *Missing Implementation:*
    *   Disable the listed features (or a subset) if not essential.
    *   Example: Disable `MapperFeature.AUTO_DETECT_CREATORS`, `AUTO_DETECT_FIELDS`, etc.

