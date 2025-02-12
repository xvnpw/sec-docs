# Mitigation Strategies Analysis for fasterxml/jackson-core

## Mitigation Strategy: [Avoid Default Typing](./mitigation_strategies/avoid_default_typing.md)

**Description:**
1.  **Identify Usage:** Search the codebase for any instances of `ObjectMapper.enableDefaultTyping()`. This method call is the primary indicator of Default Typing being enabled.
2.  **Refactor to Explicit Type Information:** Replace Default Typing with explicit type information using Jackson annotations. This means using `@JsonTypeInfo`, `@JsonSubTypes`, and `@JsonTypeName` on your classes and interfaces to define how type information is handled during serialization and deserialization.  Jackson uses these annotations to determine the correct class to instantiate.
3.  **Remove `enableDefaultTyping()`:** After refactoring, remove all calls to `ObjectMapper.enableDefaultTyping()`.
4.  **Test Thoroughly:**  Extensive testing is crucial after this refactoring to ensure correct behavior.

**List of Threats Mitigated:**
*   **Remote Code Execution (RCE) (Critical):**  Eliminates the primary mechanism for arbitrary class instantiation via malicious JSON.
*   **Denial of Service (DoS) (High):**  Reduces the attack surface related to type handling.

**Impact:**
*   **RCE:** Risk is *drastically reduced* (almost eliminated with correct implementation).
*   **DoS:** Risk is reduced.

**Currently Implemented:**
*   **Partially Implemented:** Annotations are used in some areas (`com.example.models`), but `enableDefaultTyping()` is still present in `com.example.legacy.LegacyDataProcessor`.

**Missing Implementation:**
*   `com.example.legacy.LegacyDataProcessor`:  Requires refactoring to remove `enableDefaultTyping()` and use explicit type annotations.

## Mitigation Strategy: [Use a Safe Type Validator (if Default Typing is unavoidable)](./mitigation_strategies/use_a_safe_type_validator__if_default_typing_is_unavoidable_.md)

**Description:** (Only if removing Default Typing is impossible)
1.  **Identify `enableDefaultTyping()` Usage:** Locate all instances of `ObjectMapper.enableDefaultTyping()`.
2.  **Create a `PolymorphicTypeValidator`:**
    *   Create a class extending `PolymorphicTypeValidator.Base` (or implementing `PolymorphicTypeValidator`).
    *   Override `validateSubClassName()` (and potentially others).
    *   Implement a *whitelist* of allowed classes within `validateSubClassName()`.  *Never* use a blacklist.
3.  **Configure the `ObjectMapper`:**
    *   Instantiate your custom `PolymorphicTypeValidator`.
    *   Use `JsonMapper.builder().activateDefaultTyping(ptv, ...)` to configure the `ObjectMapper` with your validator.
4.  **Maintain the Whitelist:**  This is *absolutely critical*.  The whitelist *must* be kept up-to-date.
5. **Alternatively, use `BasicPolymorphicTypeValidator`:** For Jackson 2.10+, use the built-in `BasicPolymorphicTypeValidator` for easier whitelist configuration.

**List of Threats Mitigated:**
*   **Remote Code Execution (RCE) (Critical):**  Restricts class instantiation to the whitelisted classes.
*   **Denial of Service (DoS) (High):**  Indirectly mitigated.

**Impact:**
*   **RCE:** Risk is *significantly reduced*, dependent on whitelist accuracy.
*   **DoS:** Risk is reduced.

**Currently Implemented:**
*   **Not Implemented:** No custom `PolymorphicTypeValidator` is present.

**Missing Implementation:**
*   `com.example.legacy.LegacyDataProcessor`:  If Default Typing cannot be removed, a `PolymorphicTypeValidator` *must* be implemented.

## Mitigation Strategy: [Limit Deserialization Depth and Data Size via `StreamReadConstraints`](./mitigation_strategies/limit_deserialization_depth_and_data_size_via__streamreadconstraints_.md)

**Description:**
1.  **Determine Limits:** Analyze your application to determine reasonable limits for JSON structure complexity.
2.  **Implement `StreamReadConstraints` (Jackson 2.13+):**
    *   Create a `StreamReadConstraints` instance using its builder.
    *   Set limits: `maxNestingDepth()`, `maxStringLength()`, `maxNumberLength()`, `maxNameLength()`, `setMaxArrayElements()`, `setMaxObjectEntries()`.
    *   Create a `JsonFactory` using its builder and set the `StreamReadConstraints`.
    *   Create an `ObjectMapper` using the configured `JsonFactory`.
3.  **Older Jackson Versions (Pre-2.13):** This strategy is *not directly available*.  You would need to resort to manual input size checks *before* passing data to Jackson, which is outside the scope of "directly involving jackson-core".  The `JsonParser.Feature.STRICT_DUPLICATE_DETECTION` feature is available, but it only addresses duplicate keys, not size/depth limits.

**List of Threats Mitigated:**
*   **Denial of Service (DoS) (High):**  Prevents resource exhaustion from overly complex JSON.
*   **Algorithmic Complexity Attacks (High):**  A specific type of DoS.

**Impact:**
*   **DoS:** Risk is *significantly reduced*.
*   **Algorithmic Complexity:** Risk is *significantly reduced*.

**Currently Implemented:**
*   **Partially Implemented:** `StreamReadConstraints` are used in `com.example.api.ApiController`, but not comprehensively (only string length).

**Missing Implementation:**
*   `com.example.services.DataImportService`:  Needs `StreamReadConstraints` to handle potentially large JSON files.
*   `com.example.legacy.LegacyDataProcessor`:  Also needs limits (ideally `StreamReadConstraints` if Jackson version allows).

## Mitigation Strategy: [Keep Jackson Up-to-Date](./mitigation_strategies/keep_jackson_up-to-date.md)

**Description:**
1.  **Check Current Version:**  Find the `jackson-core` (and `jackson-databind`) version in your dependency management file.
2.  **Identify Latest Stable Version:** Check the Jackson project website for the latest release.
3.  **Update Dependencies:**  Modify your dependency management file to use the latest version.
4.  **Test Thoroughly:**  Run your test suite after updating.

**List of Threats Mitigated:**
*   **All Known Vulnerabilities (Variable Severity):**  Addresses known security issues in Jackson itself.

**Impact:**
*   **All Known Vulnerabilities:** Risk is *significantly reduced*.

**Currently Implemented:**
*   **Partially Implemented:**  The project uses a recent, but not the absolute latest, version.

**Missing Implementation:**
*   **Project-Wide:**  Implement a more automated update process.

## Mitigation Strategy: [Use `@JsonTypeInfo` Correctly](./mitigation_strategies/use__@jsontypeinfo__correctly.md)

**Description:**
1.  **Review Existing Usage:** Examine all uses of `@JsonTypeInfo`.
2.  **Prefer `Id.NAME`:** Use `use = JsonTypeInfo.Id.NAME` whenever possible. This uses logical type names, which are safer than class names.
3.  **Use `As.PROPERTY`:** Generally, prefer `include = JsonTypeInfo.As.PROPERTY`.
4.  **Meaningful Property Name:** Use a clear name for the `property` attribute (e.g., `@JsonTypeInfo(..., property = "classType")`).
5. **Consider Custom Resolvers:** If needed use custom `JsonTypeResolver` and `JsonTypeIdResolver`.

**List of Threats Mitigated:**
*   **Remote Code Execution (RCE) (Critical):** Reduces the risk of attackers controlling type information.
*   **Data Integrity (Medium):** Ensures consistent type handling.

**Impact:**
*   **RCE:** Risk is *reduced*.
*   **Data Integrity:** Risk is *reduced*.

**Currently Implemented:**
*   **Partially Implemented:** `@JsonTypeInfo` is used, but not always with the safest settings (some use `Id.CLASS`).

**Missing Implementation:**
*   `com.example.models`: Review and update `@JsonTypeInfo` usage to prefer `Id.NAME` and `As.PROPERTY`.

## Mitigation Strategy: [Disable Problematic `DeserializationFeatures`](./mitigation_strategies/disable_problematic__deserializationfeatures_.md)

**Description:**
1.  **Review `ObjectMapper` Configuration:** Examine all `ObjectMapper` configurations.
2.  **Enable `FAIL_ON_UNKNOWN_PROPERTIES`:** Add `.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)`.
3.  **Enable `FAIL_ON_INVALID_SUBTYPE`:** Add `.configure(DeserializationFeature.FAIL_ON_INVALID_SUBTYPE, true)`.
4.  **Review Other Features:** Carefully consider other `MapperFeature` and `DeserializationFeature` options.

**List of Threats Mitigated:**
*   **Data Injection (Medium):** Prevents injecting unexpected properties.
*   **Unexpected Behavior (Low):** Improves predictability.

**Impact:**
*   **Data Injection:** Risk is *reduced*.
*   **Unexpected Behavior:** Risk is *reduced*.

**Currently Implemented:**
*   **Partially Implemented:** `FAIL_ON_UNKNOWN_PROPERTIES` is enabled in some configurations, but not all.

**Missing Implementation:**
*   **Project-Wide:** Ensure consistent use of `FAIL_ON_UNKNOWN_PROPERTIES` and `FAIL_ON_INVALID_SUBTYPE`.

