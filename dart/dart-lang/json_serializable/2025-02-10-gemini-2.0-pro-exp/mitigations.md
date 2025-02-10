# Mitigation Strategies Analysis for dart-lang/json_serializable

## Mitigation Strategy: [Enable `checked: true` in `build.yaml` or `pubspec.yaml`](./mitigation_strategies/enable__checked_true__in__build_yaml__or__pubspec_yaml_.md)

**Description:**
1.  Locate the `build.yaml` file (or `pubspec.yaml`).
2.  Add or modify the `targets` section to include the `json_serializable` builder.
3.  Within the `json_serializable` builder's options, set `checked: true`.
4.  Regenerate the serialization code: `flutter pub run build_runner build`.

**Threats Mitigated:**
*   **Overly Permissive Deserialization (Type Mismatches / Unexpected Types):** (Severity: High) - `json_serializable` will throw `CheckedFromJsonException` if types don't match.
*   **Data Validation Bypass (Indirectly):** (Severity: Medium) - Enforces type safety at the deserialization level.

**Impact:**
*   **Overly Permissive Deserialization:** Significantly reduces risk; this is the primary defense.
*   **Data Validation Bypass:** Moderate risk reduction.

**Currently Implemented:** (Example - Replace with your project's status)
*   Yes, in `build.yaml`.

**Missing Implementation:** (Example - Replace with your project's status)
*   None.

## Mitigation Strategy: [Implement Custom `fromJson` Factories with Robust Validation](./mitigation_strategies/implement_custom__fromjson__factories_with_robust_validation.md)

**Description:**
1.  For classes using `@JsonSerializable`, create a custom `fromJson` factory.
2.  Call the generated `_$YourClassNameFromJson(json)` method.
3.  *After* the generated code, add custom validation:
    *   Range checks.
    *   String length checks.
    *   Regular expressions.
    *   Allowed value checks.
    *   Cross-field validation.
4.  Throw an exception if validation fails.
5.  Return the object if validation passes.

**Threats Mitigated:**
*   **Overly Permissive Deserialization (Beyond Basic Types):** (Severity: High) - Allows domain-specific validation.
*   **Data Validation Bypass:** (Severity: High) - Enforces application-specific rules.
*   **Injection Attacks (Indirectly):** (Severity: Medium) - Strengthens input validation.

**Impact:**
*   **Overly Permissive Deserialization:** High risk reduction.
*   **Data Validation Bypass:** High risk reduction.
*   **Injection Attacks:** Moderate risk reduction.

**Currently Implemented:** (Example - Replace with your project's status)
*   Partially. Implemented for `UserData` and `Product`.

**Missing Implementation:** (Example - Replace with your project's status)
*   Missing for `Comment` and `Settings`.

## Mitigation Strategy: [Avoid User-Controlled `@JsonKey(name: ...)`](./mitigation_strategies/avoid_user-controlled__@jsonkey_name______.md)

**Description:**
1.  Review all `@JsonKey` annotations.
2.  Ensure `name` is *always* a hardcoded string literal.
3.  *Never* use user input for the `name` parameter.
4.  For dynamic key mapping, use a static mapping *within* a custom `fromJson` factory, not in `@JsonKey`.

**Threats Mitigated:**
*   **Injection via `@JsonKey(name: ...)`:** (Severity: High) - Prevents manipulation of JSON key mapping.

**Impact:**
*   **Injection via `@JsonKey(name: ...)`:** Eliminates the risk if followed strictly.

**Currently Implemented:** (Example - Replace with your project's status)
*   Yes.

**Missing Implementation:** (Example - Replace with your project's status)
*   None.

## Mitigation Strategy: [Use `@JsonKey` with `required: true` and `disallowNullValue: true`](./mitigation_strategies/use__@jsonkey__with__required_true__and__disallownullvalue_true_.md)

**Description:**
1.  Identify mandatory, non-nullable fields.
2.  Annotate with `@JsonKey(required: true, disallowNullValue: true)`.
3.  Regenerate code: `flutter pub run build_runner build`.

**Threats Mitigated:**
*   **Missing Required Fields:** (Severity: Medium)
*   **Unexpected Null Values:** (Severity: Medium)

**Impact:**
*   **Missing Required Fields:** High reduction for annotated fields.
*   **Unexpected Null Values:** High reduction for annotated fields.

**Currently Implemented:** (Example - Replace with your project's status)
*   Partially. Used in `UserData` and `Product`.

**Missing Implementation:** (Example - Replace with your project's status)
*   Not consistently applied across all models.

## Mitigation Strategy: [Avoid `dynamic` where possible within `@JsonSerializable` classes.](./mitigation_strategies/avoid__dynamic__where_possible_within__@jsonserializable__classes.md)

**Description:**
1.  Review data models and identify `dynamic` fields.
2.  Replace `dynamic` with specific types if known.
3.  Consider sealed classes or union types for multiple known types.
4.  Use `dynamic` only when the type is truly unknown.

**Threats Mitigated:**
*   **Type Confusion:** (Severity: Medium)
*   **Data Validation Bypass:** (Severity: Medium)

**Impact:**
*   **Type Confusion:** Moderate to high reduction.
*   **Data Validation Bypass:** Moderate reduction.

**Currently Implemented:** (Example - Replace with your project's status)
*   Partially. Some `dynamic` types replaced.

**Missing Implementation:** (Example - Replace with your project's status)
*   Needs comprehensive review.

