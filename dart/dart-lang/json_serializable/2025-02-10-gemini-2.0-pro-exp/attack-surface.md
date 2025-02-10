# Attack Surface Analysis for dart-lang/json_serializable

## Attack Surface: [Type Mismatch Exploitation](./attack_surfaces/type_mismatch_exploitation.md)

*   **1. Type Mismatch Exploitation**

    *   **Description:** Attackers craft malicious JSON payloads with incorrect data types (e.g., string instead of integer, array instead of object) to cause unexpected behavior during deserialization.
    *   **`json_serializable` Contribution:** `json_serializable` generates code for type conversion. Without proper checks (specifically, `checked: true`), the generated code might not handle unexpected types gracefully, leading to exceptions, incorrect type coercion, or other unexpected behavior.  This is the *core* vulnerability of using `json_serializable` insecurely.
    *   **Example:**
        ```dart
        // Dart class
        class User {
          final int id;
          final String name;

          User({required this.id, required this.name});

          factory User.fromJson(Map<String, dynamic> json) => _$UserFromJson(json); // Without checked: true
        }

        // Malicious JSON
        // { "id": "not_an_integer", "name": "Attacker" }
        ```
    *   **Impact:**
        *   Denial of Service (DoS) due to application crashes (if exceptions are unhandled).
        *   Logic errors leading to security bypasses (if incorrect types are silently used).
        *   Potential data corruption (less likely, but possible in some scenarios).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **`checked: true` (Essential):**  *Always* use the `checked: true` option in the `@JsonSerializable` annotation. This enables runtime type checks and throws `CheckedFromJsonException` on type mismatches. This is the *primary* defense.
        *   **Robust Error Handling (Essential):** Implement comprehensive error handling (try-catch blocks) around `fromJson` calls to catch `CheckedFromJsonException` and other potential exceptions.  *Never* silently ignore these exceptions. Log the errors and respond appropriately (e.g., return an error to the user, reject the request).
        *   **Input Validation (Important):** Perform additional input validation *after* deserialization to enforce business logic constraints (e.g., range checks, string length limits, allowed values). `json_serializable` only checks *types*, not business rules.
        *   **`@JsonKey` Options (Helpful):** Use `@JsonKey` options like `required`, `defaultValue`, and `disallowNullValue` to enforce stricter constraints on the expected JSON structure.

## Attack Surface: [Over-Posting / Mass Assignment](./attack_surfaces/over-posting__mass_assignment.md)

*   **2. Over-Posting / Mass Assignment**

    *   **Description:** Attackers add extra fields to the JSON payload that correspond to properties they shouldn't be able to modify, leading to unauthorized updates.
    *   **`json_serializable` Contribution:**  `json_serializable`'s default behavior is to deserialize all fields present in the JSON that match properties in the Dart class.  If you don't explicitly restrict this, it *directly* enables over-posting.
    *   **Example:**
        ```dart
        // Dart class
        class UserProfile {
          final String username;
          final String email;
          bool isAdmin; // Should not be modifiable by users

          UserProfile({required this.username, required this.email, this.isAdmin = false});

          factory UserProfile.fromJson(Map<String, dynamic> json) => _$UserProfileFromJson(json); // No ignoreUnannotated
        }

        // Malicious JSON (sent by a regular user)
        // { "username": "user123", "email": "user@example.com", "isAdmin": true }
        ```
    *   **Impact:** Unauthorized modification of object properties, potentially bypassing security controls and escalating privileges (e.g., making a regular user an administrator).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **`ignoreUnannotated: true` (Essential):** Use `@JsonSerializable(ignoreUnannotated: true)` to *only* serialize/deserialize fields explicitly annotated with `@JsonKey`. This is the *primary* and most effective defense against over-posting with `json_serializable`.
        *   **Data Transfer Objects (DTOs) (Recommended):** Use separate DTO classes specifically for data transfer, rather than directly using your domain model classes. This allows you to precisely control which fields are exposed for serialization/deserialization, providing a clear separation of concerns.
        *   **Explicit Field Mapping (Alternative):** Instead of directly applying the deserialized object to your domain model, manually map the fields you *want* to update. This gives you complete control over which properties are modified, but it's more verbose than using DTOs.

