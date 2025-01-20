# Attack Surface Analysis for square/moshi

## Attack Surface: [Polymorphic Deserialization Vulnerabilities](./attack_surfaces/polymorphic_deserialization_vulnerabilities.md)

**Description:** When using Moshi's polymorphic type adapters, an attacker can manipulate the type identifier in the JSON payload to force deserialization into unintended classes.

**How Moshi Contributes:** Moshi provides the mechanism for polymorphic deserialization based on a type label. If not carefully configured and validated, this mechanism can be exploited.

**Example:** An application uses a polymorphic adapter for `Animal` with subtypes `Dog` and `Cat`. An attacker sends JSON with `{"type": "java.lang.Runtime", ...}` hoping to trigger code execution during deserialization if `java.lang.Runtime` is somehow accessible or if a custom adapter for it exists with dangerous side effects.

**Impact:**
* **Arbitrary Code Execution:** If a chosen class has exploitable side effects in its constructor or methods called during deserialization.
* **Denial of Service:** By forcing deserialization into resource-intensive classes.
* **Information Disclosure:** By manipulating the type to access or expose internal data.

**Risk Severity:** **Critical**

**Mitigation Strategies:**
* **Whitelist Allowed Types:** Explicitly define and strictly enforce the allowed subtypes for polymorphic deserialization. Do not rely on user-provided type information without validation.
* **Avoid Deserializing into Potentially Dangerous Classes:**  Be extremely cautious about deserializing into classes that could have unintended side effects or provide access to system resources.
* **Principle of Least Privilege:** Ensure the application runs with the minimum necessary permissions to limit the impact of potential code execution.

## Attack Surface: [Deserialization of Untrusted Data without Sufficient Validation](./attack_surfaces/deserialization_of_untrusted_data_without_sufficient_validation.md)

**Description:**  Moshi deserializes JSON data into Java/Kotlin objects. If the application doesn't perform adequate validation *after* deserialization, malicious or unexpected data can bypass initial checks.

**How Moshi Contributes:** Moshi facilitates the conversion of JSON to objects, but it doesn't inherently enforce application-specific validation rules.

**Example:** An application expects a positive integer for `age`. An attacker sends `{"age": -10}`. Moshi successfully deserializes this, but the application logic might not handle negative ages correctly, leading to errors or security vulnerabilities.

**Impact:**
* **Data Integrity Issues:** Corrupting application state with invalid data.
* **Logic Errors:** Causing unexpected behavior due to assumptions about data format.
* **Security Vulnerabilities in Downstream Components:** Passing unvalidated data to other parts of the application.

**Risk Severity:** **High**

**Mitigation Strategies:**
* **Implement Robust Input Validation:**  Thoroughly validate all deserialized data before using it in the application logic. Use libraries like Bean Validation (JSR 303/380) or implement custom validation logic.
* **Sanitize Input:**  Cleanse or transform input data to ensure it conforms to expected formats and constraints.
* **Consider Using Data Transfer Objects (DTOs):**  Deserialize into DTOs specifically designed for input validation before mapping to internal domain objects.

