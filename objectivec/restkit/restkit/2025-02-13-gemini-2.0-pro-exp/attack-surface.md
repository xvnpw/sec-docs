# Attack Surface Analysis for restkit/restkit

## Attack Surface: [Overly Permissive Object Mapping](./attack_surfaces/overly_permissive_object_mapping.md)

*   **Description:**  The application maps more data from JSON responses to Objective-C objects than is strictly necessary, potentially exposing internal data structures or enabling unintended manipulation.
*   **How RestKit Contributes:** RestKit's core functionality is object mapping. Its flexibility, if misused, allows for overly broad mappings, *directly* creating this vulnerability.
*   **Example:**  An API returns a user object with fields like `id`, `username`, `email`, and `internal_admin_flag`. The application only needs `id` and `username`, but the RestKit mapping includes *all* fields. An attacker could send a modified response with `internal_admin_flag` set to `true`, potentially granting them elevated privileges.
*   **Impact:**  Data leakage, privilege escalation, application logic bypass.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Explicit Mapping:** Define `RKAttributeMapping` and `RKRelationshipMapping` objects that *only* include the required fields. Avoid wildcard mappings.
    *   **Data Validation (Post-Mapping):** Implement validation checks *after* the RestKit mapping process.
    *   **Input Sanitization:** Sanitize any user-provided data that influences API requests or mapping.

## Attack Surface: [Deserialization of Untrusted Data (NSCoding)](./attack_surfaces/deserialization_of_untrusted_data__nscoding_.md)

*   **Description:**  RestKit is used to deserialize data from untrusted sources using `NSCoding`, potentially leading to object injection vulnerabilities.
*   **How RestKit Contributes:**  RestKit *can be configured* to use `NSCoding` for object serialization/deserialization. This *direct configuration choice* within RestKit creates the vulnerability if misused.
*   **Example:**  An application receives data from a third-party service and uses RestKit with `NSCoding` to deserialize it directly into objects. The third-party service is compromised, and an attacker injects a malicious payload.
*   **Impact:**  Remote code execution (RCE), data corruption, application compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Untrusted Deserialization:** *Do not* use RestKit with `NSCoding` to deserialize data from untrusted sources. This is the primary mitigation.
    *   **Secure `initWithCoder:`:** If `NSCoding` *must* be used, ensure *all* involved classes have secure `initWithCoder:` implementations that thoroughly validate input.
    *   **Prefer JSON:** Use JSON (with strict schema validation) instead of `NSCoding` for external data.

## Attack Surface: [Insecure Core Data Integration (If Used)](./attack_surfaces/insecure_core_data_integration__if_used_.md)

*   **Description:**  Vulnerabilities in the integration between RestKit and Core Data, potentially leading to data breaches or manipulation.
*   **How RestKit Contributes:** RestKit *provides the functionality* to map API responses directly to Core Data entities. The *insecure use of this RestKit feature* is the direct cause.
*   **Example:** User-supplied data is used to construct a Core Data predicate without sanitization. An attacker injects malicious code into the predicate.
*   **Impact:** Data leakage, data corruption, unauthorized data modification, potential code execution.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Parameterized Predicates:** Always use parameterized predicates (e.g., `NSPredicate predicateWithFormat:`). Never construct predicates directly from user input.
    *   **Input Sanitization:** Sanitize and validate all user-supplied data before using it in Core Data operations.
    *   **Core Data Security:** Follow all recommended Core Data security best practices.
    *   **Secure Mapping:** Ensure the RestKit-to-Core Data mapping is secure.

## Attack Surface: [Outdated Dependencies (RestKit Itself)](./attack_surfaces/outdated_dependencies__restkit_itself_.md)

* **Description:** RestKit *itself* has known vulnerabilities due to being outdated.
* **How RestKit Contributes:** RestKit is the direct source of the vulnerability in this case.
* **Example:** An older version of RestKit has a known vulnerability that allows for remote code execution. An attacker exploits this vulnerability directly.
* **Impact:** Varies depending on the vulnerability, potentially ranging from denial of service to remote code execution.
* **Risk Severity:** Varies (High to Critical), depending on the specific vulnerability.
* **Mitigation Strategies:**
    * **Regular Updates:** Keep RestKit updated to the latest stable version.
    * **Vulnerability Monitoring:** Monitor for security advisories related to RestKit.

