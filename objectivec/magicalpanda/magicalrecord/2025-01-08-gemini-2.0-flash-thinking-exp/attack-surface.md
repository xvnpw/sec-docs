# Attack Surface Analysis for magicalpanda/magicalrecord

## Attack Surface: [Unvalidated Data Input via Convenience Methods](./attack_surfaces/unvalidated_data_input_via_convenience_methods.md)

*   **Description:**  MagicalRecord simplifies data creation and modification, potentially leading developers to skip thorough input validation before persisting data.
    *   **How MagicalRecord Contributes:**  Methods like `MR_createEntityInContext:` and `MR_importValuesForKeysWithObject:` offer easy ways to set object attributes, but don't inherently enforce validation. This can mask the need for careful input sanitization.
    *   **Example:**  An attacker could send a crafted JSON payload to an API endpoint that uses `MR_importValuesForKeysWithObject:` to directly populate a Core Data entity without validating the data types or ranges, leading to unexpected data in the store.
    *   **Impact:** Data corruption, application crashes due to unexpected data types, potential for exploiting vulnerabilities in other parts of the application that rely on this data.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement robust input validation *before* using MagicalRecord's convenience methods to create or update entities.
        *   Define validation rules within your Core Data model or using custom validation logic.
        *   Avoid directly mapping external input to Core Data attributes without validation.
        *   Use MagicalRecord's blocks for more controlled object creation and modification where validation can be integrated.

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

*   **Description:**  MagicalRecord's methods for setting multiple attributes at once (e.g., using dictionaries) can expose the application to mass assignment issues if not carefully managed.
    *   **How MagicalRecord Contributes:**  `MR_importValuesForKeysWithObject:` and similar methods allow setting multiple attributes based on a dictionary. If the application doesn't restrict which keys are allowed, attackers could potentially modify attributes they shouldn't.
    *   **Example:** An API endpoint updating a user profile uses `MR_importValuesForKeysWithObject:` with a dictionary received from the client. An attacker could include a key like `isAdmin: true` in the dictionary, potentially granting themselves administrative privileges if this attribute isn't explicitly protected.
    *   **Impact:** Unauthorized modification of data, privilege escalation, security breaches.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use whitelisting: explicitly define which attributes can be set through these methods.
        *   Create dedicated data transfer objects (DTOs) or view models to control the data being passed to MagicalRecord.
        *   Avoid directly using request parameters or untrusted data sources as input for mass assignment methods.
        *   Implement authorization checks before allowing attribute modifications.

