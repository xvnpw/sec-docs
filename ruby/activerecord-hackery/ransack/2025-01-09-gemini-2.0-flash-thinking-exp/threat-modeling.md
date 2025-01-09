# Threat Model Analysis for activerecord-hackery/ransack

## Threat: [Sensitive Data Exposure through Unrestricted Attribute Access](./threats/sensitive_data_exposure_through_unrestricted_attribute_access.md)

- **Threat:** Sensitive Data Exposure through Unrestricted Attribute Access
    - **Description:** An attacker could craft Ransack queries targeting model attributes containing sensitive information that are not intended for public access or the current user's authorization level. They could use various Ransack predicates to filter and retrieve this data directly through Ransack's search interface.
    - **Impact:** Unauthorized access to confidential information, potentially leading to privacy violations, compliance breaches, or reputational damage.
    - **Affected Ransack Component:** `Search` object, attribute access logic.
    - **Risk Severity:** High
    - **Mitigation Strategies:**
        - Explicitly whitelist allowed searchable attributes using `ransackable_attributes` in the model.
        - Implement authorization checks within the application logic *before* executing the Ransack query to verify if the current user is allowed to access the data associated with the targeted attributes.
        - Avoid exposing highly sensitive attributes directly to Ransack. Consider creating sanitized or aggregated views for searching if sensitive data needs to be searchable.

## Threat: [Exploiting Custom Predicates with Security Flaws](./threats/exploiting_custom_predicates_with_security_flaws.md)

- **Threat:** Exploiting Custom Predicates with Security Flaws
    - **Description:** If developers implement custom Ransack predicates, vulnerabilities in the implementation of these predicates could be exploited by attackers directly through Ransack queries. This could involve SQL injection if the custom predicate doesn't properly sanitize input passed from the Ransack query, or other logic flaws leading to unintended and potentially harmful consequences executed within the context of the Ransack query.
    - **Impact:** Potentially severe, ranging from data breaches (SQL injection leading to unauthorized data access or modification) to arbitrary code execution on the database server, depending on the nature of the vulnerability in the custom predicate.
    - **Affected Ransack Component:** Custom predicate implementations.
    - **Risk Severity:** Critical
    - **Mitigation Strategies:**
        - Treat custom Ransack predicates as a high-risk area.
        - Thoroughly review and test all custom Ransack predicates for security vulnerabilities, with a primary focus on preventing SQL injection.
        - Ensure proper input sanitization and validation of all parameters passed to custom predicate implementations. Utilize parameterized queries or ORM features to prevent SQL injection.
        - Follow secure coding practices meticulously when developing custom predicates. If possible, avoid constructing raw SQL within custom predicates.
        - Consider having custom predicate implementations reviewed by a security expert.

