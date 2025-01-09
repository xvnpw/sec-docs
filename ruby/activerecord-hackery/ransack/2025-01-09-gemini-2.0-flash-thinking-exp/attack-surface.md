# Attack Surface Analysis for activerecord-hackery/ransack

## Attack Surface: [Mass Assignment Vulnerabilities via Search Parameters](./attack_surfaces/mass_assignment_vulnerabilities_via_search_parameters.md)

* **Description:** Attackers can manipulate URL parameters used by Ransack to modify model attributes beyond the intended search scope. This occurs when the application doesn't explicitly restrict which attributes are allowed for searching, potentially allowing modification of sensitive data.
    * **How Ransack Contributes:** Ransack's flexibility in accepting parameters through the `q` object can be exploited if attribute whitelisting is not implemented. It directly binds user-provided parameters to model attributes for querying.
    * **Example:**  `?q[is_admin_eq]=true`  If the `is_admin` attribute is not properly protected and is accessible through Ransack, an attacker could attempt to elevate their privileges.
    * **Impact:** Unauthorized data modification, privilege escalation, data corruption.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Explicitly define allowed search attributes using `search_attributes` in your model.** This is the primary defense.
        * **Avoid directly mapping all model attributes to searchable fields.** Carefully consider which attributes are necessary and safe to expose for searching.

## Attack Surface: [Information Disclosure through Unintended Attribute Exposure](./attack_surfaces/information_disclosure_through_unintended_attribute_exposure.md)

* **Description:** Attackers can use Ransack to query and retrieve data from model attributes that were not intended to be publicly accessible or searchable.
    * **How Ransack Contributes:** By default, Ransack can expose all model attributes for searching unless explicitly restricted.
    * **Example:** `?q[email_cont]=attacker.com` could reveal all user email addresses if the `email` attribute is searchable.
    * **Impact:** Exposure of sensitive personal information, business data, or internal system details.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Strictly limit searchable attributes using `search_attributes`.** Only include attributes necessary for the intended search functionality.
        * **Regularly review the list of searchable attributes.** Ensure no sensitive attributes are inadvertently exposed.

## Attack Surface: [Abuse of Custom Predicates and Scopes](./attack_surfaces/abuse_of_custom_predicates_and_scopes.md)

* **Description:** If developers create custom predicates or scopes for Ransack, vulnerabilities in this custom code can be exploited by attackers.
    * **How Ransack Contributes:** Ransack provides a mechanism for extending its functionality, and insecure custom implementations can introduce new attack vectors.
    * **Example:** A custom predicate that directly interpolates user input into a raw SQL query could be vulnerable to SQL injection (though Ransack aims to prevent this in standard usage).
    * **Impact:** Depends on the vulnerability in the custom code, potentially leading to data breaches, code execution, or other severe consequences.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Thoroughly review and test all custom predicates and scopes for security vulnerabilities.** Follow secure coding practices.
        * **Avoid directly embedding user input into raw SQL queries within custom predicates.** Use parameterized queries or ORM methods.
        * **Enforce strict input validation and sanitization within custom logic.**

