# Mitigation Strategies Analysis for activerecord-hackery/ransack

## Mitigation Strategy: [Whitelist Allowed Search Attributes](./mitigation_strategies/whitelist_allowed_search_attributes.md)

*   **Mitigation Strategy:** Whitelist Allowed Search Attributes
*   **Description:**
    1.  **Identify Models Using Ransack:** Determine which ActiveRecord models are used with Ransack for searching and filtering.
    2.  **Define `ransackable_attributes` in Models:** For each identified model, open the model file (e.g., `app/models/user.rb`).
    3.  **Implement `ransackable_attributes` Method:**  Add or modify the `ransackable_attributes` class method within the model.
    4.  **List Allowed Attributes:** Inside the method, return an array of strings representing the *only* attributes that should be searchable via Ransack. Be restrictive and only include attributes necessary for search functionality.
    5.  **Review and Update Regularly:** Periodically review the list of whitelisted attributes and remove any that are no longer needed or pose a security risk.
*   **Threats Mitigated:**
    *   **Mass Assignment (High Severity):** Prevents attackers from manipulating search parameters to update model attributes they shouldn't be able to modify.
    *   **Information Disclosure (Medium Severity):** Limits exposure of sensitive or internal attributes through search functionality.
*   **Impact:**
    *   **Mass Assignment:** High Risk Reduction - Effectively eliminates the risk of mass assignment via Ransack parameters.
    *   **Information Disclosure:** Medium Risk Reduction - Significantly reduces the surface area for information disclosure by limiting searchable attributes.
*   **Currently Implemented:** Implemented in `app/models/user.rb`, `app/models/product.rb`, and `app/models/order.rb`.  `ransackable_attributes` is defined in each of these models, whitelisting specific attributes.
*   **Missing Implementation:**  Needs to be implemented in `app/models/comment.rb` and `app/models/blog_post.rb`. These models are currently using default Ransack behavior, allowing all attributes to be searchable.

## Mitigation Strategy: [Restrict Searchable Associations](./mitigation_strategies/restrict_searchable_associations.md)

*   **Mitigation Strategy:** Restrict Searchable Associations
*   **Description:**
    1.  **Review Model Associations:** Examine the associations defined in your ActiveRecord models that are used with Ransack.
    2.  **Define `ransackable_associations` in Models:** For models where you want to restrict associations, implement the `ransackable_associations` class method.
    3.  **Whitelist Allowed Associations:**  Return an array of strings containing the names of *only* the associations that should be searchable through Ransack. If no associations should be searchable, return an empty array.
    4.  **Default to No Associations:**  As a best practice, start with an empty array for `ransackable_associations` and explicitly add associations only when necessary.
*   **Threats Mitigated:**
    *   **Information Disclosure (Medium to High Severity):** Prevents unauthorized access to data through associated models that should not be exposed in search results.
    *   **Authorization Bypass (Medium Severity):**  In complex applications, improperly exposed associations could potentially bypass intended authorization checks.
*   **Impact:**
    *   **Information Disclosure:** Medium to High Risk Reduction - Significantly reduces the risk of exposing sensitive data through unintended association searches.
    *   **Authorization Bypass:** Medium Risk Reduction - Reduces the potential for bypassing authorization by limiting searchable association paths.
*   **Currently Implemented:** Implemented in `app/models/user.rb` and `app/models/product.rb`. `ransackable_associations` is set to an empty array in `User` and only explicitly allows `category` association in `Product`.
*   **Missing Implementation:**  `ransackable_associations` needs to be reviewed and implemented in `app/models/order.rb`, `app/models/comment.rb`, and `app/models/blog_post.rb`. Currently, associations might be searchable by default in these models.

