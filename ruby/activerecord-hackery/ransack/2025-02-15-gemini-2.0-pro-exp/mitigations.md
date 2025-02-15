# Mitigation Strategies Analysis for activerecord-hackery/ransack

## Mitigation Strategy: [Whitelist Allowed Attributes](./mitigation_strategies/whitelist_allowed_attributes.md)

**Description:**
1.  **Implement `ransackable_attributes`:** In your ActiveRecord model (e.g., `app/models/user.rb`), define a class method called `ransackable_attributes`.
2.  **Return an Array of Strings:** This method *must* return an array of strings, where each string is the name of an allowed attribute.  For example: `['username', 'email', 'created_at']`.  *Never* return `nil` or an empty array (which would allow all attributes).
3.  **Use `auth_object` (Optional but Recommended):**  The `ransackable_attributes` method receives an optional `auth_object` parameter. Use this to conditionally allow different attributes based on user roles or permissions.
    ```ruby
    def self.ransackable_attributes(auth_object = nil)
      if auth_object.is_a?(Admin)
        %w[id username email created_at] # Admins can search by ID
      else
        %w[username email created_at] # Regular users cannot
      end
    end
    ```
4.  **Test:**  After implementing, test to ensure only whitelisted attributes are searchable.

**List of Threats Mitigated:**
*   **Information Disclosure (High Severity):** Prevents querying of sensitive data.
*   **Denial of Service (DoS) (Medium Severity):** Reduces the chance of complex queries on non-indexed columns.
*   **SQL Injection (Low Severity - with ActiveRecord):** Limits the attack surface.

**Impact:**
*   **Information Disclosure:**  Primary defense. Significantly reduces risk.
*   **Denial of Service:**  Reduces risk.
*   **SQL Injection:**  Small additional defense.

**Currently Implemented:**
*   Partially implemented in `app/models/product.rb`, but not in `app/models/user.rb`.

**Missing Implementation:**
*   `app/models/user.rb` needs a proper implementation.
*   `app/models/order.rb` needs an implementation.
*   Review all other models.

## Mitigation Strategy: [Whitelist Allowed Predicates](./mitigation_strategies/whitelist_allowed_predicates.md)

**Description:**
1.  **Implement `ransackable_predicates`:** In your ActiveRecord model, define a class method called `ransackable_predicates`.
2.  **Return an Array of Strings:** This method *must* return an array of strings representing allowed predicates (e.g., `['eq', 'cont']`).  Be very restrictive.
3.  **Use `auth_object` (Optional):**  You can use the `auth_object` to conditionally allow different predicates.
4.  **Test:**  Ensure only whitelisted predicates work.

**List of Threats Mitigated:**
*   **Denial of Service (DoS) (Medium Severity):** Prevents resource-intensive predicates.
*   **Unexpected Query Behavior (Low Severity):**  Limits complex predicate combinations.

**Impact:**
*   **Denial of Service:**  Significantly reduces risk.
*   **Unexpected Query Behavior:**  Reduces risk and improves predictability.

**Currently Implemented:**
*   Not implemented in any models.

**Missing Implementation:**
*   Needs implementation in all models using Ransack.

## Mitigation Strategy: [Avoid `ransortable_attributes` Unless Necessary (or Whitelist)](./mitigation_strategies/avoid__ransortable_attributes__unless_necessary__or_whitelist_.md)

**Description:**
1.  **Implement `ransortable_attributes` (If Needed):**  If sorting is required, define `ransortable_attributes` in your model.
2.  **Return an Array of Strings:** Return an array of strings representing allowed sortable attributes.  Be restrictive.
3.  **Use `auth_object` (Optional):** Conditionally allow different sortable attributes.
4.  **If Sorting is Not Needed:**  *Do not* define `ransortable_attributes` at all. This prevents *all* sorting via Ransack. This is the safest option if sorting isn't a requirement.

**List of Threats Mitigated:**
*   **Denial of Service (DoS) (Medium Severity):** Prevents slow sorts on non-indexed columns.

**Impact:**
*   **Denial of Service:** Reduces risk.

**Currently Implemented:**
*   Not consistently implemented.

**Missing Implementation:**
*   Review all models; implement restrictively or remove if sorting is not essential.

## Mitigation Strategy: [Avoid Dynamic `ransackable_` Methods](./mitigation_strategies/avoid_dynamic__ransackable___methods.md)

**Description:**
1.  **Keep it Simple and Static:** The `ransackable_attributes`, `ransackable_predicates`, and `ransortable_attributes` methods should ideally return simple, *static* arrays of strings.
2.  **Avoid Complex Logic:** Do *not* use complex logic, external data, or user input to dynamically generate the allowed lists.
3.  **Use `auth_object` Carefully:** If using `auth_object`, ensure it's based on *trusted* data (e.g., user role from your authentication) and the logic is simple and thoroughly tested.

**List of Threats Mitigated:**
*   **Information Disclosure (High Severity):** Reduces risk of exposing sensitive attributes.
*   **Denial of Service (DoS) (Medium Severity):** Reduces risk of allowing resource-intensive queries.
*   **Code Injection (Low Severity):** Mitigates a potential vulnerability.

**Impact:**
*   **Information Disclosure/DoS:** Significantly reduces risk by promoting predictable behavior.
*   **Code Injection:** Mitigates a potential vulnerability.

**Currently Implemented:**
*   Mostly implemented; methods are generally static.

**Missing Implementation:**
*   Review all `ransackable_` methods for simplicity and static nature.

## Mitigation Strategy: [Regularly Update Ransack](./mitigation_strategies/regularly_update_ransack.md)

**Description:**
1.  **Use Bundler:** Manage gem dependencies with Bundler.
2.  **Run `bundle update ransack`:**  Periodically update Ransack.
3.  **Check Security Advisories:** Monitor for Ransack security advisories.
4.  **Test After Updating:** Thoroughly test after updates.

**List of Threats Mitigated:**
*   **Vulnerabilities in Ransack (Severity Varies):** Protects against known Ransack vulnerabilities.

**Impact:**
*   **Vulnerabilities in Ransack:** Essential for security.

**Currently Implemented:**
*   Partially implemented; updates are not always immediate.

**Missing Implementation:**
*   Establish a regular update schedule.
*   Consider dependency monitoring tools.

