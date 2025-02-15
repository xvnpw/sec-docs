# Attack Tree Analysis for jeremyevans/sequel

Objective: Compromise Database via Sequel (Focus: High-Risk Exploits)

## Attack Tree Visualization

```
                                      Attacker's Goal:
                                      Compromise Database via Sequel
                                      /               \
                                     /                 \
                      -------------------------------------
                      |                                   |
              [HIGH RISK] Data Exfiltration     [HIGH RISK] Data Modification
                      |                                   |
        -------------------------                 -----------------
        |                                         |
  [HIGH RISK] Unfiltered                    [HIGH RISK] Unsafe
  Input to Methods                          Updates (Mass Assignment)
        |                                         |
  (Examples)                                  (Examples)
  - *Critical Node:* SQLi via                  - *Critical Node:* SQLi
    .where()                                    in mass update .where()
    with untrusted data                         (no checks)

```

## Attack Tree Path: [[HIGH RISK] Data Exfiltration via Unfiltered Input to Methods](./attack_tree_paths/_high_risk__data_exfiltration_via_unfiltered_input_to_methods.md)

*   **Description:** This attack vector involves injecting malicious SQL code into database queries through Sequel methods that accept user-supplied input without proper sanitization or parameterization. The most common and dangerous vulnerability.
*   **Mechanism:**
    *   The attacker provides crafted input that includes SQL code fragments.
    *   The application, due to a lack of input validation and/or improper use of Sequel, directly incorporates this input into a SQL query string.
    *   The database server executes the attacker's injected SQL code, potentially returning sensitive data.
*   **`*Critical Node:*` SQLi via `.where()` with untrusted data:**
    *   **Specifics:** This represents the most direct and easily exploitable form of SQL injection. The `.where()` method is frequently used to filter data, and if user input is directly interpolated into the `where` clause, it's highly vulnerable.
    *   **Example:** `User.where("username = '#{params[:username]}'")` If `params[:username]` is `'; DROP TABLE users; --`, the entire users table could be deleted.
    *   **Mitigation:**
        *   **Parameterized Queries:** *Always* use parameterized queries: `User.where(username: params[:username])` or `User.where('username = ?', params[:username])`. This tells the database to treat the input as data, not code.
        *   **Input Validation:** Implement strict input validation *before* passing data to Sequel. Validate data type, length, format, and allowed characters. Use a whitelist approach whenever possible (allow only known-good values).
        *   **Sequel's Escaping:** If you *must* construct SQL strings (which is strongly discouraged), use Sequel's built-in escaping functions (e.g., `Sequel.escape`). However, parameterized queries are far superior.

## Attack Tree Path: [[HIGH RISK] Data Modification via Unsafe Updates (Mass Assignment)](./attack_tree_paths/_high_risk__data_modification_via_unsafe_updates__mass_assignment_.md)

*   **Description:** This attack vector exploits Sequel's mass assignment features (e.g., `update`, `update_all`) to modify database records in ways that were not intended by the application. Attackers can potentially alter fields they shouldn't have access to, leading to privilege escalation or data corruption.
*   **Mechanism:**
    *   The application uses a mass assignment method to update multiple attributes of a record at once.
    *   The attacker provides a crafted HTTP request (e.g., a form submission) that includes parameters for fields they are not authorized to modify.
    *   If the application doesn't properly restrict which fields can be updated, the attacker's changes are applied to the database.
*   **`*Critical Node:*` SQLi in mass update `.where()` (no checks):**
    *   **Specifics:** This combines the dangers of mass assignment with SQL injection.  The attacker can use SQL injection in the `where` clause to select records for modification that they shouldn't have access to, and then use the mass update to change those records.
    *   **Example:** `User.where("id = '#{params[:id]} OR 1=1'").update(admin: true)` - This could set *all* users to be administrators. The `OR 1=1` bypasses any intended ID check.
    *   **Mitigation:**
        *   **`set_allowed_columns` / `set_fields`:** Use Sequel's `set_allowed_columns` or `set_fields` methods to explicitly define which columns are permitted to be updated via mass assignment. This creates a whitelist of allowed fields.
        *   **Manual Hash Construction:** Instead of passing the entire `params` hash to `update`, manually construct a new hash containing only the permitted fields and their values.
        *   **Input Validation (again!):** Even with the above protections, validate all input to ensure it conforms to expected types and constraints.
        *   **Parameterized Queries (for the `where` clause):** If using a `where` clause with user input in an update, *always* use parameterized queries to prevent SQL injection.

