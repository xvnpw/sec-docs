# Attack Surface Analysis for jeremyevans/sequel

## Attack Surface: [SQL Injection (via Literal Strings/Interpolation)](./attack_surfaces/sql_injection__via_literal_stringsinterpolation_.md)

*   **Description:**  Bypassing Sequel's parameterized query mechanisms to inject malicious SQL code by directly embedding user input into SQL strings.
*   **How Sequel Contributes:**  Provides `Sequel.lit` and allows string interpolation within SQL strings, which, if misused with unsanitized user input, create critical injection vulnerabilities.  This is the *primary* SQL injection risk with Sequel.
*   **Example:**
    ```ruby
    # Vulnerable
    DB["SELECT * FROM users WHERE username = '#{params[:username]}'"]
    DB.fetch("SELECT * FROM users WHERE id = " + Sequel.lit(params[:id])).all # Extremely Vulnerable
    ```
*   **Impact:**  Complete database compromise, data theft, data modification, data deletion, potential server compromise (depending on database privileges).
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Developers:**  *Always* use parameterized queries with placeholders (`?`) and pass user input as separate arguments to the query method.  *Never* directly embed user input into SQL strings using string interpolation or concatenation.  Strictly avoid using `Sequel.lit` with *any* unsanitized input.  Favor dataset methods (`where`, `filter`, etc.) over raw SQL strings whenever possible.  Mandatory code reviews must specifically check for any string manipulation within SQL query construction.

## Attack Surface: [SQL Injection (via Dynamic Table/Column Names)](./attack_surfaces/sql_injection__via_dynamic_tablecolumn_names_.md)

*   **Description:**  Allowing user input to control table or column names, leading to SQL injection *even when* parameterized queries are used for values.
*   **How Sequel Contributes:**  Sequel allows dynamic table and column access (e.g., `DB[table_name.to_sym]`, `dataset.select(column_name.to_sym)`), which can be exploited if `table_name` or `column_name` are derived from user input without proper sanitization.
*   **Example:**
    ```ruby
    # Vulnerable
    DB[params[:table].to_sym].where(id: params[:id])
    DB[:users].select(params[:column].to_sym).order(params[:order_column].to_sym).all
    ```
*   **Impact:**  Similar to standard SQL injection: database compromise, data theft, modification, deletion.  Can be used to bypass access controls and query arbitrary tables/columns.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Developers:**  *Never* allow direct user control over table or column names in SQL queries.  Implement a *strict whitelist* of allowed table and column names.  Validate user input against this whitelist *before* constructing the query.  Use enums, lookup tables, or other indirect mapping techniques to translate user-provided identifiers to actual database identifiers.  Avoid any dynamic construction of table/column names based on user input.

## Attack Surface: [Data Exposure (via Unintentional `select`)](./attack_surfaces/data_exposure__via_unintentional__select__.md)

*   **Description:**  Accidentally exposing sensitive data by selecting more columns than intended, particularly through misuse of `select(*)`.
*   **How Sequel Contributes:**  Sequel's `select` method, especially the wildcard `select(*)`, can easily lead to unintentional data exposure if developers are not meticulous about specifying *only* the necessary columns.
*   **Example:**
    ```ruby
    # Potentially Vulnerable (if password_hash or other sensitive data exists)
    DB[:users].select(:id, :username, :password_hash).all  # Exposes password_hash
    DB[:users].select(*).all # Highly risky; exposes all columns
    ```
*   **Impact:**  Leakage of sensitive data (passwords, PII, API keys, etc.), potentially violating privacy regulations and causing reputational damage.
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **Developers:**  Explicitly list *only* the required columns in `select` statements.  *Avoid* using `select(*)` unless absolutely necessary and you are *certain* about the table schema and the absence of sensitive data.  Use separate models or database views for different access levels, each selecting only the data appropriate for that level.  Regularly review all uses of `select` to ensure no sensitive data is unintentionally exposed.  Consider using a "deny-list" approach to explicitly exclude sensitive columns.

## Attack Surface: [Unsafe Sequel Extensions](./attack_surfaces/unsafe_sequel_extensions.md)

*   **Description:**  Using untrusted or vulnerable Sequel extensions that introduce new attack vectors.
*   **How Sequel Contributes:** Sequel's extension mechanism allows loading additional functionality, which could be malicious or contain vulnerabilities.
*   **Example:** `Sequel.extension :some_untrusted_extension`
*   **Impact:** Varies depending on the extension, but could include SQL injection, data exposure, or other vulnerabilities.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    * **Developers:** Only use extensions from trusted sources (e.g., official Sequel extensions or well-maintained community extensions with a strong security track record). Carefully vet any third-party extensions before using them, including reviewing the source code for potential vulnerabilities. Keep extensions updated to their latest versions to receive security patches.

