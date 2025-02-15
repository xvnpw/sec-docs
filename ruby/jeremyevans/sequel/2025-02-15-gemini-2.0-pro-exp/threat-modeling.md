# Threat Model Analysis for jeremyevans/sequel

## Threat: [SQL Injection via String Interpolation](./threats/sql_injection_via_string_interpolation.md)

**1. Threat: SQL Injection via String Interpolation**

*   **Description:** An attacker crafts malicious input that, when interpolated directly into a SQL query string *within Sequel methods*, alters the query's logic to execute arbitrary SQL commands. This bypasses Sequel's intended parameterization, even if the developer *thinks* they are using Sequel. The attacker can read, modify, or delete data, and potentially compromise the server.
*   **Impact:**
    *   Data breach (unauthorized access to sensitive data).
    *   Data modification (unauthorized changes to data).
    *   Data deletion (unauthorized removal of data).
    *   Potential server compromise (if the database allows OS command execution).
*   **Sequel Component Affected:**
    *   `DB.fetch` (when used with raw SQL *and* string interpolation).
    *   `Dataset#where` (when used with string interpolation *inside* the `where` clause).
    *   `Sequel.lit` (when *misused* with string interpolation instead of placeholders).
    *   Any Sequel method accepting raw SQL fragments *without* proper escaping using Sequel's mechanisms.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Absolutely never** use string interpolation (`#{}`, string concatenation) within SQL queries passed to *any* Sequel method.
    *   **Always** use parameterized queries with placeholders (`?`) or named placeholders (`:name`) *within Sequel*. Example: `DB[:users].where("name = ?", params[:name])` or `DB[:users].where(:name => params[:name])`.
    *   Prefer Sequel's dataset methods (e.g., `where(:name => params[:name])`) as they handle parameterization correctly.
    *   Sanitize and validate all user input *before* it reaches any Sequel method, as a defense-in-depth measure, but *do not rely on this alone*.

## Threat: [Dataset Manipulation via Untrusted Input (Non-Value Injection)](./threats/dataset_manipulation_via_untrusted_input__non-value_injection_.md)

**2. Threat: Dataset Manipulation via Untrusted Input (Non-Value Injection)**

*   **Description:** An attacker provides crafted input that is used to construct *parts* of a Sequel dataset query *other than* the values.  This includes manipulating `order`, `select`, `join`, `group`, `having`, etc. The attacker can change the query's structure, potentially exposing unintended data, causing denial of service through inefficient queries, or even modifying data in some edge cases. This is *not* traditional SQL injection of *values*, but manipulation of the query *structure* itself.
*   **Impact:**
    *   Information disclosure (exposing data in unintended ways).
    *   Denial of service (through inefficient queries or resource exhaustion).
    *   Potential data modification (in specific, less common scenarios, depending on the database and the manipulated query).
*   **Sequel Component Affected:**
    *   `Dataset#order`
    *   `Dataset#select`
    *   `Dataset#join`
    *   `Dataset#group`
    *   `Dataset#having`
    *   Any dataset method that accepts column names, table names, or SQL fragments as arguments *without proper validation*.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use strict whitelists to control allowed column names, table names, and operations for *all* dataset methods.  Do not allow arbitrary user input to dictate these.
    *   Use Sequel's `identifier` method to explicitly mark strings as identifiers: `DB[:users].order(Sequel.identifier(params[:order_by]))`.  *However*, still validate `params[:order_by]` against a whitelist *before* passing it to `Sequel.identifier`.
    *   Validate and sanitize user input *before* it's used in *any* dataset method, even if it's not directly in a `where` clause. This is crucial.
    *   Avoid dynamically constructing complex dataset chains based solely on unfiltered user input. Use a controlled, pre-defined API for query construction, limiting the user's ability to inject arbitrary SQL.

## Threat: [Mass Assignment (Attribute Spoofing) via Unprotected `set`/`update`](./threats/mass_assignment__attribute_spoofing__via_unprotected__set__update_.md)

**3. Threat: Mass Assignment (Attribute Spoofing) via Unprotected `set`/`update`**

*   **Description:** An attacker submits a request with extra, unexpected parameters that correspond to model attributes they shouldn't be able to modify. If the application uses Sequel's `set` or `update` methods *without* specifying allowed attributes, these unauthorized attributes are updated in the database. The attacker might elevate privileges (e.g., setting an `admin` flag) or modify sensitive data directly.
*   **Impact:**
    *   Elevation of privilege.
    *   Data modification (unauthorized changes to sensitive attributes).
    *   Bypassing application logic and security controls.
*   **Sequel Component Affected:**
    *   `Model#set` (when used without `set_only` or `set_fields`).
    *   `Model#update` (when used without `update_only` or `update_fields`).
    *   `Model.new` (when used with unfiltered input *and* immediately saved).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Always** use `set_only` or `update_only` to explicitly specify the *only* allowed attributes: `user.set_only(params, [:name, :email])`.
    *   Alternatively, use `set_fields` or `update_fields` with a whitelist of allowed fields: `user.set_fields(params, [:name, :email])`.
    *   *Never* use `set` or `update` directly with unfiltered user input. This is a critical vulnerability.
    *   If using a framework like Rails, utilize strong parameters.  If not, implement a similar parameter filtering mechanism *before* data reaches Sequel.

