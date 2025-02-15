# Attack Surface Analysis for sqlalchemy/sqlalchemy

## Attack Surface: [Raw SQL Injection](./attack_surfaces/raw_sql_injection.md)

*   **Description:**  Execution of arbitrary SQL commands by injecting malicious code into SQL queries.
*   **SQLAlchemy Contribution:**  Provides methods (`text()`, `engine.execute()`, `connection.execute()`) that allow direct execution of raw SQL strings.  Improper use of these methods with unsanitized user input creates the vulnerability.
*   **Example:**
    ```python
    # Vulnerable
    user_input = request.args.get('username')  # e.g., "'; DROP TABLE users; --"
    connection.execute(text("SELECT * FROM users WHERE username = '" + user_input + "'"))
    ```
*   **Impact:**  Complete database compromise, data theft, data modification, data deletion, denial of service.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Parameterized Queries (Primary Defense):**  Always use parameterized queries (bound parameters) with `text()` and other raw SQL execution methods.
        ```python
        # Mitigated
        user_input = request.args.get('username')
        connection.execute(text("SELECT * FROM users WHERE username = :username"), {"username": user_input})
        # OR, using positional parameters:
        connection.execute(text("SELECT * FROM users WHERE username = ?"), (user_input,))
        ```
    *   **ORM Usage (When Possible):** Prefer using SQLAlchemy's ORM features (e.g., `session.query()`, `filter()`) over raw SQL whenever possible. The ORM generally handles parameterization automatically when used correctly.
    * **Avoid String Concatenation:** Never build SQL queries by concatenating strings with user input.

## Attack Surface: [ORM-Level Injection (Subtle SQL Injection)](./attack_surfaces/orm-level_injection__subtle_sql_injection_.md)

*   **Description:**  Manipulation of the generated SQL through misuse of ORM features, leading to unintended query behavior.
*   **SQLAlchemy Contribution:**  Features like dynamic filter criteria, custom SQL functions, and `func` with untrusted input can be exploited if not handled carefully.
*   **Example:**
    ```python
    # Potentially Vulnerable
    user_supplied_column = request.args.get('sort_by')  # e.g., "id; --"
    query = session.query(User).order_by(user_supplied_column)
    ```
*   **Impact:**  Data leakage, unauthorized data access, potentially data modification or deletion (depending on the specific injection).
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **Whitelist Allowed Values:**  For dynamic filter criteria or ordering, maintain a whitelist of allowed column names and operators.  Reject any input that doesn't match the whitelist.
        ```python
        ALLOWED_COLUMNS = ["id", "username", "email"]
        user_supplied_column = request.args.get('sort_by')
        if user_supplied_column in ALLOWED_COLUMNS:
            query = session.query(User).order_by(user_supplied_column)
        else:
            # Handle invalid input (e.g., return an error)
            pass
        ```
    *   **Avoid Direct User Input in ORM Constructs:**  Minimize the use of direct user input in constructing ORM queries.  Use intermediate variables and mappings to translate user-friendly input into safe, internal representations.
    *   **Careful Use of `func`:**  If using `sqlalchemy.func`, strictly whitelist allowed SQL function names.  Validate and sanitize any arguments passed to these functions.
    * **Avoid `literal_column` with user input:** Do not use user-provided data directly within `literal_column`.

## Attack Surface: [Denial of Service (Unbounded Queries)](./attack_surfaces/denial_of_service__unbounded_queries_.md)

*   **Description:** Exhaustion of server resources (memory, CPU, database connections) by executing queries that return excessively large result sets.
*   **SQLAlchemy Contribution:** SQLAlchemy allows queries without explicit limits, making it possible to retrieve all rows from a table.
*   **Example:**
    ```python
    # Vulnerable
    products = session.query(Product).all()  # If 'Product' table has millions of rows
    ```
*   **Impact:** Application unavailability, performance degradation, potential server crashes.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Pagination (Essential):** Always use pagination (e.g., `limit()` and `offset()`, or SQLAlchemy's `paginate()` method) for queries that could potentially return large result sets.
        ```python
        # Mitigated
        page = request.args.get('page', 1, type=int)
        per_page = 20
        products = session.query(Product).limit(per_page).offset((page - 1) * per_page).all()
        # OR, using paginate():
        # products = session.query(Product).paginate(page=page, per_page=per_page)
        ```
    *   **Maximum Result Limits:** Set hard limits on the maximum number of results that can be returned by a query, even with pagination.

