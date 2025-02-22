## Vulnerability List

### SQL Injection in SQL Panel Views

* Vulnerability Name: SQL Injection in SQL Panel Views
* Description:
    1. An attacker can access the debug toolbar (precondition: `DEBUG=True` and IP is in `INTERNAL_IPS` or custom `SHOW_TOOLBAR_CALLBACK` allows it).
    2. The attacker navigates to the SQL panel.
    3. The attacker finds a recorded SQL query in the SQL panel.
    4. The attacker clicks on "SELECT", "EXPLAIN", or "PROFILE" buttons associated with the SQL query. These actions send AJAX requests to backend views (`sql_select`, `sql_explain`, `sql_profile`) to execute the query or its variants.
    5. These views use `SQLSelectForm` to process the request, which includes `raw_sql` and `params` from the original query.
    6. The `SQLSelectForm` directly executes the provided `raw_sql` with `params` using `cursor.execute(sql, params)`.
    7. If the original recorded SQL query was crafted maliciously (e.g., by a compromised internal application component that makes database queries and its queries are logged by debug toolbar), or if the parameters are manipulated by an attacker (although parameters are signed, the vulnerability lies in re-executing potentially dangerous original queries), the attacker could potentially inject arbitrary SQL commands.
* Impact:
    - Information Disclosure: An attacker could extract sensitive data from the database by crafting malicious SQL queries.
    - Data Manipulation: In certain database configurations or if the application user has sufficient privileges, an attacker might be able to modify or delete data in the database.
    - Privilege Escalation: If the database user has elevated privileges, the attacker might be able to escalate privileges within the database system.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - Signature Verification: The views (`sql_select`, `sql_explain`, `sql_profile`) use `SignedDataForm` to verify the integrity and authenticity of the data sent from the frontend. This prevents direct manipulation of parameters in transit.
    - Limited Exposure: The debug toolbar is intended for development and debugging purposes and is generally not enabled in production environments. Access is restricted by `DEBUG=True` and `INTERNAL_IPS` or a custom `SHOW_TOOLBAR_CALLBACK`.
    - Non-destructive operations by default: The provided views are intended for `SELECT`, `EXPLAIN`, and `PROFILE` operations which are typically read-only or metadata retrieval operations. However, `PROFILE` in some databases or configurations might have side effects.
* Missing Mitigations:
    - Input Sanitization and Validation: While the `SignedDataForm` prevents tampering during transit, it does not sanitize or validate the `raw_sql` and `params` before re-execution. The application should implement server-side validation and sanitization of the SQL query and its parameters before executing them, even within the debug toolbar context.
    - Query Parameterization Enforcement: Ensure that all user-provided input is properly parameterized and not directly concatenated into the SQL query string. While parameterization is used in the re-execution, the original SQL query itself is taken directly from the recorded query, which might be vulnerable.
    - Least Privilege: Ensure that the database user used by the Django application (and consequently by the debug toolbar's re-executed queries) has the minimum necessary privileges required for the application's functionality, limiting the potential impact of SQL injection.
    - Review and hardening of `SHOW_TOOLBAR_CALLBACK`: Ensure that custom `SHOW_TOOLBAR_CALLBACK` implementations are secure and do not unintentionally expose the debug toolbar to unauthorized users.
* Preconditions:
    - `DEBUG = True` is set in Django settings.
    - The attacker's IP address is in `INTERNAL_IPS` or a custom `SHOW_TOOLBAR_CALLBACK` allows access for the attacker.
    - The debug toolbar is enabled and the SQL panel is active.
    - There is a recorded SQL query in the SQL panel, which could be a benign query or a maliciously crafted one.
* Source Code Analysis:
    1. **`debug_toolbar/panels/sql/views.py`:**
        - `sql_select`, `sql_explain`, `sql_profile` views all follow a similar pattern (inferred from description, file not provided but functionality is clear from context):
            ```python
            def sql_select(request):
                verified_data = get_signed_data(request)
                if not verified_data:
                    return HttpResponseBadRequest("Invalid signature")
                form = SQLSelectForm(verified_data)

                if form.is_valid():
                    sql = form.cleaned_data["raw_sql"] # [!] Untrusted input from recorded query
                    params = form.cleaned_data["params"] # [!] Untrusted input from recorded query
                    with form.cursor as cursor:
                        cursor.execute(sql, params) # [!] SQL execution with untrusted SQL and params
                        # ... rest of the code to process and return result
            ```
        - The views retrieve `raw_sql` and `params` from the `SQLSelectForm`, which are based on the initially recorded SQL query. These are then directly passed to `cursor.execute(sql, params)`.

    2. **`debug_toolbar/panels/sql/forms.py`:**
        - `SQLSelectForm` (from `/code/debug_toolbar/panels/sql/forms.py`) is defined to process the signed data.
        - It initializes with `verified_data` which contains the original SQL query details.
        - The form includes `clean_raw_sql` which validates that the query is a `SELECT` query, but performs no further sanitization.
        - The form includes `clean_params` which validates that params are valid JSON, but performs no sanitization on the content.
        - The form itself does not perform any further sanitization or validation on `raw_sql` and `params` beyond these basic checks.

    3. **`debug_toolbar/panels/sql/panel.py`:**
        - The `SQLPanel` (inferred from description, file not provided but functionality is clear from context) records SQL queries in the `record` method, storing the raw SQL and parameters.
        - When the user interacts with the panel, these recorded queries are used to populate the `SQLSelectForm` and are sent to the views.

    ```mermaid
    graph LR
        A[User (Attacker) - Browser] --> B(Debug Toolbar Frontend);
        B -- Click "SELECT/EXPLAIN/PROFILE" --> C(AJAX Request to Backend View);
        C --> D(sql_select/sql_explain/sql_profile in views.py);
        D --> E(SQLSelectForm);
        E --> F{cursor.execute(raw_sql, params)};
        F --> G[Database];
        G --> F;
        F --> D;
        D --> C;
        C --> B;
        B --> A;
        style F fill:#f9f,stroke:#333,stroke-width:2px
        style E fill:#f9f,stroke:#333,stroke-width:2px
        style D fill:#f9f,stroke:#333,stroke-width:2px
    ```

* Security Test Case:
    1. Set `DEBUG = True` and ensure your IP is in `INTERNAL_IPS` in your Django project's `settings.py`.
    2. Access the Django development server in your browser.
    3. Navigate to a page that triggers a database query. Ensure the debug toolbar is visible and the SQL panel is populated.
    4. In your Django project, modify a view or model to execute a malicious SQL query that will be captured by the debug toolbar. For example, in a view, execute:
        ```python
        from django.db import connection
        def malicious_view(request):
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1; DROP TABLE auth_user;") # [!] Malicious SQL - DO NOT USE IN PRODUCTION
            return HttpResponse("Malicious query executed (check debug toolbar)")
        ```
        **[Important Security Note]:** ***Do not actually use `DROP TABLE auth_user;` on a production or important development database. Use a test database for this vulnerability test and a less destructive command if needed for your testing environment. The goal is to demonstrate SQL injection, not to cause data loss.*** A safer test would be `SELECT sqlite_version(); -- malicious comment` or similar, depending on your database.
    5. Access the view that executes the malicious SQL query in your browser.
    6. Open the debug toolbar and go to the SQL panel.
    7. Find the malicious SQL query you injected.
    8. Click on the "SELECT" (or "EXPLAIN" or "PROFILE") button for this query.
    9. Observe the behavior. If the SQL injection is successful, you might see errors related to the injected SQL command (e.g., table dropped error if you used `DROP TABLE`). Or, if you used a `SELECT` based injection, you might retrieve data you shouldn't have access to if you modify the query to extract data.
    10. Examine the database state (using a database client or Django shell) to confirm if the injected SQL command was executed. For example, if you attempted to drop a table (again, only for testing on a *test database*!), check if the table is indeed dropped.

---