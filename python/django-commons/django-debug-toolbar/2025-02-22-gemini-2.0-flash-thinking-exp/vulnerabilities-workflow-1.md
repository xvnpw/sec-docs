## Combined Vulnerability List

### SQL Injection in SQL Panel Views

* Vulnerability Name: SQL Injection in SQL Panel Views (`sql_select`, `sql_explain`, `sql_profile`) / SQL Debug Endpoint Forgery
* Description:
    The Django Debug Toolbar exposes several SQL endpoints (`sql_select`, `sql_explain`, `sql_profile`) that allow execution of SQL queries. These views, located in `/code/debug_toolbar/panels/sql/views.py` (not provided in PROJECT FILES), process user-provided SQL queries and parameters via a signed form (`SignedDataForm`) and `SQLSelectForm`. The vulnerability arises because `SQLSelectForm` and the associated views may not properly sanitize or parameterize the SQL queries before execution.

    Specifically, the attack can be triggered as follows:
    1. An attacker can access the debug toolbar if `DEBUG=True` and their IP is in `INTERNAL_IPS` or a custom `SHOW_TOOLBAR_CALLBACK` allows it.
    2. The attacker navigates to the SQL panel and finds a recorded SQL query.
    3. The attacker clicks on "SELECT", "EXPLAIN", or "PROFILE" buttons. This sends a request to backend views (`sql_select`, `sql_explain`, `sql_profile`) with details of the selected query.
    4. These views use `SQLSelectForm` to process the signed payload containing SQL query details.
    5. The `SQLSelectForm` directly executes the provided `raw_sql` with `params` using `cursor.execute(sql, params)`, after minimal validation (checking if query starts with `SELECT`).
    6. An attacker who is aware of—or can guess—the application’s default or weak `SECRET_KEY` can potentially create a forged payload that passes the signature verification (SQL Debug Endpoint Forgery). Alternatively, if the original recorded SQL query was malicious or parameters are manipulated (despite signing), re-execution can lead to SQL injection.

* Impact:
    Successful exploitation of this vulnerability allows an attacker to execute arbitrary SQL queries against the application's database. This can result in:
    - **Data Breach:** Exposure of sensitive data by directly querying database tables, including user details, configuration parameters, or internal schema information.
    - **Data Manipulation:** Modification or deletion of critical data, leading to data integrity issues.
    - **Database Compromise:** In severe cases, complete control over the database server, potentially allowing for further attacks on the underlying system.
    - **Privilege Escalation:** If the database user has elevated privileges, the attacker might be able to escalate privileges within the database system.

* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - **Signature Verification:** The views use `SignedDataForm` to sign the data sent in requests to the SQL panel views. This signature verifies that the data has not been tampered with during transit, aiming to prevent basic request manipulation. The signing mechanism (using Django’s signing module) relies on the application’s `SECRET_KEY`.
    - **Limited Exposure:** The debug toolbar is intended for development use and should not be enabled in production. The middleware’s `show_toolbar()` function restricts activation of the toolbar to cases when `DEBUG=True` and the request is from an IP address in the `INTERNAL_IPS` list. Debug endpoints are decorated with access‑limiting decorators (`require_show_toolbar`).
    - **`SELECT` Query Restriction:** The SQL form (`SQLSelectForm`) enforces that only `SELECT` queries are executed through validation in `clean_raw_sql`.
    - **Access Control Decorators:** Debug endpoints are decorated with access‑limiting decorators (such as `require_show_toolbar` and `login_not_required`) so that in a correctly configured development environment only trusted/local requests may access them.

* Missing Mitigations:
    - **Input Sanitization and Validation:** There is no robust input sanitization or validation of the `raw_sql` and `params` beyond checking if the query starts with `SELECT`.  Proper SQL query parameterization and input sanitization within the `SQLSelectForm` and the SQL execution logic in the views are missing.
    - **Query Parameterization Enforcement:**  The application should use parameterized queries to ensure that user-provided data is treated as data, not as executable SQL code. Input validation should also be implemented to restrict the types of SQL operations allowed and to detect and reject potentially malicious SQL syntax.
    - **Strong Secret Key Enforcement:** If the application uses a weak or default `SECRET_KEY` (as in the provided example settings), an attacker can forge valid signed payloads. There should be stronger warnings or enforcement to prevent usage of weak secret keys, especially in debug/development environments that might be accidentally exposed.
    - **Rate Limiting and Audit Logging:** There is no rate limiting or audit logging on these endpoints to track abuse.
    - **Production Environment Detection and Hard Disable:** Implement a more robust mechanism within the Debug Toolbar to detect if it's running in a production-like environment (beyond just `DEBUG=False`) and completely disable itself, regardless of other settings.
    - **Least Privilege:** Ensure that the database user used by the Django application has the minimum necessary privileges.
    - **Review and hardening of `SHOW_TOOLBAR_CALLBACK`:** Ensure that custom `SHOW_TOOLBAR_CALLBACK` implementations are secure.

* Preconditions:
    - The Django Debug Toolbar must be enabled and accessible. This typically requires `DEBUG=True` in Django settings and the attacker's IP address to be either within `INTERNAL_IPS` or able to bypass these restrictions if misconfigured or via a custom `SHOW_TOOLBAR_CALLBACK`.
    - The application is deployed with the debug toolbar active (i.e. `DEBUG=True`) and is accessible from the external network.
    - The attacker needs to be able to navigate to the Debug Toolbar and access the SQL panel.
    - The attacker must be able to initiate requests to the vulnerable SQL panel views (`sql_select`, `sql_explain`, `sql_profile`).
    - Optionally, for SQL Debug Endpoint Forgery: The `SECRET_KEY` in use is weak, default, or otherwise compromised.

* Source Code Analysis:
    1. **`debug_toolbar/panels/sql/views.py`:**
        - `sql_select`, `sql_explain`, `sql_profile` views (inferred from description):
            ```python
            def sql_select(request):
                verified_data = get_signed_data(request) # Verifies signature
                if not verified_data:
                    return HttpResponseBadRequest("Invalid signature")
                form = SQLSelectForm(verified_data) # Processes signed data

                if form.is_valid():
                    sql = form.cleaned_data["raw_sql"] # [!] Untrusted input from recorded query
                    params = form.cleaned_data["params"] # [!] Untrusted input from recorded query
                    with form.cursor as cursor:
                        cursor.execute(sql, params) # [!] SQL execution with untrusted SQL and params
                        # ... process and return result
            ```

    2. **`debug_toolbar/panels/sql/forms.py`:**
        - `SQLSelectForm` in `/code/debug_toolbar/panels/sql/forms.py`:
            ```python
            class SQLSelectForm(SignedDataForm):
                raw_sql = forms.CharField()
                params = forms.CharField()
                alias = forms.CharField()
                duration = forms.FloatField()

                def clean_raw_sql(self):
                    value = self.cleaned_data["raw_sql"]
                    if not is_select_query(value): # Basic validation
                        raise ValidationError("Only 'select' queries are allowed.")
                    return value

                def clean_params(self):
                    value = self.cleaned_data["params"]
                    try:
                        return json.loads(value) # JSON validation only
                    except ValueError as exc:
                        raise ValidationError("Is not valid JSON") from exc

                @cached_property
                def cursor(self):
                    return self.connection.cursor() # No sanitization here
            ```

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
        style F fill:#f9f,stroke:#333,stroke-width:2px
        style E fill:#f9f,stroke:#333,stroke-width:2px
        style D fill:#f9f,stroke:#333,stroke-width:2px
        labelStyle fill:yellow,stroke:blue,stroke-width:2px;
        classDef important fill:#f9f,stroke:#333,stroke-width:2px;
        class D,E,F important;
    ```

* Security Test Case:
    1. **Setup:** Deploy a Django application with Django Debug Toolbar enabled (`DEBUG=True`, IP address in `INTERNAL_IPS`). Ensure the application executes some SQL queries to populate the SQL panel. For "SQL Debug Endpoint Forgery" test, ensure or set a weak `SECRET_KEY`.
    2. **Access SQL Panel:** Access the Django Debug Toolbar in the browser and navigate to the SQL Panel.
    3. **Select Query for Exploitation:** Identify a SQL query listed in the panel. Click the "Select", "Explain", or "Profile" button associated with this query.
    4. **Intercept/Forge Request:**
        - **For Direct Injection:** Use browser developer tools or a proxy to intercept the request generated when submitting the form for "Select", "Explain", or "Profile".
        - **For SQL Debug Endpoint Forgery:** Forge a signed payload using Django's signing module (or a custom script) with a known weak `SECRET_KEY`, including a malicious `SELECT` query (e.g., `SELECT sqlite_version();`).
    5. **Modify/Craft `raw_sql` Parameter:**
        - **For Direct Injection:** In the intercepted request's POST data, modify the `raw_sql` parameter to inject malicious SQL code (e.g., `SELECT * FROM auth_user WHERE id = 1; DROP TABLE auth_user; --`).
        - **For SQL Debug Endpoint Forgery:** Construct the request URL with the forged signed payload parameters (e.g., `/__debug__/sql_select/?<signed_payload_parameters>`).
    6. **Send Modified/Forged Request:** Forward the modified intercepted request or send the crafted forged request to the server.
    7. **Verify SQL Injection:**
        - **Check for Errors:** Observe the response from the server for database-related errors.
        - **Database State (Destructive Injection):** For destructive queries (like `DROP TABLE`), check the database to see if the table was dropped (in a test environment only!).
        - **Data Exfiltration (`UNION SELECT` or similar):** Examine the response for signs of data exfiltration if using `UNION SELECT` or similar techniques.
        - **For SQL Debug Endpoint Forgery:** Check if the JSON response includes the result of the forged SQL query (e.g., SQLite version).
    8. **Success Confirmation:** Confirm SQL injection if database changes are observed or unauthorized data is accessed. For SQL Debug Endpoint Forgery, successful execution and result return confirms the vulnerability.

---

### Information Disclosure via Settings Panel

* Vulnerability Name: Information Disclosure via Settings Panel
* Description:
    The Settings panel in the Django Debug Toolbar, located in `/code/debug_toolbar/panels/settings.py` (not provided in PROJECT FILES), is designed to display Django project settings. If the Debug Toolbar is enabled in a production environment (`DEBUG=True`), this panel becomes an information disclosure vulnerability. Attackers gaining access can view sensitive configuration details. The file `/code/example/settings.py` shows how easily `DEBUG = True` can be set, and how the Debug Toolbar is enabled based on this setting.

* Impact:
    Exposure of Django settings can lead to critical information disclosure:
    - **Database Credentials:** Usernames, passwords, hostnames, ports for database access.
    - **Secret Keys:** The `SECRET_KEY`, crucial for cryptographic operations.
    - **API Keys and Service Credentials:** API keys for external services, email server credentials, etc.
    - **Internal Application Structure:** Insights into the application's configuration, aiding further attacks.

* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - **Intended Development Use:** The Django Debug Toolbar is intended for development only and should not be enabled in production.
    - **`DEBUG` and `INTERNAL_IPS` Checks:** `DebugToolbarMiddleware` and `show_toolbar` function (in `/code/debug_toolbar/middleware.py`) prevent toolbar display in production by checking `settings.DEBUG` and `settings.INTERNAL_IPS`.
    - **Access Control Decorators:** Debug endpoints are decorated with access‑limiting decorators (`require_show_toolbar`).

* Missing Mitigations:
    - **Production Environment Hard Disable:** No robust built-in safeguards within the Debug Toolbar to prevent information disclosure if mistakenly enabled in production.
    - **Setting Filtering/Redaction:** No option to selectively filter or redact sensitive settings from the Settings panel.
    - **Stronger Warnings and Documentation:**  Documentation and warnings in the Settings panel about security risks when `DEBUG=True` is active could be enhanced.
    - **Automated Production Detection:**  More robust mechanism to detect production-like environments and disable the toolbar, beyond just checking `DEBUG=False`.

* Preconditions:
    - `DEBUG=True` is set in Django application's `settings.py` in production.
    - `DebugToolbarMiddleware` is active in `MIDDLEWARE`.
    - Application is deployed and accessible.
    - Attackers can access Debug Toolbar URLs (`/__debug__/`).

* Source Code Analysis:
    1. **`/code/debug_toolbar/panels/settings.py`:**
        - `SettingsPanel` class displays settings.
        - `generate_stats` retrieves settings using `get_safe_settings()`.
        - `get_safe_settings()` (from `django.views.debug`) filters some sensitive info, but may not be enough.

    2. **`/code/example/settings.py`:**
        - Shows `DEBUG = True` and toolbar activation linked to `DEBUG` and `INTERNAL_IPS`.
        - `ENABLE_DEBUG_TOOLBAR` links activation to `DEBUG`:
          ```python
          ENABLE_DEBUG_TOOLBAR = DEBUG and "test" not in sys.argv
          if ENABLE_DEBUG_TOOLBAR:
              INSTALLED_APPS += ["debug_toolbar",]
              MIDDLEWARE += ["debug_toolbar.middleware.DebugToolbarMiddleware",]
          ```

* Security Test Case:
    1. **Deploy Misconfigured Application:** Deploy Django application to a public test environment with `DEBUG = True` in `settings.py`. Ensure Debug Toolbar is installed and its middleware is active.
    2. **Access Debug Toolbar:** Access application in browser, navigate to `/__debug__/`.
    3. **Navigate to Settings Panel:** Click on the "Settings" panel.
    4. **Verify Sensitive Settings Exposure:** Examine Settings panel for:
        - `DATABASES` settings (passwords, usernames, etc.)
        - `SECRET_KEY`
        - Email settings (`EMAIL_HOST_PASSWORD`, etc.)
        - Other sensitive project-specific settings.
    5. **Confirm Vulnerability:** If sensitive settings are viewable in a publicly accessible, `DEBUG=True` application, vulnerability is confirmed.

---

### Debug Toolbar Information Disclosure (General)

* Vulnerability Name: Debug Toolbar Information Disclosure
* Description:
    If the Django Debug Toolbar is enabled on a publicly accessible production instance, an external attacker can send requests (e.g., to `/__debug__/render_panel/`) with valid query parameters (e.g. a valid `store_id` and panel identifier) that bypass intended internal IP and debug‑mode checks. When the middleware’s check (`show_toolbar()`) erroneously accepts an external request due to misconfiguration (`INTERNAL_IPS`, fallback "Docker hack"), an attacker can retrieve internal debug data such as SQL queries, stack traces, and application state.

* Impact:
    An attacker could harvest sensitive information about the internal workings of the application:
    - Database query patterns
    - Configuration settings
    - Implementation logic
    This information can facilitate further targeted attacks.

* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - **`show_toolbar()` Function:** Middleware’s `show_toolbar()` restricts activation to `DEBUG=True` and requests from `INTERNAL_IPS`.
    - **Access Control Decorators:** Debug endpoints are decorated with access‑limiting decorators (`require_show_toolbar` and `login_not_required`).

* Missing Mitigations:
    - **Production Disable Guarantee:** No guarantee Debug Toolbar is completely disabled in production. Misconfiguration (`DEBUG=True`, misconfigured `INTERNAL_IPS`) exposes endpoints.
    - **Additional Authentication:** No extra authentication beyond internal IP and debug‑mode checks.

* Preconditions:
    - Application deployed with `DEBUG=True` (or permissive `INTERNAL_IPS`).
    - Debug toolbar is active for external IPs.
    - Attacker can guess debug endpoint URL patterns (e.g., `/__debug__/render_panel/`).

* Source Code Analysis:
    - **`debug_toolbar/middleware.py`:**
        - `show_toolbar(request)` checks request IP against `INTERNAL_IPS` (or "Docker hack").
    - **`debug_toolbar/views.py`:**
        - `render_panel` view (decorated with `require_show_toolbar`) returns internal debug panel content in JSON response when called with valid GET parameters.

* Security Test Case:
    1. **Setup:** Configure application with `DEBUG=True` (or misconfigure `INTERNAL_IPS`) so debug toolbar is active for external IPs.
    2. **Request:** From external host, send GET request to:
       ```
       http://<target-domain>/__debug__/render_panel/?store_id=<valid_uuid>&panel_id=SQLPanel
       ```
    3. **Observation:** Examine JSON response. If response includes `"content"` with SQL queries, stack traces, or internal data, vulnerability confirmed.
    4. **Confirmation:** Sensitive internal debug information disclosed to external client validates vulnerability.

---

### Template Source Disclosure via Forged Signed Parameter

* Vulnerability Name: Template Source Disclosure via Forged Signed Parameter
* Description:
    The debug toolbar's template source view (`template_source`) returns template source code after syntax highlighting. It expects a signed GET parameter `template_origin`, signed using Django’s signing module. An attacker knowing or guessing the weak `SECRET_KEY` can forge a valid signature for a template filename. Submitting this forged signature with a `template` parameter forces the debug toolbar to return the template’s source code.

* Impact:
    Disclosure of template source code can reveal:
    - Sensitive internal logic
    - Configuration hints
    - Business rules
    This can assist attackers in further attacks, bypassing client‑side validation, or exploiting other weaknesses.

* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - **`@require_show_toolbar` Decorator:** View protected by `@require_show_toolbar` (and `@login_not_required`), restricting access in debug environments.
    - **Signed `template_origin` Parameter:** Attempts to ensure only approved template sources are revealed.

* Missing Mitigations:
    - **Additional Authorization/Authentication:** No further auth beyond debug toolbar’s internal checks.
    - **Weak `SECRET_KEY` Issue:** If weak/default `SECRET_KEY` is used, attacker can forge signed parameter.
    - **Input Validation:** Limited to `signing.loads` deserialization, no further restrictions on retrieved templates.

* Preconditions:
    - Debug toolbar enabled in deployed instance (`DEBUG=True`).
    - Application uses weak or default `SECRET_KEY`.
    - `INTERNAL_IPS` or access controls are misconfigured/bypassable.

* Source Code Analysis:
    - **`/code/debug_toolbar/panels/templates/views.py`:**
        - `template_source` view retrieves `template_origin` GET parameter.
        - Deserializes `template_origin` using `signing.loads()`.
        - Uses result to create `Origin` object and iterates template loaders (`loader.get_contents(origin)`) to find template source.
        - Returns syntax‑highlighted content in JSON response.
        - Signing relies on `SECRET_KEY` security (weak key allows forgery).

* Security Test Case:
    1. **Setup:** Verify debug toolbar enabled (`DEBUG=True`), note `SECRET_KEY` (if weak/default).
    2. **Forge Signature:** Using Django’s signing tools, create a valid signed string for a known template file's origin.
    3. **Request:** Send GET request to:
       ```
       http://<target-domain>/__debug__/template_source/?template_origin=<forged_value>&template=<expected_template_name>
       ```
    4. **Observation:** If response is HTTP 200 and JSON contains HTML-formatted template source code, vulnerability confirmed.
    5. **Confirmation:** Successful template source retrieval indicates attacker can expose template code.