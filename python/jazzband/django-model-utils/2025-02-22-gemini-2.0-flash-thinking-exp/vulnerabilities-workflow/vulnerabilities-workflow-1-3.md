## Vulnerability List

### SQL Injection in `JoinQueryset.join` method

*   **Vulnerability Name:** SQL Injection in `JoinQueryset.join`
*   **Description:**
    The `JoinQueryset.join` method in `managers.py` constructs a raw SQL query using string formatting to create a temporary table. This method takes a queryset as input and extracts its SQL query string to embed it within a larger SQL statement for temporary table creation. If the input queryset is crafted using user-controlled data that is not properly sanitized by Django's query builder in this specific context, it can lead to SQL injection. An attacker could manipulate the input queryset to inject malicious SQL code, which would then be executed by the database when the `join` method is called.
    **Step-by-step trigger:**
    1. An attacker identifies an application endpoint that utilizes a Django model that uses `JoinManager` or `JoinQueryset.as_manager()`.
    2. The application uses the `join` method on a queryset that is in some way influenced by user-provided input (e.g., through URL parameters, form data, etc.) to filter or order the initial queryset.
    3. The attacker crafts a malicious input that, when processed by the application and incorporated into the queryset used in `join`, injects SQL code into the final SQL query string that is constructed in the `join` method.
    4. When the `join` method executes the constructed SQL query against the database, the injected SQL code is executed, leading to SQL injection.
*   **Impact:**
    Successful SQL injection can have critical impacts, including:
    * **Data Breach:** Unauthorized access to sensitive data stored in the database. Attackers can read, extract, and exfiltrate confidential information.
    * **Data Manipulation:** Attackers can modify or delete data, leading to data integrity issues and potential disruption of application functionality.
    * **Account Takeover:** In some cases, attackers might be able to escalate privileges or gain access to administrator accounts.
    * **Denial of Service:** Although explicitly excluded, SQL injection can be used to cause database overload, indirectly leading to denial of service.
    * **Code Execution:** In the most severe scenarios, depending on the database system and configuration, it might be possible to achieve remote code execution on the database server.
*   **Vulnerability Rank:** critical
*   **Currently Implemented Mitigations:**
    No mitigations are implemented in the provided code for the `JoinQueryset.join` method to prevent SQL injection. The method uses string formatting directly with the SQL query string obtained from the input queryset, without proper parameterization in the final SQL construction step.
*   **Missing Mitigations:**
    The primary missing mitigation is the use of parameterized queries when constructing the SQL statement within the `JoinQueryset.join` method. Instead of using `.format()` with the raw SQL string, the code should use the database cursor's `execute` method with the SQL query and parameters provided by `qs.query.sql_with_params()`. This would ensure that user-provided data is properly escaped and treated as data, not as executable SQL code.
*   **Preconditions:**
    1. The Django project utilizes models that are configured to use `JoinManager` or `JoinQueryset.as_manager()`.
    2. An application feature exists where the `join` method is called on a queryset that is in any way derived from or influenced by user-controlled input. This could be through URL parameters, form submissions, or any other mechanism where user data affects the initial queryset that is subsequently used in the `join` method.
    3. The application is deployed in an environment where an external attacker can send requests that trigger the vulnerable code path.
*   **Source Code Analysis:**
    ```python
    def join(self, qs: QuerySet[Any] | None = None) -> QuerySet[Any]:
        '''
        ...
        '''
        # ... [Code to prepare qs and fk_column] ...

        TABLE_NAME = 'temp_stuff'
        query, params = qs.query.sql_with_params() # <-- Get raw SQL and params
        sql = '''
            DROP TABLE IF EXISTS {table_name};
            DROP INDEX IF EXISTS {table_name}_id;
            CREATE TEMPORARY TABLE {table_name} AS {query}; # <-- Vulnerable string formatting
            CREATE INDEX {table_name}_{fk_column} ON {table_name} ({fk_column});
        '''.format(table_name=TABLE_NAME, fk_column=fk_column, query=str(query)) # <-- Vulnerability is here

        with connection.cursor() as cursor:
            cursor.execute(sql, params) # <-- Executes the constructed SQL

        # ... [Rest of the method] ...
        return new_qs
    ```
    **Visualization:**

    ```
    [User Input] --> [Application Logic] --> [QuerySet Construction (qs)] --> JoinQueryset.join(qs)
                                                                                |
                                                                                v
                                    qs.query.sql_with_params() --> (SQL Query String, Parameters)
                                                                                |
                                                                                v
                    String Formatting with SQL Query String --> [Injected SQL if qs is malicious] --> SQL Query
                                                                                |
                                                                                v
                                            cursor.execute(SQL Query, params) --> [Database Execution] --> SQL Injection
    ```

    **Explanation:**
    1. The `join` method retrieves the raw SQL query string and parameters from the provided queryset `qs` using `qs.query.sql_with_params()`.
    2. It then constructs a new SQL query string for creating a temporary table. Critically, it uses `.format()` to embed the SQL query string obtained from `qs` directly into the `CREATE TEMPORARY TABLE AS` clause.
    3. If the queryset `qs` is influenced by user input and that input is not properly sanitized by Django's query building process, malicious SQL code can be injected into the `query` string.
    4. When the `cursor.execute(sql, params)` is called, the entire constructed SQL string, including the potentially injected malicious code, is executed against the database.
    5. Even though `sql_with_params` returns parameters, these parameters are not used in the string formatting of the final SQL query, making the string formatting vulnerable. The parameters returned are only used for the *outer* query if any, not for the inner query that is string formatted.

*   **Security Test Case:**
    **Objective:** To demonstrate SQL injection vulnerability in `JoinQueryset.join` when the input queryset is manipulated with malicious SQL.

    **Pre-requisites:**
    1. Set up a Django project that includes the `model_utils` library and defines a model that uses `JoinManager` or `JoinQueryset.as_manager()`. Let's assume a model named `MyModel`.
    2. Create a view that uses `JoinQueryset.join` and allows user input to influence the queryset used in `join`. For simplicity, let's assume we can control a filter on `MyModel` through a GET parameter.

    **Steps:**
    1. **Craft Malicious Input:** Prepare a malicious SQL injection payload to be injected through the user-controlled input. A simple example for testing would be to inject `'; SELECT pg_sleep(10); --` which, if successful, would cause a 10-second delay in the database response (PostgreSQL specific, adjust for other DBs).
    2. **Construct Malicious URL:** Construct a URL that includes the malicious payload in a parameter that influences the queryset used in `JoinQueryset.join`. For example, if the view filters `MyModel` based on a parameter named `filter_param`, the URL might look like: `http://example.com/vulnerable_endpoint/?filter_param=malicious_payload`.  The exact parameter and how it influences the queryset will depend on the application's code. Assume for this test case, the application uses the parameter to filter a field named 'name' in `MyModel`. So, the malicious payload could be injected as part of the filter value.
    3. **Send Malicious Request:** Send the crafted HTTP request (e.g., using `curl`, `wget`, or a browser) to the vulnerable endpoint.
    4. **Observe Response Time:** Monitor the response time from the server. If the SQL injection is successful and the `pg_sleep(10)` (or equivalent) is executed, the response from the server will be delayed by approximately 10 seconds (or the sleep duration used in the payload). A normal, non-injected request should respond much faster.
    5. **Verify Injection (Optional, but Recommended):** For more robust verification, instead of `pg_sleep`, a payload that attempts to extract data (e.g., database version or username) could be used, and the response could be checked for the injected data. However, the time-based injection test with `pg_sleep` is often sufficient to confirm the vulnerability.

    **Expected Result:** If the vulnerability exists, the request with the malicious payload will take significantly longer to respond (e.g., 10 seconds longer if using `pg_sleep(10)`) compared to a normal request, indicating successful SQL injection.