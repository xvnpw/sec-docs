### Vulnerability List:

- **Vulnerability Name:** SQL Injection via crafted string comparison in DjangoQL query

- **Description:**
    An attacker can inject raw SQL into the database query through a crafted DjangoQL query string, specifically when using string comparison operators like `startswith`, `endswith`, `~` (contains), and their negated forms (`not startswith`, `not endswith`, `!~`). This is due to insufficient sanitization of string literals within the DjangoQL parser before they are used in raw SQL LIKE clauses.

    **Step-by-step trigger:**
    1. Identify a Django application using DjangoQL and exposing a DjangoQL search interface to external users (e.g., via Django Admin or a custom view like `completion_demo`).
    2. Construct a malicious DjangoQL query that includes a string comparison operator (`startswith`, `endswith`, `~`, `!~`, `not startswith`, `not endswith`, `!~`).
    3. Inject raw SQL within the string literal part of the query. For example, using `startswith "') OR 1=1 --"` within a user-controlled input field that is processed by DjangoQL.
    4. Submit the crafted query to the application.
    5. The DjangoQL parser will generate an AST.
    6. The `build_filter` function will construct a Django ORM query using this AST, embedding the malicious SQL string directly into a raw SQL `LIKE` clause.
    7. The database will execute the query with the injected SQL, potentially leading to data extraction, modification, or other malicious actions.

- **Impact:**
    Critical. Successful SQL injection can lead to:
    - **Data Breach:** Unauthorized access to sensitive data stored in the database.
    - **Data Manipulation:** Modification or deletion of data, leading to data integrity issues.
    - **Account Takeover:** In some cases, it might be possible to escalate privileges or gain access to other user accounts.
    - **System Compromise:** In severe cases, depending on database permissions and application setup, it could potentially lead to broader system compromise.

- **Vulnerability Rank:** critical

- **Currently implemented mitigations:**
    None. The provided code does not implement any sanitization or escaping of string literals specifically to prevent SQL injection in `LIKE` clauses.

- **Missing mitigations:**
    - **Input Sanitization/Escaping:**  String literals used in `LIKE` clauses within DjangoQL queries should be properly sanitized or escaped before being incorporated into raw SQL queries. This could involve escaping special characters that have meaning in SQL `LIKE` patterns (e.g., `%`, `_`, `\`).
    - **Parameterized Queries (for LIKE):** Ideally, even for `LIKE` clauses, parameterized queries should be used to separate SQL code from user-provided data. However, directly parameterizing the pattern in `LIKE` might not be straightforward across all database backends. Escaping is a more practical immediate mitigation for `LIKE`.
    - **Content Security Policy (CSP):** While not a direct mitigation for SQL injection, a strong CSP can help limit the impact of successful attacks by restricting the actions an attacker can take even if they manage to inject malicious code.

- **Preconditions:**
    - A Django application is using the DjangoQL library.
    - The application exposes a DjangoQL search interface to external users, either through Django Admin or custom views.
    - The application uses string comparison operators (`startswith`, `endswith`, `~`, `!~`, `not startswith`, `not endswith`, `!~`) in its DjangoQL queries.

- **Source code analysis:**

    1. **`djangoql/lexer.py`:** The lexer correctly identifies string literals, including escaped characters, but does not perform any sanitization for SQL `LIKE` context.
    ```python
    @TOKEN(r'\"(' + re_escaped_char +
           '|' + re_escaped_unicode +
           '|' + re_string_char + r')*\"')
    def t_STRING_VALUE(self, t):
        t.value = t.value[1:-1]  # cut leading and trailing quotes ""
        return t
    ```
    The string literal value is extracted but no SQL escaping is applied.

    2. **`djangoql/parser.py`:** The parser constructs the AST, including string literals, without modification.
    ```python
    def p_string(self, p):
        """
        string : STRING_VALUE
        """
        p[0] = Const(value=unescape(p[1]))
    ```
    The `unescape` function handles Python string escapes but not SQL `LIKE` escapes.

    3. **`djangoql/schema.py`:** The schema validation focuses on data types and field existence but does not validate the *content* of string literals for SQL injection risks.

    4. **`djangoql/queryset.py`:** The `build_filter` function constructs Django ORM `Q` objects. For string comparisons (`~`, `!~`, `startswith`, `endswith`, and their negated forms), it uses `icontains`, `istartswith`, `iendswith` lookups, which translate to `LIKE` in SQL. The string literal is directly passed into the ORM lookup without escaping for `LIKE` context.
    ```python
    def get_operator(self, operator):
        """
        Get a comparison suffix to be used in Django ORM & inversion flag for it
        ...
        """
        op = {
            '=': '',
            '>': '__gt',
            '>=': '__gte',
            '<': '__lt',
            '<=': '__lte',
            '~': '__icontains', # <--- icontains, istartswith, iendswith use LIKE
            'in': '__in',
            'startswith': '__istartswith', # <--- icontains, istartswith, iendswith use LIKE
            'endswith': '__iendswith', # <--- icontains, istartswith, iendswith use LIKE
        }.get(operator)
        if op is not None:
            return op, False
        op = {
            '!=': '',
            '!~': '__icontains', # <--- icontains, istartswith, iendswith use LIKE
            'not in': '__in',
            'not startswith': '__istartswith', # <--- icontains, istartswith, iendswith use LIKE
            'not endswith': '__iendswith', # <--- icontains, istartswith, iendswith use LIKE
        }[operator]
        return op, True

    def get_lookup(self, path, operator, value):
        """
        Performs a lookup for this field with given path, operator and value.
        ...
        """
        search = '__'.join(path + [self.get_lookup_name()])
        op, invert = self.get_operator(operator)
        q = models.Q(**{'%s%s' % (search, op): self.get_lookup_value(value)}) # <--- value is used directly in Q object
        return ~q if invert else q
    ```
    The value from the parsed string literal is directly placed into the `Q` object, which will be used by Django ORM to construct the SQL query. Django ORM generally parameterizes values, but for `LIKE` patterns, the pattern itself (including `%`, `_`) is treated as part of the SQL command and not fully parameterized in all database backends, making it vulnerable if not escaped.

- **Security test case:**

    **Pre-requisites:**
    - Set up the `test_project` from the provided files.
    - Create a superuser and log in to the Django admin panel.
    - Ensure there are `Book` objects in the database.

    **Steps:**
    1. Access the Django Admin changelist view for `Book` objects (`/admin/core/book/`).
    2. Locate the DjangoQL search field.
    3. Enter the following malicious DjangoQL query into the search field:
       ```
       name startswith "') OR 1=1 --"
       ```
       or
       ```
       name ~ "') OR 1=1 --"
       ```
       or
       ```
       name endswith "') OR 1=1 --"
       ```
    4. Submit the search query.
    5. **Observe the results.** If the vulnerability is present, the query `1=1` will always be true, and the `--` comment will comment out the rest of the original query condition. This could result in all `Book` objects being returned, regardless of the actual intended search criteria. This behavior would indicate successful SQL injection.
    6. **(Advanced Test - Requires Database Logging):** Examine the raw SQL queries executed by Django in the database logs. You should see the injected SQL being directly embedded within the `LIKE` clause, confirming the SQL injection vulnerability. For example, the logged query might look something like:
       ```sql
       SELECT ... FROM core_book WHERE core_book.name LIKE '%) OR 1=1 --%';
       ```

This test case demonstrates a basic SQL injection. More sophisticated injection payloads can be crafted to extract data or perform other database operations.