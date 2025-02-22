### Vulnerability List

- Vulnerability Name: Potential DjangoQL Injection in `completion_demo` view
- Description: The `completion_demo` view in `/code/test_project/core/views.py` is vulnerable to DjangoQL injection. The view uses user-provided input from the `q` GET parameter to construct and execute DjangoQL queries against the `User` model. The `UserQLSchema` used in this view, while intending to limit searchable fields, by default includes all fields of the `User` and `Group` models except 'password'. This allows an attacker to craft malicious DjangoQL queries to access sensitive user attributes and related data that are not intended for public exposure.
- Impact: Information Disclosure. A remote attacker can potentially extract sensitive information about users, such as `is_staff`, `is_superuser`, `last_login`, `date_joined`, email addresses, and group memberships, by crafting specific DjangoQL queries. This information can be used for further attacks or unauthorized access.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - DjangoQL Schema validation: The project uses `DjangoQLSchema` to define searchable models and fields. However, the default schema in `completion_demo` is not restrictive enough.
    - Error handling: The code includes error handling for `DjangoQLError` exceptions, which prevents the application from crashing due to invalid queries, but it does not prevent information disclosure.
- Missing mitigations:
    - Restrictive DjangoQL Schema: The `UserQLSchema` in `/code/test_project/core/views.py` should be modified to explicitly include only non-sensitive fields of the `User` and `Group` models that are intended for public demonstration. For example, limit fields to `username`, `first_name`, `last_name`, and `groups.name`. Sensitive fields like `is_staff`, `is_superuser`, `last_login`, `date_joined`, and `email` should be explicitly excluded or not included in the schema.
    - Input sanitization: While DjangoQL is designed to handle query parsing safely, consider adding an additional layer of input sanitization to filter or validate the `q` parameter before passing it to `apply_search`. This can act as a defense-in-depth measure.
    - Access control: If the `completion_demo` view is intended only for internal demonstration purposes, consider removing it from public access or implementing authentication and authorization to restrict access to trusted users.
- Preconditions:
    - The application must be deployed and publicly accessible, with the `completion_demo` view exposed through a URL.
    - No Web Application Firewall (WAF) or other security controls are in place to filter or block malicious DjangoQL queries.
- Source code analysis:
    1. **Vulnerable Code Location:** `/code/test_project/core/views.py:22-37`
    2. **Vulnerability Step-by-step:**
        - The `completion_demo` view is accessed via a GET request.
        - The view retrieves the value of the `q` parameter from the request: `q = request.GET.get('q', '')`.
        - A Django queryset for `User` model is initialized: `query = User.objects.all().order_by('username')`.
        - If the `q` parameter is not empty, the `apply_search` function is called to filter the queryset based on the DjangoQL query provided in `q`: `query = apply_search(query, q, schema=UserQLSchema)`.
        - The `UserQLSchema` is defined in the same file (`/code/test_project/core/views.py:14-19`) and includes `User` and `Group` models without explicitly excluding any fields.
        - The `apply_search` function in `/code/djangoql/queryset.py` parses the DjangoQL query using `DjangoQLParser` and builds a Django ORM query based on the schema.
        - Because `UserQLSchema` does not restrict fields, an attacker can query against any field of the `User` and `Group` models, including sensitive ones.
        - The filtered queryset is then passed to the template for rendering, potentially displaying sensitive information based on the attacker's query.

    ```python
    # /code/test_project/core/views.py
    @require_GET
    def completion_demo(request):
        q = request.GET.get('q', '') # [Step 1] User input is taken from 'q' parameter
        error = ''
        query = User.objects.all().order_by('username') # [Step 2] Initialize User queryset
        if q:
            try:
                query = apply_search(query, q, schema=UserQLSchema) # [Step 3] Apply DjangoQL search with user input and UserQLSchema
            except DjangoQLError as e:
                query = query.none()
                error = str(e)
        # ... rest of the view ...
    ```

    ```python
    # /code/test_project/core/views.py
    class UserQLSchema(DjangoQLSchema): # [Step 4] UserQLSchema definition (not restrictive enough)
        include = (User, Group)
        suggest_options = {
            Group: ['name'],
        }
    ```

- Security test case:
    1. Deploy the `test_project` application to a publicly accessible server.
    2. Access the `completion_demo` view by navigating to the root URL `/`.
    3. Construct a malicious URL to test for information disclosure by querying for users with `is_staff = True`. For example, append the following query string to the URL: `?q=is_staff=True`. The full URL would look like: `http://<your-deployed-app-url>/?q=is_staff=True`.
    4. Examine the search results displayed on the page. If the results only show users who are staff members (i.e., `is_staff` is True), this indicates that the query was successfully executed and sensitive information based on `is_staff` is accessible.
    5. Further test by querying other sensitive fields like `is_superuser=True`, `last_login > "2024-01-01"`, or even accessing related fields like `groups.name = "Administrators"` to confirm the extent of information disclosure.
    6. Observe the response. If you can filter users based on these sensitive attributes, the application is vulnerable to DjangoQL injection and information disclosure.