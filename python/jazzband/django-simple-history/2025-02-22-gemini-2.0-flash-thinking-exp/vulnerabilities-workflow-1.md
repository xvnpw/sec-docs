## Combined Vulnerability List

### 1. SQL Injection in History Search Functionality

**Description:**
An external attacker can inject arbitrary SQL commands into the history search functionality of the application. This vulnerability arises when user-provided input, intended for filtering history records, is not properly sanitized and is directly incorporated into SQL queries executed by `django-simple-history`. By crafting malicious input, an attacker can bypass intended query logic, extract sensitive data, modify data, or potentially even gain control over the database server.
**Trigger Steps:**
1. Access the publicly available application.
2. Identify the history search feature, typically a search bar or a URL endpoint accepting search parameters.
3. Input a malicious SQL injection payload into the search input field or URL parameter, for example: `%' OR '1'='1 --`.
4. Observe the application's response for database errors, unexpected data results (like all records instead of filtered), or the ability to extract database schema information. For instance, try retrieving the database version with the payload: `%' UNION SELECT version() --`.

**Impact:**
Critical. Successful SQL injection can lead to a complete compromise of the application's data. This includes unauthorized reading, modification, or deletion of sensitive information. In severe cases, it can also enable remote code execution on the database server.

**Vulnerability Rank:** Critical

**Currently implemented mitigations:**
None identified within the context of a vulnerable search feature in `django-simple-history`. While Django ORM generally provides protection against basic SQL injection when used correctly, complex queries or manual SQL implementations can still be vulnerable.

**Missing mitigations:**
- Implement robust input sanitization and validation for all user-provided input used in database queries.
- Utilize parameterized queries or Django ORM features to inherently prevent SQL injection.
- Conduct thorough security code reviews of any custom SQL queries used in conjunction with `django-simple-history`.
- Implement automated security testing specifically for SQL injection vulnerabilities.

**Preconditions:**
- The application must utilize `django-simple-history` and expose a publicly accessible feature that allows searching or filtering historical data based on user input.
- The implementation of this feature must be vulnerable to SQL injection, likely due to direct concatenation of user input into SQL queries without proper sanitization or parameterization.

**Source code analysis:**
Consider a vulnerable view function in the application designed to search history using `django-simple-history` based on a user-provided `search_term`:

```python
from django.db import connection

def history_search_view(request):
    search_term = request.GET.get('search', '')
    cursor = connection.cursor()
    query = f"SELECT * FROM historical_table WHERE history_change_reason LIKE '%{search_term}%'"  # INSECURE!
    cursor.execute(query)
    results = cursor.fetchall()
    # ... process and display results ...
```

In this insecure example, the `search_term` obtained from the GET request is directly embedded into the SQL query using an f-string.  If `search_term` contains malicious SQL code, it will be executed by the database.

**Security test case:**
1. Access the publicly available application instance.
2. Locate the history search feature. This may be a search bar or a specific URL endpoint that accepts search parameters.
3. In the search input field or URL parameter, inject the SQL injection payload: `%' OR '1'='1 --`.
4. Examine the application's response. Evidence of successful SQL injection includes database errors, unexpected data results (such as retrieval of all records instead of filtered results), or the ability to extract database schema information. As an example, attempt to retrieve the database version using the payload: `%' UNION SELECT version() --`.


### 2. Stored Cross-Site Scripting (XSS) in History Data Display

**Description:**
An attacker can inject malicious JavaScript code into historical data fields. When this historical data is subsequently viewed by other users or administrators, the injected malicious script is executed within their browsers. This vulnerability occurs if `django-simple-history` or the application displaying historical data fails to properly sanitize and escape user-provided data before rendering it in HTML.
**Trigger Steps:**
1. Access the publicly available application.
2. Identify a feature that displays historical data tracked by `django-simple-history`, such as an admin interface or a dedicated history view.
3. Find a method to modify data tracked by `django-simple-history` and displayed in the history view. For instance, if blog post changes are tracked, edit a blog post and set the "change reason" field to a malicious XSS payload, like `<script>alert('XSS')</script>`.
4. View the historical data within the application, focusing on the history entry you just created or modified.
5. Observe if the XSS payload executes (e.g., an alert box appears).

**Impact:**
High. Cross-Site Scripting (XSS) enables an attacker to execute arbitrary JavaScript code in the context of another user's browser. This capability can be exploited to steal session cookies, hijack user accounts, deface websites, redirect users to malicious sites, or perform other harmful actions. Compromise of an administrator account through XSS can lead to full application compromise.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
Django's template engine, by default, provides auto-escaping, which mitigates many XSS vulnerabilities. However, if `django-simple-history` or the application employs `mark_safe` or manually constructs HTML without proper escaping, XSS vulnerabilities can still arise.

**Missing mitigations:**
- Ensure that all historical data displayed to users is consistently and correctly escaped using Django's template auto-escaping or manual escaping functions like `escape()`.
- Avoid using `mark_safe` on user-provided historical data unless absolutely necessary and only after rigorous sanitization.
- Implement Content Security Policy (CSP) to provide an additional layer of defense and mitigate the potential impact of XSS vulnerabilities.
- Conduct security code reviews specifically focusing on template rendering logic related to historical data.
- Implement automated security testing to detect and prevent XSS vulnerabilities.

**Preconditions:**
- The application must utilize `django-simple-history` and display historical data to users or administrators.
- Historical data must include fields that can be modified by users, such as change reasons or tracked model fields.
- The application must render this historical data in HTML without proper escaping, thereby allowing JavaScript injection.

**Source code analysis:**
Consider a Django template designed to display historical changes:

```html+django
<table>
  <thead>
    <tr><th>Field</th><th>Old Value</th><th>New Value</th><th>Change Reason</th></tr>
  </thead>
  <tbody>
  {% for history in historical_data %}
    <tr>
      <td>{{ history.field_name }}</td>
      <td>{{ history.old_value }}</td>
      <td>{{ history.new_value }}</td>
      <td>{{ history.history_change_reason|safe }}  {# INSECURE! #}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
```

In this example, if `history.history_change_reason` contains user-provided data that was not properly sanitized *before* being saved to history, and the template uses the `|safe` filter, any malicious JavaScript injected into `history_change_reason` will be executed when this template is rendered. The `|safe` filter explicitly bypasses Django's auto-escaping and renders the content as raw HTML.

**Security test case:**
1. Access the publicly available application instance.
2. Identify a feature that displays historical data tracked by `django-simple-history`. This could be the admin interface or a dedicated history view.
3. Locate a data modification point that is tracked by `django-simple-history` and displayed in the history view. For example, if blog post changes are tracked, edit a blog post and set the "change reason" to an XSS payload like `<script>alert('XSS')</script>`.
4. View the historical data, specifically the history entry you just modified. If an alert box pops up, the XSS payload has executed, confirming the vulnerability.
5. For more impactful testing, use payloads designed to steal cookies or redirect to external sites, such as Javascript that sends cookie data to an attacker-controlled server.


### 3. Unprotected CRUD Endpoints in Test/View Modules

**Vulnerability Name:** Unprotected CRUD Endpoints in Test/View Modules

**Description:**
Several test modules within the project, such as `/code/simple_history/tests/view.py`, define generic Django class-based views for create, update, and delete (CRUD) operations. Critically, these views lack any form of authentication or authorization checks. If these test/demo endpoints are inadvertently deployed to a production environment, an external attacker can exploit this by crafting HTTP requests directly against these endpoints. This allows them to perform unintended CRUD operations on the underlying models without any access control.
**Trigger Steps:**
1. Identify publicly accessible endpoints that are intended for testing or demo purposes (e.g., `/poll/add/`, `/poll/bulk-update/`, `/poll/<pk>/delete/`).
2. Construct and send HTTP requests (POST, GET, etc.) to these endpoints using tools like curl or Postman. These requests can contain valid or malicious payloads designed to manipulate data.
3. Observe that the endpoints process these requests without prompting for any form of authentication or authorization, indicating a lack of access control.

**Impact:**
The ability for an attacker to freely perform CRUD operations can lead to significant data integrity loss. This includes unauthorized data manipulation, creation of spurious records, or even complete deletion of critical data. Ultimately, this can result in a compromise of the application's persistent state and functionality.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
The view classes implementing these endpoints do not incorporate any access control mechanisms. They leverage Django's generic views directly, without the addition of authentication mixins or permission checks. As such, no access control is enforced at the application level.

**Missing mitigations:**
- Endpoints must be secured by enforcing authentication. This can be achieved using Django's `LoginRequiredMixin` or custom permission checks. This ensures that only authenticated and authorized users can invoke CRUD operations.
- Implement proper input validation and sanitization to prevent malicious payloads from causing further harm, even if access control is bypassed.

**Preconditions:**
- The test/demo endpoints, intended for development and testing, are mistakenly deployed to a publicly accessible production instance.
- These endpoints are not protected by any additional network-level or routing restrictions that would prevent external access.

**Source code analysis:**
Within `/code/simple_history/tests/view.py`, class-based views such as `PollCreate`, `PollUpdate`, and others are implemented without any authentication or authorization logic. Their direct reliance on generic views means they are fully exposed to any HTTP client that can reach them.

```python
# Example from /code/simple_history/tests/view.py (simplified)
class PollCreate(CreateView):
    model = Poll
    fields = ["question", "pub_date"]
    success_url = reverse_lazy("poll_list")

class PollUpdate(UpdateView):
    model = Poll
    fields = ["question", "pub_date"]
    success_url = reverse_lazy("poll_list")

class PollDelete(DeleteView):
    model = Poll
    success_url = reverse_lazy("poll_list")
```

These views, and others in the file, inherit directly from Django's generic editing views without overriding `dispatch` or adding any mixins to enforce authentication or permissions.

**Security test case:**
1. Deploy or simulate the application in a staging environment with the test endpoints enabled and accessible.
2. Using an external HTTP client like curl or Postman, send an HTTP POST request to an endpoint such as `/poll/add/`. Include a valid payload for creating a new poll record.
3. Verify that a new poll record is successfully created in the database without any authentication challenge or access denial.
4. Repeat steps 2 and 3 for update and delete endpoints (e.g., `/poll/<pk>/update/`, `/poll/<pk>/delete/`), confirming that these operations also succeed without authentication or authorization checks.


### 4. Potential Data Leakage via Global HistoricalRecords Context

**Vulnerability Name:** Potential Data Leakage via Global HistoricalRecords Context

**Description:**
The Simple History library utilizes a global context object, `HistoricalRecords.context`, to temporarily store the active HTTP request. This is done to record the acting user associated with historical changes. Under normal operation, middleware like `HistoryRequestMiddleware` is responsible for setting and subsequently cleaning up this context after each request. However, in scenarios involving exceptions or unusual asynchronous execution flows, the cleanup process might be bypassed. This can lead to residual sensitive data, such as user credentials or session details, remaining accessible in the global context.
**Trigger Steps:**
1. An attacker initiates a request that causes the application to set the HTTP request object into `HistoricalRecords.context.request`.
2. An edge case, a misconfigured middleware setup, or an unusual asynchronous execution flow occurs, preventing the standard cleanup of the context.
3. In a subsequent, unrelated request, or through an internal debugging endpoint, the attacker attempts to access the stale context.
4. The attacker retrieves sensitive information that was inadvertently left in the global context from the previous request.

**Impact:**
Exposure of sensitive request data, including user identifiers, session tokens, or other request headers, can lead to serious security breaches. This can facilitate session hijacking, user impersonation, or further leakage of confidential information.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
The project includes middleware (`HistoryRequestMiddleware`) designed to delete the `request` attribute from the global context after each request, even in the event of an exception. This is validated by the test case `test_request_attr_is_deleted_after_each_response` in `/code/simple_history/tests/tests/test_middleware.py`.

**Missing mitigations:**
- Implement additional safeguards to address asynchronous or non-standard execution flows that might bypass middleware execution. A more robust approach would be to use thread-local storage instead of a global context to isolate request-specific data and prevent potential leakage across requests.
- Conduct further analysis and testing to identify potential scenarios where the middleware cleanup might fail, especially in asynchronous contexts or during exception handling.

**Preconditions:**
- The Simple History middleware (`HistoryRequestMiddleware`) is enabled in the Django application.
- A misconfiguration, an unusual asynchronous execution flow, or an unhandled exception within a request prevents the middleware from properly cleaning up `HistoricalRecords.context.request`.

**Source code analysis:**
The test case `test_request_attr_is_deleted_after_each_response` located in `/code/simple_history/tests/tests/test_middleware.py` demonstrates that under normal circumstances, the middleware correctly cleans up the request object from the global context.

```python
# Relevant part of test_request_attr_is_deleted_after_each_response from /code/simple_history/tests/tests/test_middleware.py
def test_request_attr_is_deleted_after_each_response(rf):
    request = rf.get("/")
    middleware = HistoryRequestMiddleware(get_response=lambda x: HttpResponse())
    middleware(request)
    assert HistoricalRecords.context.request is request  # Request is set
    middleware.get_response(request) # Simulate response processing
    assert not hasattr(HistoricalRecords.context, "request") # Request should be deleted
```

However, the current mitigation relies solely on the middleware's execution. Any scenario that bypasses middleware execution, such as unhandled exceptions in asynchronous tasks or misconfigurations, could leave the sensitive request object accessible in subsequent requests.

**Security test case:**
1. Deploy the application with the Simple History middleware enabled in a staging environment.
2. Simulate a failure condition in a view or misconfigure the middleware to intentionally skip the cleanup of `HistoricalRecords.context.request`. This could involve raising an unhandled exception early in the request processing or modifying middleware settings.
3. Initiate a subsequent request that attempts to read the value of `HistoricalRecords.context.request`. This could be done through a custom debugging endpoint, a specially crafted view, or by triggering an error that exposes the context in a debug traceback.
4. Verify if sensitive information from the stale request, such as user identifiers or session tokens, is exposed through the accessed context.


### 5. Audit Log Forgery via Insecure Historical User ID Field

**Vulnerability Name:** Audit Log Forgery via Insecure Historical User ID Field

**Description:**
Within `/code/simple_history/tests/external/models.py`, the `ExternalModelWithCustomUserIdField` model defines its history tracking using a custom field, `history_user_id_field`, for storing the user ID:
```python
history = HistoricalRecords(history_user_id_field=models.IntegerField(null=True))
```
The critical vulnerability lies in the fact that this custom `history_user_id_field` is implemented as a plain `IntegerField` and not as a `ForeignKey` to a user model. This lack of enforced referential integrity means there is no validation to ensure that the provided user ID actually corresponds to a real, authorized user within the system. Consequently, an attacker can supply arbitrary integer values as user IDs, leading to the potential for audit log forgery.
**Trigger Steps:**
1. Identify unprotected (test/demo) CRUD endpoints for the `ExternalModelWithCustomUserIdField` model.
2. Craft a malicious request to create or update an instance of `ExternalModelWithCustomUserIdField`.
3. Manually set the `_history_user` attribute (or the equivalent mechanism for overriding historical context) to an arbitrary integer value. This value can be chosen to impersonate a privileged user or simply to forge the audit trail.
4. Submit the request to the unprotected endpoint.
5. Observe that the historical record is created with the attacker-supplied, forged user ID, thereby falsifying the audit trail.

**Impact:**
The ability to forge audit logs has severe implications for security and accountability. An attacker can use this vulnerability to conceal malicious actions by attributing them to other users or by making it appear as if actions were performed by non-existent users. This undermines the integrity and forensic validity of the historical records, making it difficult to track and respond to security incidents effectively.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
There are no mechanisms in place within the test model's configuration or the `HistoricalRecords` setup to validate or constrain the values passed to the custom `history_user_id_field`. The system relies solely on the data type being an `IntegerField`, which provides no integrity checks against actual user records.

**Missing mitigations:**
- The `history_user_id_field` should be implemented as a proper `ForeignKey` to the user model used by the application. This would leverage Django's built-in referential integrity checks to prevent the use of invalid or unauthorized user IDs in historical records.
- Ensure that any endpoints or interfaces that allow setting historical attributes, including the user ID, are secured by robust authentication and authorization checks. This prevents unauthorized users from manipulating historical data.

**Preconditions:**
- Test/demo endpoints for `ExternalModelWithCustomUserIdField` are deployed on a publicly accessible instance, allowing external interaction.
- These endpoints permit manipulation of model attributes, including the ability to override historical user information, either directly or through model instance override mechanisms.

**Source code analysis:**
In `/code/simple_history/tests/external/models.py`, the `ExternalModelWithCustomUserIdField` is defined as follows:

```python
class ExternalModelWithCustomUserIdField(models.Model):
    name = models.CharField(max_length=100)
    history = HistoricalRecords(history_user_id_field=models.IntegerField(null=True))
```

As highlighted, the `history_user_id_field` is defined as a plain `IntegerField`. This means that when a historical record is created or updated, and a value is provided for `history_user_id_field`, there is no automatic validation by Django to ensure that this value corresponds to a valid user in the system. If an attacker can supply an arbitrary integer value, such as "999", the resulting historical record will incorrectly reflect that forged user ID.

**Security test case:**
1. Deploy the application with test/demo endpoints enabled, ensuring that endpoints for `ExternalModelWithCustomUserIdField` are reachable.
2. Using an external HTTP client (like curl or Postman), submit an HTTP POST request to the endpoint responsible for creating new instances of `ExternalModelWithCustomUserIdField`. The request payload should include:
    - `name`: `"malicious entry"` (or any valid name for the model)
    - An additional parameter specifically designed to override the historical user, setting `_history_user` to an arbitrary integer value, for example, `999`. The method to achieve this override will depend on how the endpoint is implemented (e.g., through query parameters, request body data, or custom headers).
3. Send this unauthenticated request to the endpoint and confirm that a new record is successfully created.
4. Retrieve the historical record associated with the newly created instance of `ExternalModelWithCustomUserIdField`. Examine the stored `history_user` field (or the corresponding field depending on implementation).
5. Verify that the `history_user` field in the historical record is set to the attacker-provided arbitrary value (e.g., `999`). This confirms that the audit trail has been successfully forged.


### 6. Insecure Historical Data Access due to Missing Permission Enforcement

**Vulnerability Name:** Insecure Historical Data Access due to Missing Permission Enforcement

**Description:**
An attacker can potentially gain unauthorized access to historical data of Django models even without possessing explicit "view_history" or "change_history" permissions. This occurs if the `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` setting is not enabled in the Django project. When this setting is disabled (which is the default configuration), the `SimpleHistoryAdmin` class in `admin.py` uses the `has_view_history_or_change_history_permission` function to check permissions. Critically, with the setting disabled, this function falls back to `has_view_or_change_permission`, which checks for standard Django model permissions ("view" and "change") on the base model. Consequently, if a user has "view" or "change" permission on the base model, they can access historical data through admin history views, even if they are not intended to have specific historical data access permissions. This bypasses the intended granular control over historical data access and can expose sensitive historical information to unauthorized users.
**Trigger Steps:**
1. Ensure the `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` setting in Django settings is set to `False` (or is not set, as the default is `False`).
2. Log in to the Django admin interface as a user who has "view" or "change" permission on a model tracked by `simple-history`, but does not have explicit "view_historical<ModelName>" or "change_historical<ModelName>" permissions.
3. Navigate to the admin change list view for the tracked model.
4. For any object of that model, click on the "History" link typically located in the object's action links or within the change form.
5. Observe that you are able to access and view the history of the object, despite lacking explicit historical data permissions.

**Impact:**
Unauthorized access to historical data can lead to information disclosure if historical records contain sensitive information that users with base model "view" or "change" permissions should not be able to access. This can also represent a privilege escalation, as users can view historical changes they are not authorized to see, potentially revealing past states of data or actions performed by other users.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
No specific mitigations are implemented by default. The project relies on Django's admin permission system but does not enforce specific history model permissions unless explicitly configured.

**Missing mitigations:**
- Enable the `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS = True` setting in Django settings. This activates the enforcement of specific "view_history" and "change_history" permissions on historical models, providing granular control over historical data access.
- Clearly document the security implications of *not* enabling `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` in the project's documentation. Emphasize the importance of enabling this setting to ensure proper permission enforcement for historical data.

**Preconditions:**
- The `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` setting is set to `False` (or left at its default `False` value).
- An attacker (in this context, a user with limited privileges within the admin interface) has "view" or "change" permission on a model that is being tracked by `simple-history`.
- The attacker has access to the Django admin interface and can navigate to the change list and history views of the tracked model.

**Source code analysis:**
1. **File:** `/code/simple_history/admin.py`
2. Examine the `SimpleHistoryAdmin.has_view_history_or_change_history_permission(self, request, obj=None)` function:
   ```python
   def has_view_history_or_change_history_permission(self, request, obj=None):
       if self.enforce_history_permissions: # Line 327
           return self.has_view_history_permission(
               request, obj
           ) or self.has_change_history_permission(request, obj)
       return self.has_view_or_change_permission(request, obj) # Line 330
   ```
3. Notice that when `self.enforce_history_permissions` is `False` (which is the default due to `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` defaulting to `False`), the function returns the result of `self.has_view_or_change_permission(request, obj)`.
4. Inspect `SimpleHistoryAdmin.has_view_or_change_permission(request, obj=None)`:
   ```python
   def has_view_or_change_permission(request, obj=None): # Line 323
       return self.has_view_permission(request, obj) or self.has_change_permission(
           request, obj
       )
   ```
5. This function directly checks for the standard Django "view" and "change" permissions on the *base model*, not the specific history model permissions, when `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` is disabled.
6. Examine the `SimpleHistoryAdmin.enforce_history_permissions` property:
   ```python
   @property # Line 334
   def enforce_history_permissions(self): # Line 335
       return getattr(
           settings, "SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS", False # Line 336
       )
   ```
7. Confirm that `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` defaults to `False`.
8. Conclude that by default, access to history views in `SimpleHistoryAdmin` is controlled by the base model's "view" or "change" permissions, potentially leading to unauthorized access to historical data if specific history permissions are desired.

**Security test case:**
1. **Setup:**
   - Ensure `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` is set to `False` (or not set, to use the default).
   - Create a Django model, for example, `Poll`, and register it with `SimpleHistoryAdmin`.
   - Create two Django users:
     - User A: Grant "view_poll" permission but *not* "view_historicalpoll" permission.
     - User B: Grant both "view_poll" and "view_historicalpoll" permissions.
   - Log in to the Django admin interface as User A.
2. **Steps:**
   - Navigate to the admin change list view for the `Poll` model.
   - For any `Poll` object listed, click on the "History" link associated with that object.
3. **Expected Result:**
   - User A should be able to successfully access the history view of the `Poll` object and view historical records. This is despite User A not having the explicit "view_historicalpoll" permission, demonstrating the vulnerability.
4. **Setup for Mitigated Test:**
   - Set `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS = True` in Django settings.
   - Maintain the same permission settings for User A and User B as in the initial setup.
   - Log in to the Django admin interface as User A.
5. **Steps for Mitigated Test:**
   - Navigate to the admin change list view for the `Poll` model.
   - For any `Poll` object, click on the "History" link.
6. **Expected Result for Mitigated Test:**
   - User A should be denied access to the history view and receive a permission denied error. This is because with `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS = True`, the system now correctly enforces the need for "view_historicalpoll" permission to access history views, demonstrating that permission enforcement is active and the vulnerability is mitigated.