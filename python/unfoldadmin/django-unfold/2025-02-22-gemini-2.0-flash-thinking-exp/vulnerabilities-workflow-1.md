Here is the combined list of vulnerabilities, formatted as markdown with main paragraphs and subparagraphs for each vulnerability:

### Combined Vulnerability List

#### Open Redirect in Admin Actions

* **Vulnerability Name:** Open Redirect in Admin Actions
* **Description:**
    The `ModelAdmin.response_change` and `ModelAdmin.response_add` methods in `unfold/admin.py` redirect to the URL specified in the `next` GET parameter without proper validation. An attacker can craft a malicious URL with a `next` parameter pointing to an external website. When an admin user performs a change or add action and is redirected, they could be redirected to the attacker's site, potentially leading to phishing or other attacks.
    1. Attacker crafts a malicious URL to the admin change/add form with a `next` parameter pointing to an attacker-controlled website (e.g., `https://malicious.example.com`).
    2. Attacker sends this malicious URL to an authenticated admin user or tricks them into accessing it (e.g., via phishing email or social engineering).
    3. Admin user, while logged into the admin panel, clicks on the malicious link and accesses the admin change/add form with the `next` parameter.
    4. Admin user submits the change/add form.
    5. The application, upon successful change/add action, redirects the admin user to the URL specified in the `next` parameter, which is the attacker-controlled website `https://malicious.example.com`.
* **Impact:**
    High. An attacker can redirect admin users to a malicious website after they perform an action in the admin panel. This can be used for phishing attacks, where the attacker can trick admin users into entering their credentials or other sensitive information on a fake login page or similar, or to perform other malicious actions on behalf of the admin user if the attacker-controlled site is designed to do so.
* **Vulnerability Rank:** high
* **Currently implemented mitigations:**
    None. The code directly redirects to the `next` parameter without any validation.
* **Missing mitigations:**
    Input validation and sanitization for the `next` parameter. The application should validate that the `next` URL is a safe URL, such as a URL on the same domain or a predefined trusted domain list. A safer approach would be to remove the redirection to the `next` parameter altogether if it's not a critical feature, or use Django's `is_safe_url` to validate the target URL.
* **Preconditions:**
    1. The attacker needs to be able to craft a URL to the Django admin change/add form.
    2. An authenticated admin user needs to be logged into the Django admin panel.
    3. The admin user needs to be tricked into accessing the crafted malicious URL and submitting a change/add form.
* **Source code analysis:**
    File: `/code/src/unfold/admin.py`
    ```python
        def response_change(self, request: HttpRequest, obj: Model) -> HttpResponse:
            res = super().response_change(request, obj)
            if "next" in request.GET:
                return redirect(request.GET["next"]) # Vulnerability: Open redirect
            return res

        def response_add(
            self, request: HttpRequest, obj: Model, post_url_continue: Optional[str] = None
        ) -> HttpResponse:
            res = super().response_add(request, obj, post_url_continue)
            if "next" in request.GET:
                return redirect(request.GET["next"]) # Vulnerability: Open redirect
            return res
    ```
    The `response_change` and `response_add` methods in `ModelAdmin` class directly use `redirect(request.GET["next"])` without any validation. This allows an attacker to control the redirection target by providing a `next` parameter in the GET request, leading to an open redirect vulnerability.
* **Security test case:**
    1.  Access the Django admin login page and log in as an administrator.
    2.  Navigate to the change list page of any model (e.g., Users - `/admin/example/user/`).
    3.  Click on the "Add User" button to access the add form (e.g., `/admin/example/user/add/`).
    4.  In the browser's address bar, append the following parameter to the URL: `?next=https://malicious.example.com`. The URL should now look similar to: `/admin/example/user/add/?next=https://malicious.example.com`.
    5.  Fill out the required fields in the "Add user" form (e.g., Username, Password, etc.).
    6.  Click the "Save" button.
    7.  Observe that instead of being redirected to the user change list page or the newly created user's change form, you are redirected to `https://malicious.example.com`.

#### Insecure Dynamic Callback Execution via UNFOLD Configuration

* **Vulnerability Name:** Insecure Dynamic Callback Execution via UNFOLD Configuration
* **Description:**
    The project’s configuration (in settings and documentation files) lets administrators specify callback functions as strings (for keys such as `ENVIRONMENT`, `ENVIRONMENT_TITLE_PREFIX`, `TABS`, `SITE_ICON`, and `SITE_LOGO`). Later these strings are passed to Django’s dynamic import mechanism (e.g. via an import_string–like helper) and then executed with the current request context. If an attacker is able to modify these settings (for example, through a misconfigured configuration management tool, an insecure admin interface that allows settings override, or via filesystem tampering), they could cause arbitrary Python code to run with full server privileges.
* **Impact:**
    Critical. An attacker who is able to change the UNFOLD configuration may execute arbitrary code on the server (remote code execution), thereby compromising the entire system.
* **Vulnerability Rank:** critical
* **Currently implemented mitigations:**
    - The project assumes these UNFOLD settings are hard‑coded in the server’s settings file, which is normally not user‑modifiable at runtime.
    - Standard Django deployment practices (including proper file system and settings file protection) help mitigate external tampering.
* **Missing mitigations:**
    - No runtime validation, whitelisting, or explicit sanitization is applied to callback strings prior to dynamic import.
* **Preconditions:**
    - The attacker must be able to alter (or inject) configuration values—this might occur via an insecure configuration management process, an over‑permissive admin tool, or filesystem compromise.
* **Source code analysis:**
    - Documentation (see *docs/configuration/settings.md*) and tests (such as *tests/test_environment.py*) show that keys like `ENVIRONMENT`, `ENVIRONMENT_TITLE_PREFIX`, and `TABS` expect string values that are subsequently passed to Django’s `import_string` (or similar) function without any further checks.
* **Security test case:**
    - In a controlled test environment, override the UNFOLD configuration (using, for example, Django’s `@override_settings`) to substitute one of the callback settings with the path to a test function (e.g. one that writes a marker to a log file).
    - Trigger a view (for example, by accessing an admin page that calls `each_context`) and verify that the test function is executed.
    - Then substitute the callback with one that attempts to execute a command such as `os.system("id")` and observe that arbitrary Python code execution is indeed possible.

#### Potential Stored Cross‑Site Scripting (XSS) via WysiwygWidget

* **Vulnerability Name:** Potential Stored Cross‑Site Scripting (XSS) via WysiwygWidget
* **Description:**
    The Unfold admin theme uses a custom rich‑text widget (the WysiwygWidget based on the Trix editor) for editing large text fields. If an attacker (or a compromised administrator) submits content that includes malicious JavaScript (e.g. `<script>alert('XSS')</script>`) and that content is later rendered without proper sanitization (for example, in a readonly change‑form or list view), the browser may execute the injected script.
* **Impact:**
    High. An attacker exploiting stored XSS can execute arbitrary JavaScript in the context of any admin user viewing the affected field—potentially leading to session hijacking, defacement, or data exfiltration.
* **Vulnerability Rank:** high
* **Currently implemented mitigations:**
    - In most cases the widget is used in fields declared in `readonly_fields`, so Django’s autoescaping is normally active.
    - The admin interface is restricted to trusted administrators.
* **Missing mitigations:**
    - No built‑in sanitization is applied to the HTML content submitted through the WysiwygWidget.
    - There is no explicit filter or sanitizer (such as Bleach) applied before rendering stored HTML content in non‑editable contexts.
* **Preconditions:**
    - An attacker (or compromised admin) must be able to submit HTML content via the WysiwygWidget.
    - The malicious content must later be rendered in a view where it is not re‑escaped by Django’s templates.
* **Source code analysis:**
    - The widget defined in *src/unfold/contrib/forms/widgets.py* uses the Trix editor but does not integrate a sanitization library.
    - Documentation (see *docs/widgets/wysiwyg.md*) confirms the intended use of the widget for rich text but does not mention sanitation.
* **Security test case:**
    - Create a model field that employs the WysiwygWidget for input and is later rendered in a readonly admin view.
    - Log in as an administrator, and submit content containing a benign JavaScript payload (for example, `<script>alert("XSS")</script>`).
    - In a separate session (or browser), visit the page rendering this content and check if the script executes (e.g. observe an alert or log entry).
    - If the script runs, then the stored XSS vulnerability is confirmed and sanitization should be added.

#### Unescaped Output in Custom Tab Configuration

* **Vulnerability Name:** Unescaped Output in Custom Tab Configuration
* **Description:**
    The UNFOLD settings include a “TABS” configuration that accepts a list of dictionaries used to render custom navigation tabs through the `{% tab_list "page_name" %}` template tag. If the content provided for these tab items (such as the “title” or “link” fields) is not properly escaped before rendering, an attacker who can modify these settings may be able to inject arbitrary HTML or JavaScript into the admin interface.
* **Impact:**
    High. Injection of malicious HTML or JavaScript into the admin navigation could result in stored XSS. This would allow an attacker to execute code in the browser of any admin user viewing the navigation—potentially leading to session hijacking or other forms of privilege escalation.
* **Vulnerability Rank:** high
* **Currently implemented mitigations:**
    - Django’s default autoescaping is enabled in templates, meaning that unless the configuration values are explicitly marked “safe,” they will normally be escaped.
    - The documentation does not advise bypassing autoescaping when rendering custom tab content.
* **Missing mitigations:**
    - There is no explicit sanitization or whitelist enforcement to validate that the data provided for custom tabs is free of malicious markup.
    - In cases where developers have explicitly marked these configuration values as “safe” (for styling reasons), the risk of XSS is inadvertently introduced.
* **Preconditions:**
    - The attacker or a compromised administrator must be able to modify the UNFOLD “TABS” configuration (for example, via a misconfigured settings editor or insecure configuration management).
* **Source code analysis:**
    - The template tag `{% tab_list "page_name" %}` (defined in *src/unfold/templatetags/unfold.py*) directly renders the tab items from the config without performing additional sanitation.
    - Documentation (see *docs/tabs/dynamic.md*) indicates that the “TABS” configuration accepts arbitrary strings for tab titles and links.
* **Security test case:**
    - In a controlled environment, override the UNFOLD “TABS” configuration (using Django’s `@override_settings`) to include a tab item with an HTML payload (for example, set the title to `"<script>alert('XSS')</script>"`).
    - Load a page that includes the `{% tab_list "custom_page" %}` tag and inspect the rendered HTML source or observe behavior in the browser.
    - If the injected script executes instead of being escaped, then the vulnerability is confirmed and sanitization measures must be implemented.

#### Unrestricted File Download via Readonly URLField Widget

* **Vulnerability Name:** Unrestricted File Download via Readonly URLField Widget
* **Description:**
    1. An attacker can identify a URLField in the Django admin interface configured with `readonly_fields`.
    2. The URLField widget in django-unfold renders URLs as clickable links, even for file URLs.
    3. If a URLField points to a file resource that is intended to be protected or not publicly accessible, the readonly URLField widget in django-unfold will unintentionally provide a direct download link to this resource.
    4. By simply clicking the link in the admin panel (or crafting the URL manually if the link is predictable or exposed elsewhere), an attacker can bypass intended access controls and download the file.
* **Impact:**
    High. Confidentiality breach: Unauthorized access and download of potentially sensitive files linked in URLField attributes within the Django admin. Data exfiltration: Attackers could potentially automate the process to discover and download multiple files if URL patterns are predictable.
* **Vulnerability Rank:** high
* **Currently implemented mitigations:**
    None. The current implementation renders URLFields as clickable links without any checks on the URL scheme or target resource type.
* **Missing mitigations:**
    - Implement URL scheme validation in the `URLField` widget to restrict clickable links to safe schemes like `http` and `https` and prevent rendering clickable links for file-based schemes like `file://` or `data:`.
    - Introduce a configuration option to disable clickable links for `URLField` widgets in `readonly_fields` or to specifically whitelist safe URL schemes.
    - For sensitive file resources, developers should not rely on URLFields in readonly admin views as a security mechanism. Proper access control should be implemented at the application level, ensuring that file resources are protected and accessed only through authorized channels.
* **Preconditions:**
    - A Django model with a URLField that contains a URL pointing to a file resource.
    - The URLField is configured as `readonly_fields` in the Django admin ModelAdmin definition.
    - The file resource pointed to by the URL is not adequately protected by other access control mechanisms and is accessible if the direct URL is known.
* **Source code analysis:**
    - Based on the documentation, the rendering logic for URLFields is in the `_get_contents` method of `UnfoldAdminReadonlyField` class (file `/code/src/unfold/fields.py` - not in PROJECT FILES):
    ```python
    elif isinstance(f, models.URLField):
        return format_html(
            '<a href="{}" class="text-primary-600 dark:text-primary-500">{}</a>',
            value,
            value,
        )
    ```
    The code uses `format_html` for escaping, but it directly renders the URL as an `<a>` tag without validating the URL scheme. This allows any URL, including `file://` or URLs to unprotected media files, to become a clickable link in the admin, leading to potential unauthorized file downloads.
* **Security test case:**
    1. As an external attacker, identify a publicly accessible Django admin panel using django-unfold.
    2. Find a model with a `URLField` configured in `readonly_fields`. This might require some reconnaissance of the admin interface or publicly available information about the application's models.
    3. Observe the `URLField` in the readonly fields. If it's rendered as a clickable link, proceed.
    4. If the link points to a file (e.g., `/media/file.txt` or similar), click the link.
    5. Verify that the file is downloaded directly to your browser without any additional authentication or authorization checks.
    6. If successful, the attacker has confirmed the unrestricted file download vulnerability.

#### Potential Information Disclosure via Verbose Error Messages in Filters

* **Vulnerability Name:** Potential Information Disclosure via Verbose Error Messages in Filters
* **Description:**
    1. An attacker can interact with enhanced filters (Dropdown, Autocomplete, Numeric, Datetime, Text) in the Django admin changelist view.
    2. By providing crafted or invalid input to these filters, an attacker can attempt to trigger backend errors during filter processing.
    3. If the error handling in the custom filters is insufficient, verbose error messages from the backend (including database details, internal paths, or code snippets) might be exposed in the admin interface.
    4. An attacker can analyze these verbose error messages to gain sensitive information about the application's internal workings and potentially identify further vulnerabilities.
* **Impact:**
    High. Information disclosure: Exposure of sensitive application internals, database information, or server details through verbose error messages. Reconnaissance advantage: Detailed error messages can aid attackers in understanding the application's architecture and identifying potential weaknesses for exploitation.
* **Vulnerability Rank:** high
* **Currently implemented mitigations:**
    - Django's default DEBUG mode being disabled in production reduces general error verbosity but might not fully sanitize error messages in admin views.
    - Some filters (`RangeNumericFilter`, `RangeDateFilter`, `RangeDateTimeFilter`, `SingleNumericFilter`) have basic `try-except` blocks that return `None` on `ValueError` or `ValidationError`, but this is not comprehensive error handling.
* **Missing mitigations:**
    - Implement generic error handling in base filter classes to catch backend exceptions and replace verbose messages with user-friendly, generic errors.
    - Introduce logging for filter errors on the server-side for debugging and security monitoring without exposing details to the frontend.
    - Provide security documentation for developers on implementing robust error handling in custom filters.
* **Preconditions:**
    - The application uses custom filters provided by django-unfold (Dropdown, Autocomplete, Numeric, Datetime, Text) in the Django admin.
    - Filter implementations are susceptible to backend errors when processing specific user inputs.
    - Verbose error messages are not fully suppressed or sanitized in the admin interface in the deployed environment.
* **Source code analysis:**
    - In `unfold/contrib/filters/admin.py`, filters like `RangeNumericFilter` have `try-except` blocks in their `queryset` methods:
    ```python
    class RangeNumericFilter(RangeNumericMixin, admin.FieldListFilter):
        ...
        def queryset(self, request: HttpRequest, queryset: QuerySet) -> QuerySet:
            filters = {}
            ...
            try:
                return queryset.filter(**filters)
            except (ValueError, ValidationError):
                return None
    ```
    While this prevents crashes for `ValueError` and `ValidationError`, it does not handle other potential exceptions or ensure generic error messages are displayed to the user. Deeper error handling and sanitization of error responses are missing, which could lead to verbose error messages being displayed in the admin interface if other types of exceptions occur or if the error handling is bypassed.
* **Security test case:**
    1. As an external attacker, access a publicly available Django admin panel using django-unfold.
    2. Identify a changelist view that utilizes enhanced filters.
    3. Manipulate filter parameters in the URL or through the filter UI to cause a backend error. For example, for a `NumericFilter`, inputting non-numeric values, or for a `DateFilter`, inputting invalid date formats, or injecting SQL syntax in `TextFilter` if backend is vulnerable to SQL injection (assuming no input sanitization).
    4. Observe the response from the server. If a verbose error message is displayed in the admin interface, examine the message content.
    5. Analyze the error message for sensitive information such as database schema details, internal file paths, code snippets, or versions of backend components.
    6. If sensitive information is revealed in the error message, the information disclosure vulnerability is confirmed.

#### Potential Cross-Site Scripting (XSS) via Unsanitized Input in Custom Dashboard Components

* **Vulnerability Name:** Potential Cross-Site Scripting (XSS) via Unsanitized Input in Custom Dashboard Components
* **Description:**
    1. An attacker can potentially influence data displayed in custom dashboard components if the application uses data from external sources or user inputs without proper sanitization.
    2. If a custom dashboard component renders this unsanitized data directly into the HTML output, it becomes vulnerable to Cross-Site Scripting (XSS) attacks.
    3. By injecting malicious JavaScript code into the data source (if controllable), an attacker can execute arbitrary scripts in the browsers of admin users viewing the dashboard.
    4. This can lead to session hijacking, cookie theft, or malicious actions performed on behalf of the admin user.
* **Impact:**
    High. Cross-Site Scripting (XSS): Execution of malicious JavaScript code in admin users' browsers. Account compromise: Potential session hijacking and unauthorized admin account access. Data manipulation: Ability to potentially modify data within the admin interface or perform unauthorized actions.
* **Vulnerability Rank:** high
* **Currently implemented mitigations:**
    - Django's template engine with automatic output escaping is used. However, developers might use `|safe` or raw template tags incorrectly, bypassing escaping.
    - No specific XSS mitigation measures are implemented within django-unfold components themselves.
* **Missing mitigations:**
    - Security guidelines for developers on secure dashboard component development and XSS prevention.
    - Secure component base classes or helper functions with built-in output escaping for common data types.
    - Security documentation to warn developers about XSS risks in custom dashboard components.
* **Preconditions:**
    - The application utilizes custom dashboard components.
    - Custom components render data from potentially untrusted sources (user input, external APIs, database content without proper sanitization).
    - Admin users view dashboards containing these vulnerable components.
* **Source code analysis:**
    - `RenderComponentNode` in `/code/src/unfold/templatetags/unfold.py` renders components using `render_to_string`:
    ```python
    class RenderComponentNode(template.Node):
        def render(self, context: RequestContext) -> str:
            values = { ... }
            return render_to_string(
                self.template_name, request=context.request, context=values
            )
    ```
    The security relies entirely on the component templates and how data is handled in the `get_context_data` method of custom components. If component templates or `get_context_data` methods do not properly sanitize or escape user-controlled data before rendering, XSS vulnerabilities can be introduced. There is no automatic sanitization within `RenderComponentNode`.
* **Security test case:**
    1. As an external attacker, identify a publicly accessible Django admin panel using django-unfold that includes custom dashboard components.
    2. Investigate if any dashboard components display data that might be sourced from external or user-controlled inputs. This might require analyzing the application's functionality or public information.
    3. If a data source is identified as potentially controllable, attempt to inject a malicious JavaScript payload into it. For example, if the component displays data from a database, and there is a way to influence the database content (e.g., via a public form or API, or even by social engineering an admin to modify data).
    4. Once the malicious payload is injected into the data source, access the admin dashboard.
    5. Observe if the JavaScript code is executed in your browser when the dashboard component is rendered. For example, an alert box might appear, or more sophisticated XSS behavior can be tested.
    6. If the JavaScript code executes, the XSS vulnerability in the custom dashboard component is confirmed.

#### Potential Authorization Bypass via Insecure Direct Object References (IDOR) in Custom Actions

* **Vulnerability Name:** Potential Authorization Bypass via Insecure Direct Object References (IDOR) in Custom Actions
* **Description:**
    1. An attacker can attempt to exploit custom actions (changelist, changeform, row, submitline, dropdown) in the Django admin if they are not properly secured.
    2. If a custom action handler directly uses `object_id` from the request without authorization checks, it is vulnerable to Insecure Direct Object References (IDOR).
    3. By manipulating the `object_id` in the action URL or request parameters, an attacker might try to access or modify objects they are not authorized to interact with.
    4. This can lead to unauthorized data access, modification, or deletion, bypassing intended access controls.
* **Impact:**
    High. Authorization bypass: Circumvention of access controls, leading to unauthorized object access or manipulation. Data integrity compromise: Potential modification or deletion of data by unauthorized users. Privilege escalation: Possible escalation of privileges if IDOR allows access to actions not intended for the attacker's role.
* **Vulnerability Rank:** high
* **Currently implemented mitigations:**
    - Django's permission system and ModelAdmin's `has_permission` methods are available for use in custom action handlers.
    - `@action` decorator allows specifying `permissions` for action visibility, but not enforced object-level authorization within handlers.
    - Developers are responsible for implementing object-level authorization checks within action handlers.
* **Missing mitigations:**
    - Security guidelines for developers on secure custom action implementation, emphasizing IDOR prevention and authorization.
    - Helper functions or decorators to simplify object-level permission checks within action handlers.
    - Security documentation to warn about IDOR risks in custom actions.
* **Preconditions:**
    - The application implements custom actions in the Django admin.
    - Custom action handlers use `object_id` parameters from requests without proper authorization checks.
    - Authorization is intended to be enforced for object access and manipulation through admin actions.
* **Source code analysis:**
    - `ActionModelAdminMixin` in `/code/src/unfold/mixins/action_model_admin.py` handles action processing. `_filter_unfold_actions_by_permissions` checks permissions for action *visibility*:
    ```python
    def _filter_unfold_actions_by_permissions(self, ...):
        ...
        if object_id:
            if all(
                has_permission(request, object_id) # Permission check for visibility
                for has_permission in permission_checks
            ):
                filtered_actions.append(action)
        ...
    ```
    The `@action` decorator in `/code/src/unfold/decorators.py` also focuses on action visibility permissions. Object-level authorization within the action handler itself is not enforced by the framework and is the developer's responsibility. If developers fail to implement these checks, IDOR vulnerabilities can arise.
* **Security test case:**
    1. As an external attacker with limited admin privileges, identify a publicly accessible Django admin panel using django-unfold with custom actions.
    2. Find a custom action that appears to operate on specific objects (e.g., "delete item", "approve order").
    3. Analyze the action's URL structure to identify how `object_id` is passed (usually in the URL or POST parameters).
    4. Attempt to trigger the custom action for an `object_id` that you are *not* authorized to access or modify. You might need to enumerate or guess valid `object_id` values for objects outside your authorized scope.
    5. Submit the request with the manipulated `object_id`.
    6. Observe if the action is executed successfully on the unauthorized object. Verify if you can access or modify the protected object through the custom action despite lacking proper authorization.
    7. If successful, the IDOR vulnerability in the custom action is confirmed.

#### Potential Reflected Cross-Site Scripting (XSS) via Unsanitized Query Parameters in List Filters

* **Vulnerability Name:** Potential Reflected Cross-Site Scripting (XSS) via Unsanitized Query Parameters in List Filters
* **Description:**
    1. An attacker can craft malicious URLs containing JavaScript code within filter query parameters used by django-unfold's enhanced list filters.
    2. If the application does not properly sanitize or encode these filter query parameters when rendering filter forms or displaying filter values in the UI, it is vulnerable to reflected XSS.
    3. When an admin user clicks on a malicious link, the unsanitized query parameters are reflected back into the HTML response.
    4. The injected JavaScript code can then execute in the admin user's browser, potentially leading to account compromise or malicious actions.
* **Impact:**
    High. Reflected Cross-Site Scripting (XSS): Execution of attacker-controlled JavaScript in admin users' browsers. Account compromise: Potential session hijacking and unauthorized admin account access. Data manipulation: Ability to potentially modify data or perform actions on behalf of the admin user.
* **Vulnerability Rank:** high
* **Currently implemented mitigations:**
    - Django's template engine provides automatic output escaping. However, if filter values are not properly passed through templates or if escaping is bypassed, XSS can occur.
    - No specific XSS mitigation measures are implemented within django-unfold filter components for query parameter sanitization.
* **Missing mitigations:**
    - Implement input sanitization or output encoding for filter query parameters to prevent XSS.
    - Ensure filter values are properly escaped when rendered in the UI (input fields, labels, URLs).
    - Security guidelines for developers on secure filter implementation and XSS prevention.
    - Secure filter base classes or helper functions with automatic sanitization/encoding.
* **Preconditions:**
    - The application uses enhanced list filters provided by django-unfold.
    - Filter forms or UI elements render filter values from query parameters without sanitization.
    - Admin users are tricked into clicking malicious URLs with XSS payloads in filter query parameters.
* **Source code analysis:**
    - Filter classes in `unfold/contrib/filters/admin.py` (e.g., `TextFilter`) retrieve filter values directly from `request.GET` in their `value()` and `choices()` methods:
    ```python
    class TextFilter(admin.SimpleListFilter):
        ...
        def choices(self, changelist: ChangeList) -> tuple[dict[str, Any], ...]:
            return (
                {
                    "form": self.form_class(
                        name=self.parameter_name,
                        label=_("By %(filter_title)s") % {"filter_title": self.title},
                        data={self.parameter_name: self.value()}, # Value from request.GET
                    ),
                },
            )
    ```
    The `value()` method also directly retrieves from `request.GET`. These values from `request.GET` are passed to form classes and rendered in templates. If the filter templates (`unfold/filters/filters_field.html` etc. - not in PROJECT FILES) do not properly escape these values, reflected XSS vulnerabilities will be present.
* **Security test case:**
    1. As an external attacker, access a publicly available Django admin panel using django-unfold with enhanced list filters.
    2. Craft a malicious URL for a changelist view by adding a filter query parameter with a JavaScript payload. For example, if a filter parameter is named `name`, the URL could be `?name=<script>alert('XSS')</script>`.
    3. Send this malicious URL to an admin user (e.g., via email or social engineering).
    4. If the admin user clicks the link and accesses the admin page, observe if the JavaScript code is executed in their browser. For example, an alert box might appear.
    5. Examine the HTML source of the changelist page to confirm that the injected JavaScript payload from the query parameter is reflected in the HTML output without proper escaping.
    6. If the JavaScript executes and the payload is reflected, the reflected XSS vulnerability is confirmed.