## Combined List of Vulnerabilities

This document combines identified vulnerabilities from multiple lists into a single comprehensive list, removing any duplicates. Each vulnerability is detailed with its description, impact, rank, mitigation status, preconditions, source code analysis, and a security test case.

### 1. Server-Side Template Injection in `TemplateColumn`

- **Description:**
    - An attacker can inject malicious template code into the `template_code` or `template_name` parameters of the `TemplateColumn`.
    - When the table is rendered and the `TemplateColumn` is processed, the injected template code will be executed by the Django template engine.
    - Step 1: An attacker crafts a request to an application using `django-tables2` that somehow allows control over data rendered in a `TemplateColumn`. This could be through URL parameters, form input, or database content that is displayed in a table.
    - Step 2: The attacker injects malicious Django template code into the controlled data. For example, `{% load os %}{% os.system "malicious command" %}` or similar constructs that execute arbitrary code.
    - Step 3: The application renders the table, and the `TemplateColumn` processes the attacker-controlled template code.
    - Step 4: The Django template engine executes the malicious code, leading to server-side template injection.
- **Impact:**
    - **Critical**: Full server compromise. An attacker can execute arbitrary code on the server, read sensitive data, modify data, or cause a denial of service. The impact is only limited by the permissions of the user running the Django application.
- **Vulnerability Rank:** critical
- **Currently Implemented Mitigations:**
    - None: The code directly uses `Template` and `Context` to render the provided template code without any sanitization or escaping of potentially malicious input.
- **Missing Mitigations:**
    - Sandboxed template environment: Instead of using the default Django template engine, a sandboxed template environment should be used for rendering `TemplateColumn` content. This would restrict the available template tags and filters, preventing the execution of dangerous code.
- **Preconditions:**
    - The application using `django-tables2` must be using `TemplateColumn` to render data in tables.
    - An attacker must be able to control the input data that is rendered by the `TemplateColumn` (either directly or indirectly, e.g., through stored data).
- **Source Code Analysis:**
    - File: `/code/django_tables2/columns/templatecolumn.py`
    - Class: `TemplateColumn`
    - Method: `render`
    - Code snippet:
      ```python
      def render(self, record, table, value, bound_column, **kwargs):
          if self.template:
              template = self.template
          elif self.template_name:
              template = get_template(self.template_name)
          elif self.template_code:
              template = Template(self.template_code) # Vulnerability: Directly using Template on user input
          else:
              return super().render(record=record, table=table, value=value, bound_column=bound_column, **kwargs)

          context = Context(self.get_context_data(
              record=record, table=table, value=value, bound_column=bound_column, extra_context=getattr(table, 'context', None)
          ))
          return template.render(context) # Vulnerability: Rendering template with Context
      ```
    - Visualization:
      ```mermaid
      graph LR
          A[Request with malicious payload] --> B(Application using django-tables2);
          B --> C{Data source with attacker payload for TemplateColumn};
          C --> D[TemplateColumn.render];
          D --> E{Template instantiation with attacker payload: Template(template_code)};
          E --> F[Template engine execution: template.render(Context)];
          F --> G[Server-Side Code Execution];
      ```
    - Step-by-step analysis:
        1. The `TemplateColumn.render` method is called to render a cell in the table.
        2. If `template_code` is provided during `TemplateColumn` initialization, a `Template` object is created directly from `self.template_code`. This is where the vulnerability lies, as `template_code` can be directly controlled by developers using the library, and potentially indirectly by attackers if developers are not careful about data sources.
        3. A `Context` is created, which includes the record, table, value, bound_column, and any extra context from the table.
        4. `template.render(context)` is called, which renders the template using the created context. If the `template_code` contains malicious code, it will be executed at this point.
- **Security Test Case:**
    - Step 1: Create a Django project and install `django-tables2`.
    - Step 2: Define a Django model that will be used in the table.
    - Step 3: Create a Django view that renders a table.
    - Step 4: Define a `tables.Table` class with a `TemplateColumn`. Pass a template string to `template_code` parameter of `TemplateColumn` which executes system command, e.g., `{% load os %}{{ os.popen "id" }}`. Ensure that the data source for the table allows rendering of this `TemplateColumn`.
    - Step 5: Access the view in a web browser.
    - Step 6: Observe that the output of the `id` command is executed and rendered on the page, demonstrating server-side template injection.

### 2. Unauthenticated Data Export Vulnerability

- **Vulnerability Name:** Unauthenticated Data Export Vulnerability
- **Description:**
    - The `ExportMixin` (used in views like `FilteredPersonListView`) automatically exports a table’s complete dataset when it detects a valid export trigger (by default, the GET parameter `_export`).
    - An external attacker can simply append (for example, `?_export=csv`) to the URL of any publicly accessible view that uses `ExportMixin` and receive an export of all rows—even bypassing any pagination or UI restrictions.
    - **Step‑by-step trigger:**
        1. Identify a view (such as the one provided by `FilteredPersonListView`) that employs `ExportMixin`.
        2. Issue a GET request to the view URL (e.g. `/filtered/`) without authentication.
        3. Append `?_export=csv` (or another supported format) to the URL.
        4. Receive an export (CSV or XLS) of the entire dataset.
- **Impact:**
    - An attacker is able to exfiltrate potentially sensitive or confidential data in bulk, bypassing any UI restrictions or client‑side pagination. This can lead to serious data breaches.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The export mixin validates the export trigger and format but does not enforce any authentication or authorization checks.
- **Missing Mitigations:**
    - Access control measures (such as authentication and authorization checks) or CSRF/non‑GET method verification must be implemented before triggering export.
- **Preconditions:**
    - A publicly accessible view employing `ExportMixin` exists and it lacks proper authentication/authorization checks.
- **Source Code Analysis:**
    - In `/code/example/app/views.py`, the class `FilteredPersonListView` extends `ExportMixin` without any additional checks.
    - The GET parameter `_export` (e.g. `/?_export=csv`) is used to trigger the export of the table data, and the mixin immediately returns the export response without verifying the requestor’s identity.
- **Security Test Case:**
    - Step 1: Deploy the Django application using the view that employs `ExportMixin` (with no extra access control).
    - Step 2: In a browser or via a tool like curl, visit the URL normally (e.g. `http://example.com/filtered/`).
    - Step 3: Append the export trigger to the query string (e.g. `http://example.com/filtered/?_export=csv`).
    - Step 4: Verify that the response is a complete CSV (or XLS) export of the full dataset without any authentication prompt.

### 3. DEBUG Mode Enabled in Production

- **Vulnerability Name:** DEBUG Mode Enabled in Production
- **Description:**
    - The example project settings (in `/code/example/settings.py`) have `DEBUG = True` and `ALLOWED_HOSTS = ["*"]`.
    - When an application is deployed with DEBUG enabled, any error (for example, visiting a non‑existent URL) results in a detailed error page that includes stack traces, settings, and potentially sensitive configuration details.
    - **Step‑by-step trigger:**
        1. Deploy the application with the provided example settings.
        2. Visit an invalid URL or trigger an error.
        3. The application returns a detailed error page with internal information.
- **Impact:**
    - Detailed error pages may disclose internal file paths, configuration settings (such as database settings), and portions of the source code. This information facilitates reconnaissance against the application.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - No mitigation exists; the application uses development settings unconditionally.
- **Missing Mitigations:**
    - In production, `DEBUG` must be set to `False` and `ALLOWED_HOSTS` should be restricted to trusted domain names.
- **Preconditions:**
    - The application is deployed using the `/code/example/settings.py` configuration without modifications.
- **Source Code Analysis:**
    - The settings file (`/code/example/settings.py`) includes:
      ```
      DEBUG = True
      ALLOWED_HOSTS = ["*"]
      ```
    - This configuration causes any unhandled exception to display detailed debug information publicly.
- **Security Test Case:**
    - Step 1: Deploy the application using the provided settings.
    - Step 2: Navigate to a URL that will trigger an error (for example, a non‑existent page).
    - Step 3: Confirm that a detailed error page with a stack trace and configuration details is shown.

### 4. Weak SECRET_KEY in Production

- **Vulnerability Name:** Weak SECRET_KEY in Production
- **Description:**
    - The `SECRET_KEY` is hard‑coded in the example settings (`SECRET_KEY = "this is super secret"`), making it easily guessable.
    - In Django, the `SECRET_KEY` is used for cryptographic signing (for sessions, CSRF protection, password reset tokens, etc.).
    - **Step‑by-step trigger:**
        1. Deploy the application using the provided settings.
        2. An attacker who discovers the weak key can use it to forge session cookies or CSRF tokens.
- **Impact:**
    - With a known secret key, an attacker can forge cryptographically signed data. This may result in session hijacking, unauthorized actions, or data tampering.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - There is no mitigation; the insecure key is statically defined in the settings.
- **Missing Mitigations:**
    - A strong, randomly generated secret key must be used for production – ideally supplied via a secure environment variable.
- **Preconditions:**
    - The application is deployed unmodified from `/code/example/settings.py`, thereby using the weak secret key.
- **Source Code Analysis:**
    - In `/code/example/settings.py`, the line
      ```
      SECRET_KEY = "this is super secret"
      ```
      is used, which is not unique or random.
- **Security Test Case:**
    - Step 1: Deploy the application with the provided settings.
    - Step 2: Using the known value of the `SECRET_KEY`, attempt to craft a session cookie or CSRF token that the server accepts.
    - Step 3: If successful, this confirms that the cryptographic signing is compromised by the weak key.

### 5. Insecure Media File Serving Vulnerability

- **Vulnerability Name:** Insecure Media File Serving Vulnerability
- **Description:**
    - The URL configuration (in `/code/example/urls.py`) includes a route that serves media files via Django’s built‑in static file server:
      ```
      path("media/<path>", static.serve, {"document_root": settings.MEDIA_ROOT}),
      ```
    - This view is intended only for development and lacks production‑grade security controls.
    - **Step‑by-step trigger:**
        1. Deploy the application in a production‑like environment using the example URL configuration.
        2. Access files under `/media/` using crafted URLs (or directory traversal strings).
- **Impact:**
    - An attacker may be able to access or traverse directories within the `MEDIA_ROOT`, potentially leading to unauthorized disclosure of sensitive files.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The project relies on Django’s development static file server (`django.views.static.serve`), which does not enforce strict protections.
- **Missing Mitigations:**
    - In production, media files should be served by a dedicated web server (e.g. Nginx or Apache) that applies proper access restrictions rather than using Django’s development view.
- **Preconditions:**
    - The application is deployed in a production‑like environment with the provided URL configuration, leaving `/media/` openly accessible.
- **Source Code Analysis:**
    - The URL configuration in `/code/example/urls.py` includes:
      ```
      path("media/<path>", static.serve, {"document_root": settings.MEDIA_ROOT}),
      ```
      which means that any file under `MEDIA_ROOT` can be served without additional security checks.
- **Security Test Case:**
    - Step 1: Deploy the application with the example URL configuration (simulating production).
    - Step 2: Request known media files (or attempt directory traversal via paths such as `../`) using URLs like `http://example.com/media/sensitive_file.pdf`.
    - Step 3: Verify that files are served without authentication or access control.