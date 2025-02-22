- **Vulnerability Name:** Insecure Dynamic Callback Execution via UNFOLD Configuration  
  **Description:**  
  The project’s configuration (in settings and documentation files) lets administrators specify callback functions as strings (for keys such as `ENVIRONMENT`, `ENVIRONMENT_TITLE_PREFIX`, `TABS`, `SITE_ICON`, and `SITE_LOGO`). Later these strings are passed to Django’s dynamic import mechanism (e.g. via an import_string–like helper) and then executed with the current request context. If an attacker is able to modify these settings (for example, through a misconfigured configuration management tool, an insecure admin interface that allows settings override, or via filesystem tampering), they could cause arbitrary Python code to run with full server privileges.  
  **Impact:**  
  An attacker who is able to change the UNFOLD configuration may execute arbitrary code on the server (remote code execution), thereby compromising the entire system.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  - The project assumes these UNFOLD settings are hard‑coded in the server’s settings file, which is normally not user‑modifiable at runtime.  
  - Standard Django deployment practices (including proper file system and settings file protection) help mitigate external tampering.  
  **Missing Mitigations:**  
  - No runtime validation, whitelisting, or explicit sanitization is applied to callback strings prior to dynamic import.  
  **Preconditions:**  
  - The attacker must be able to alter (or inject) configuration values—this might occur via an insecure configuration management process, an over‑permissive admin tool, or filesystem compromise.  
  **Source Code Analysis:**  
  - Documentation (see *docs/configuration/settings.md*) and tests (such as *tests/test_environment.py*) show that keys like `ENVIRONMENT`, `ENVIRONMENT_TITLE_PREFIX`, and `TABS` expect string values that are subsequently passed to Django’s `import_string` (or similar) function without any further checks.  
  **Security Test Case:**  
  - In a controlled test environment, override the UNFOLD configuration (using, for example, Django’s `@override_settings`) to substitute one of the callback settings with the path to a test function (e.g. one that writes a marker to a log file).  
  - Trigger a view (for example, by accessing an admin page that calls `each_context`) and verify that the test function is executed.  
  - Then substitute the callback with one that attempts to execute a command such as `os.system("id")` and observe that arbitrary Python code execution is indeed possible.  

---

- **Vulnerability Name:** Potential Stored Cross‑Site Scripting (XSS) via WysiwygWidget  
  **Description:**  
  The Unfold admin theme uses a custom rich‑text widget (the WysiwygWidget based on the Trix editor) for editing large text fields. If an attacker (or a compromised administrator) submits content that includes malicious JavaScript (e.g. `<script>alert('XSS')</script>`) and that content is later rendered without proper sanitization (for example, in a readonly change‑form or list view), the browser may execute the injected script.  
  **Impact:**  
  An attacker exploiting stored XSS can execute arbitrary JavaScript in the context of any admin user viewing the affected field—potentially leading to session hijacking, defacement, or data exfiltration.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - In most cases the widget is used in fields declared in `readonly_fields`, so Django’s autoescaping is normally active.  
  - The admin interface is restricted to trusted administrators.  
  **Missing Mitigations:**  
  - No built‑in sanitization is applied to the HTML content submitted through the WysiwygWidget.  
  - There is no explicit filter or sanitizer (such as Bleach) applied before rendering stored HTML content in non‑editable contexts.  
  **Preconditions:**  
  - An attacker (or compromised admin) must be able to submit HTML content via the WysiwygWidget.  
  - The malicious content must later be rendered in a view where it is not re‑escaped by Django’s templates.  
  **Source Code Analysis:**  
  - The widget defined in *src/unfold/contrib/forms/widgets.py* uses the Trix editor but does not integrate a sanitization library.  
  - Documentation (see *docs/widgets/wysiwyg.md*) confirms the intended use of the widget for rich text but does not mention sanitation.  
  **Security Test Case:**  
  - Create a model field that employs the WysiwygWidget for input and is later rendered in a readonly admin view.  
  - Log in as an administrator, and submit content containing a benign JavaScript payload (for example, `<script>alert("XSS")</script>`).  
  - In a separate session (or browser), visit the page rendering this content and check if the script executes (e.g. observe an alert or log entry).  
  - If the script runs, then the stored XSS vulnerability is confirmed and sanitization should be added.  

---

- **Vulnerability Name:** Unescaped Output in Custom Tab Configuration  
  **Description:**  
  The UNFOLD settings include a “TABS” configuration that accepts a list of dictionaries used to render custom navigation tabs through the `{% tab_list "page_name" %}` template tag. If the content provided for these tab items (such as the “title” or “link” fields) is not properly escaped before rendering, an attacker who can modify these settings may be able to inject arbitrary HTML or JavaScript into the admin interface.  
  **Impact:**  
  Injection of malicious HTML or JavaScript into the admin navigation could result in stored XSS. This would allow an attacker to execute code in the browser of any admin user viewing the navigation—potentially leading to session hijacking or other forms of privilege escalation.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - Django’s default autoescaping is enabled in templates, meaning that unless the configuration values are explicitly marked “safe,” they will normally be escaped.  
  - The documentation does not advise bypassing autoescaping when rendering custom tab content.  
  **Missing Mitigations:**  
  - There is no explicit sanitization or whitelist enforcement to validate that the data provided for custom tabs is free of malicious markup.  
  - In cases where developers have explicitly marked these configuration values as “safe” (for styling reasons), the risk of XSS is inadvertently introduced.  
  **Preconditions:**  
  - The attacker or a compromised administrator must be able to modify the UNFOLD “TABS” configuration (for example, via a misconfigured settings editor or insecure configuration management).  
  **Source Code Analysis:**  
  - The template tag `{% tab_list "page_name" %}` (defined in *src/unfold/templatetags/unfold.py*) directly renders the tab items from the config without performing additional sanitation.  
  - Documentation (see *docs/tabs/dynamic.md*) indicates that the “TABS” configuration accepts arbitrary strings for tab titles and links.  
  **Security Test Case:**  
  - In a controlled environment, override the UNFOLD “TABS” configuration (using Django’s `@override_settings`) to include a tab item with an HTML payload (for example, set the title to `"<script>alert('XSS')</script>"`).  
  - Load a page that includes the `{% tab_list "custom_page" %}` tag and inspect the rendered HTML source or observe behavior in the browser.  
  - If the injected script executes instead of being escaped, then the vulnerability is confirmed and sanitization measures must be implemented.