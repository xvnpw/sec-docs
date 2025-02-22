## Vulnerability List

- Potential Cross-Site Scripting (XSS) via `compare_values` template tag

### Potential Cross-Site Scripting (XSS) via `compare_values` template tag

- Description:
    1. An attacker with admin access can import data containing malicious HTML or JavaScript code in one of the fields.
    2. During import or when viewing change history in the Django admin, the `compare_values` template tag is used to display differences between old and new values.
    3. The `compare_values` tag uses `diff_match_patch.diff_prettyHtml` to generate HTML diffs.
    4. If the imported malicious HTML/JavaScript is not properly sanitized by `diff_match_patch.diff_prettyHtml`, it will be rendered as part of the HTML diff in the admin interface.
    5. When an admin user views the import confirmation page or change history, the malicious script will be executed in their browser, leading to XSS.
- Impact:
    - Account Takeover: An attacker could potentially steal admin session cookies or credentials, leading to full account takeover.
    - Data Breach: The attacker could potentially access sensitive data visible to the admin user.
    - Malicious Actions: The attacker could perform actions on behalf of the admin user, such as modifying data, creating new admin users, etc.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    - None identified in the provided code related to sanitizing inputs to `compare_values` or the output of `diff_match_patch.diff_prettyHtml`.
- Missing Mitigations:
    - Input sanitization: Sanitize `value1` and `value2` inputs to `compare_values` template tag before passing them to `diff_match_patch.diff_prettyHtml`. Use Django's `escape` filter or a more robust HTML sanitization library like Bleach.
    - Output sanitization: Ensure that `diff_match_patch.diff_prettyHtml` properly sanitizes its output or use a safer diffing and HTML generation approach.
- Preconditions:
    - Admin access to the Django admin interface to perform import operations.
    - Ability to import data that includes fields that will be displayed using `compare_values` tag in admin views (e.g., in import confirmation page or change history).
    - The imported data must contain malicious HTML or JavaScript code.
- Source code analysis:
    - File: `/code/import_export/templatetags/import_export_tags.py`
    ```python
    from diff_match_patch import diff_match_patch
    from django import template

    register = template.Library()


    @register.simple_tag
    def compare_values(value1, value2):
        dmp = diff_match_patch()
        diff = dmp.diff_main(value1, value2)
        dmp.diff_cleanupSemantic(diff)
        html = dmp.diff_prettyHtml(diff)
        return html
    ```
    - The `compare_values` template tag directly uses `diff_match_patch.diff_prettyHtml` without any sanitization of `value1` and `value2` or escaping of the generated HTML output.
    - If `value1` or `value2` contain malicious HTML, `diff_prettyHtml` might not sanitize it properly, and the resulting `html` will be rendered in the template without further escaping, leading to potential XSS.
- Security test case:
    1. Create a Django project and install `django-import-export`.
    2. Define a model and a `Resource` for it.
    3. Register the model with the Django admin.
    4. Create an import file (e.g., CSV, XLSX) with a column that will be displayed in the admin change history or import confirmation page. In this column, include a malicious payload like `<img src=x onerror=alert(document.domain)>`.
    5. Log in to the Django admin as a superuser.
    6. Go to the import page for the registered model and upload the crafted import file.
    7. Complete the import process.
    8. Navigate to the change history of an imported object or the import confirmation page.
    9. Observe if the JavaScript `alert(document.domain)` is executed. If it is, the XSS vulnerability is confirmed.