### Vulnerability List for django-treebeard

* Vulnerability Name: Reflected Cross-Site Scripting (XSS) in Django Admin Tree List

* Description:
    1. An attacker with Django admin access can create or edit a tree node through the admin interface.
    2. When creating or editing a node, the attacker enters a malicious payload containing JavaScript (e.g., `<script>alert('XSS-treebeard')</script>`) into a field of the node model that is used in the `__str__` method for display purposes in the admin interface.
    3. When a Django admin user navigates to the change list view for the tree model in the Django admin, the `result_tree` template tag, used in `admin/treebeard/templatetags/admin_tree_list.py`, renders the tree structure.
    4. The `_line` function within the `treebeard/templatetags/admin_tree_list.py` template tags is responsible for rendering each node in the tree. This function uses `str(node)` to obtain the string representation of the node for display.
    5. The output of `str(node)`, which includes the attacker's malicious payload (if the `__str__` method does not perform proper HTML escaping), is then incorporated into the HTML output using `format_html`. While `format_html` provides some escaping, it does not escape pre-rendered HTML content within the `str(node)` output.
    6. As a result, the malicious JavaScript payload from the node's `__str__` representation is injected into the HTML response without sufficient escaping and is executed by the admin user's web browser when the admin page is loaded.
    7. This leads to a reflected Cross-Site Scripting (XSS) vulnerability.

* Impact:
    - An attacker can compromise the Django admin account of a user viewing the tree change list.
    - Upon successful exploitation, the attacker can execute arbitrary JavaScript code within the security context of the admin user's session.
    - This can lead to various malicious actions, including but not limited to: stealing session cookies, performing actions on behalf of the admin user, defacing the admin interface, or redirecting the admin user to malicious websites.
    - The vulnerability can be leveraged to escalate privileges within the Django application if the compromised admin user has elevated permissions.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - The `CHANGES.md` file mentions "Release 4.0.1 (May 1, 2016) * Escape input in forms". This suggests an attempt to address input escaping issues, however, based on source code analysis, output escaping in tree rendering using `str(node)` might be missing or insufficient to prevent XSS in all cases, particularly when the `__str__` method of a tree node model is not explicitly escaping HTML entities.

* Missing Mitigations:
    - **Output Escaping in `__str__` Methods**: Developers using django-treebeard should be strongly advised and explicitly documented to ensure that the `__str__` methods of their tree node models properly escape HTML entities for any user-controlled data they include in the string representation. This is the primary missing mitigation from the django-treebeard library itself, as it relies on user models to be secure.
    - **Context-Aware Output Escaping in Templates**: While `format_html` is used, ensure that the output of `str(node)` is treated as plain text and properly escaped in the template tag `_line` function before being rendered as HTML.  Alternatively, ensure that `str(node)` is guaranteed to return HTML-safe strings.

* Preconditions:
    - The attacker must have valid credentials for a Django admin account with permissions to create or edit tree nodes.
    - A tree model implemented using django-treebeard is registered in the Django admin.
    - The tree node model's `__str__` method includes a field that can be controlled by an admin user and does not perform HTML escaping.
    - The Django admin user must access the change list view of the tree model to trigger the XSS.

* Source Code Analysis:
    - File: `/code/treebeard/templatetags/admin_tree_list.py`
    - Function: `_line(context, node, request)`
    - Code Snippet:
    ```python
    def _line(context, node, request):
        # ...
        output = ''
        if needs_checkboxes(context):
            output += format_html(CHECKBOX_TMPL, node.pk)
        return output + format_html(
            '<a href="{}/" {}>{}</a>',
            node.pk, mark_safe(raw_id_fields), str(node))
    ```
    - Analysis: The `_line` function constructs an HTML link (`<a>` tag) to display each node in the tree. The node's string representation, obtained by calling `str(node)`, is directly embedded within the HTML using `format_html`. Although `format_html` is intended to prevent XSS by escaping HTML-unsafe characters in its direct arguments (like `node.pk` and `raw_id_fields`), it does **not** re-escape content that is already marked as HTML or that comes from a string that itself contains unescaped HTML. If the `str(node)` method of the tree node model returns a string containing unescaped HTML (e.g., a malicious `<script>` tag injected into a node field and reflected in `__str__`), `format_html` will render this HTML directly, leading to XSS. The `mark_safe(raw_id_fields)` is irrelevant to the XSS issue related to `str(node)`.

* Security Test Case:
    1. **Setup Django Project and Treebeard:** Create a new Django project and install `django-treebeard` using pip.
    2. **Create Vulnerable Tree Model:** Define a Django model (e.g., `VulnerableNode`) that inherits from `treebeard.mp_tree.MP_Node` (or any other tree implementation). Add a `CharField` named `display_name` and override the `__str__` method to return this field *without* any HTML escaping:
    ```python
    from django.db import models
    from treebeard.mp_tree import MP_Node

    class VulnerableNode(MP_Node):
        name = models.CharField(max_length=50)
        display_name = models.CharField(max_length=255)

        def __str__(self):
            return self.display_name # Vulnerable: No HTML escaping
    ```
    3. **Register Model in Admin:** In your `admin.py`, register `VulnerableNode` with `TreeAdmin`:
    ```python
    from django.contrib import admin
    from treebeard.admin import TreeAdmin
    from .models import VulnerableNode

    admin.site.register(VulnerableNode, TreeAdmin)
    ```
    4. **Login to Django Admin:** Start the Django development server and log in to the Django admin panel as a superuser.
    5. **Navigate to Tree Model Change List:** Go to the change list view for `Vulnerable Nodes` in the admin.
    6. **Create a Malicious Node:** Click "Add Vulnerable node". In the `Name` field, enter any value. In the `Display name` field, enter the XSS payload: `<script>alert('XSS-treebeard-admin-tree')</script>`. Save the node.
    7. **Observe XSS:** After saving, observe the tree in the change list view. If an alert box with the message 'XSS-treebeard-admin-tree' pops up, the reflected XSS vulnerability is confirmed. The JavaScript code injected through the `display_name` field and rendered by the `_line` function in the template tag has been executed in the admin user's browser.