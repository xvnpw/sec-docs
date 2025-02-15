# Attack Surface Analysis for django/django

## Attack Surface: [Unrestricted File Uploads (via `FileField`/`ImageField`)](./attack_surfaces/unrestricted_file_uploads__via__filefield__imagefield__.md)

*   **Description:**  Allowing users to upload files without proper validation and restrictions, leveraging Django's built-in file handling.
*   **How Django Contributes:** Django *provides* `FileField` and `ImageField`, making file uploads a common and easily implemented feature, thus increasing the attack surface if misused.
*   **Example:**  An attacker uploads a malicious script disguised as an image, exploiting a server misconfiguration to gain code execution.
*   **Impact:**  Complete system compromise, data theft, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:**
        *   Use `FileField`/`ImageField` with strict validators (`FileExtensionValidator`, size limits).
        *   Store files *outside* the web root.
        *   Rename files to random, unique names (UUIDs).
        *   Validate file *content* (MIME type), not just extensions.
        *   Use a dedicated file storage service.
        *   Scan for malware.

## Attack Surface: [Improper URL Configuration (ReDoS in `urls.py`)](./attack_surfaces/improper_url_configuration__redos_in__urls_py__.md)

*   **Description:**  Vulnerable regular expressions in Django's `urls.py`, leading to Regular Expression Denial of Service (ReDoS).
*   **How Django Contributes:** Django's URL routing system *requires* the use of regular expressions, making this a core Django-specific vulnerability.
*   **Example:**  A poorly crafted regex in `urls.py` is exploited with a specially crafted URL, causing excessive CPU usage and denial of service.
*   **Impact:**  Denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:**
        *   Use simple, well-tested regexes.
        *   Avoid nested quantifiers.
        *   Prefer Django's URL converters (`<int:pk>`).
        *   Use ReDoS detection tools.
        *   Set regex timeouts.

## Attack Surface: [Debug Mode Enabled in Production (`DEBUG = True`)](./attack_surfaces/debug_mode_enabled_in_production___debug_=_true__.md)

*   **Description:**  Leaving Django's `DEBUG` setting enabled in a production environment.
*   **How Django Contributes:** `DEBUG` is a core Django setting that controls the display of sensitive debugging information.
*   **Example:**  An error reveals database credentials, file paths, and code snippets to an attacker.
*   **Impact:**  Information disclosure, aiding further attacks; exposure of sensitive data.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer/Admin:**
        *   **Always** set `DEBUG = False` in production.
        *   Use environment variables for different settings.

## Attack Surface: [Secret Key Exposure (`SECRET_KEY`)](./attack_surfaces/secret_key_exposure___secret_key__.md)

*   **Description:**  Compromise of Django's `SECRET_KEY`.
*   **How Django Contributes:** The `SECRET_KEY` is a fundamental Django security component used for cryptographic signing.
*   **Example:**  An attacker obtains the `SECRET_KEY` and forges session cookies, gaining unauthorized access.
*   **Impact:**  Session hijacking, CSRF attacks, potential system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer/Admin:**
        *   Never commit the `SECRET_KEY` to version control.
        *   Use environment variables or a secure configuration system.
        *   Generate a strong, random key.
        *   Rotate the key regularly.

## Attack Surface: [Improper `ALLOWED_HOSTS` Configuration](./attack_surfaces/improper__allowed_hosts__configuration.md)

*   **Description:**  Incorrectly configuring Django's `ALLOWED_HOSTS` setting, or setting it to `['*']`.
*   **How Django Contributes:** `ALLOWED_HOSTS` is a Django-specific security setting to prevent host header attacks.
*   **Example:**  An attacker uses a malicious `Host` header, and Django processes the request due to a misconfigured `ALLOWED_HOSTS`.
*   **Impact:**  Host header injection, potentially leading to other vulnerabilities.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer/Admin:**
        *   Set `ALLOWED_HOSTS` to the specific, valid domain names/IPs.
        *   Avoid wildcards (`*`) in production.

## Attack Surface: [Template Injection (Bypassing Auto-Escaping)](./attack_surfaces/template_injection__bypassing_auto-escaping_.md)

*   **Description:**  User input rendered in Django templates without proper escaping, allowing execution of template code.
*   **How Django Contributes:** While Django auto-escapes, the *potential* for misuse exists through the `safe` filter or disabling auto-escaping. This is a Django template engine specific issue.
*   **Example:**  User input containing `{{ settings.SECRET_KEY }}` is rendered with the `safe` filter, exposing the secret key.
*   **Impact:**  Information disclosure, potential remote code execution.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:**
        *   Never disable auto-escaping globally.
        *   Use `safe` *extremely* sparingly and only after sanitization.
        *   Prefer custom template tags/filters.
        *   Avoid dynamic template rendering with user input.

## Attack Surface: [Weak or Default Admin Credentials (Django Admin Interface)](./attack_surfaces/weak_or_default_admin_credentials__django_admin_interface_.md)

*   **Description:**  Using weak or default passwords for the Django admin interface.
*   **How Django Contributes:** Django *provides* the built-in admin interface (`/admin/`), a common and high-value target.
*   **Example:**  Brute-force or credential stuffing attacks succeed against the admin interface.
*   **Impact:**  Complete application and database control.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer/Admin:**
        *   Strong, unique passwords.
        *   Multi-factor authentication (MFA).
        *   Change the default admin URL.
        *   Restrict access by IP.
        *   Audit admin activity.
        *   Consider disabling if not essential.

## Attack Surface: [ORM-Specific SQL Injection (Misusing `raw()` or `extra()`)](./attack_surfaces/orm-specific_sql_injection__misusing__raw____or__extra____.md)

*   **Description:**  Using Django's `raw()` or `extra()` ORM methods with unsanitized user input.
*   **How Django Contributes:** These methods, *provided by Django's ORM*, bypass the ORM's usual SQL injection protections if misused.
*   **Example:**  Using `raw()` with string formatting instead of parameterized queries.
*   **Impact:**  Data theft, modification, corruption, denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:**
        *   Prefer built-in ORM methods.
        *   If `raw()` is needed, use *parameterized queries*.
        *   Avoid `extra()` if possible; use its `params` argument for safe parameter passing.

## Attack Surface: [Mass Assignment](./attack_surfaces/mass_assignment.md)

* **Description:** Updating model instances directly from user-provided data without specifying allowed fields, potentially allowing attackers to modify unintended fields.
* **How Django Contributes:** Django's ORM allows for easy model updates, but developers need to be mindful of which fields are being updated. The ease of updating models contributes to the potential for this vulnerability.
* **Example:** An attacker adds an `is_admin=True` field to a POST request when updating their user profile, potentially granting themselves administrative privileges.
* **Impact:** Unauthorized data modification, privilege escalation.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * **Developer:**
        * Use Django Forms, which by default only process fields defined in the form.
        * If manually updating models, use the `fields` option in `Model.save()` or explicitly set only the allowed fields.
        * Consider using Django's `ModelForm` with the `fields` or `exclude` attributes to control which fields are included in the form.

