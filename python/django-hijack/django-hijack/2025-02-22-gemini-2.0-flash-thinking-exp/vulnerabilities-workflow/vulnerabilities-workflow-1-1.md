### Vulnerability List:

- Vulnerability Name: Insecure Custom Permission Function leading to Privilege Escalation
- Description: If a developer implements a custom permission check function (`HIJACK_PERMISSION_CHECK`) incorrectly, it can lead to privilege escalation. This allows unauthorized users, who should not have hijack permissions, to impersonate other users, potentially gaining access to sensitive data or performing actions on their behalf.
- Impact: Unauthorized account access, privilege escalation, potential data breach or unauthorized actions performed as another user.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - The default permission function `hijack.permissions.superusers_only` is secure and restricts hijacking to superusers only.
    - The documentation in `SECURITY.md`, `docs/security.md`, and `docs/customization.md` warns developers about the security risks of writing custom permission functions and emphasizes the importance of thorough testing.
- Missing mitigations:
    - No input validation or security checks are performed on the custom permission function defined in `HIJACK_PERMISSION_CHECK`.
    - The project does not provide tools or guidelines to help developers write secure custom permission functions, beyond a warning.
    - No built-in mechanism to prevent overly permissive custom functions (e.g., limiting the scope of permissions that can be granted).
- Preconditions:
    - The application must be configured to use a custom permission check function by setting `HIJACK_PERMISSION_CHECK` in `settings.py`.
    - The custom permission function implemented by the developer must contain a logical flaw that results in unintended users being granted hijack permissions.
- Source code analysis:
    - `hijack/conf.py`: The `HIJACK_PERMISSION_CHECK` setting is defined as a string:
      ```python
      class LazySettings:
          HIJACK_PERMISSION_CHECK = "hijack.permissions.superusers_only"
          # ...
      ```
    - `hijack/views.py`: The `AcquireUserView` imports and uses the function defined in `HIJACK_PERMISSION_CHECK` without any validation:
      ```python
      from django.utils.module_loading import import_string

      class AcquireUserView(
          # ...
      ):
          # ...
          def test_func(self):
              func = import_string(settings.HIJACK_PERMISSION_CHECK)
              return func(hijacker=self.request.user, hijacked=self.get_object())
      ```
      - The `import_string` function simply imports the function based on the string path.
      - The `test_func` then directly calls this imported function, relying entirely on the developer to implement a secure permission check.
      - **Visualization:**
        ```
        settings.py (HIJACK_PERMISSION_CHECK = "path.to.custom_function") --> hijack/conf.py --> hijack/views.py (import_string(HIJACK_PERMISSION_CHECK)) --> custom_function (developer implemented, potential vulnerability)
        ```
- Security test case:
    1. **Create a vulnerable custom permission function:**
       - In your Django project (assuming you are using `django-hijack` in a project), create a file (e.g., `my_permissions.py`) with the following vulnerable permission function:
         ```python
         # my_permissions.py
         def insecure_permission_check(*, hijacker, hijacked):
             """Insecure permission check that allows staff users to hijack anyone."""
             if hijacker.is_staff:
                 return True  # Intentionally insecure: staff can hijack anyone
             return False
         ```
    2. **Configure `HIJACK_PERMISSION_CHECK`:**
       - In your project's `settings.py`, set `HIJACK_PERMISSION_CHECK` to point to this vulnerable function:
         ```python
         # settings.py
         HIJACK_PERMISSION_CHECK = "my_permissions.insecure_permission_check"
         ```
    3. **Create a staff user and a regular user:**
       - Use Django admin or `createsuperuser` to create:
         - A staff user (e.g., `staff_user`) who is *not* a superuser but `is_staff=True`.
         - A regular user (e.g., `regular_user`) who is neither staff nor superuser.
    4. **Log in as the staff user:**
       - Use a browser to log in to your Django application as `staff_user`.
    5. **Attempt to hijack the regular user:**
       - Navigate to a page where you can trigger the hijack functionality for `regular_user` (e.g., Django admin user list if you have integrated `HijackUserAdminMixin`, or a custom view using `can_hijack` template tag).
       - Click the hijack button/link for `regular_user`.
    6. **Verify successful hijack:**
       - You should be successfully logged in as `regular_user`, even though a staff user should not normally be able to hijack any user based on the default `superusers_only` permission.
       - Check the hijack notification is displayed, and `request.user.username` reflects `regular_user`.
    7. **Clean up (Important):**
       - After testing, revert `HIJACK_PERMISSION_CHECK` in your `settings.py` back to a secure setting like the default `hijack.permissions.superusers_only` and remove the vulnerable custom permission function.

- Vulnerability Name: Open Redirect Vulnerability in `next` parameter
- Description: The `acquire` and `release` views in `django-hijack` use a `next` parameter to redirect the user after a successful hijack or release action. If this `next` parameter is not properly validated, an attacker could craft a malicious URL and inject it into the `next` parameter, leading to an open redirect vulnerability. This could be used in phishing attacks to redirect users to attacker-controlled websites after they interact with the hijack feature.
- Impact: Redirection to malicious websites, potential phishing attacks, and user credential theft if the redirected site is designed to mimic a legitimate login page.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - The `SuccessUrlMixin` in `hijack/views.py` uses Django's `url_has_allowed_host_and_scheme` function to validate the `next` URL:
      ```python
      from django.utils.http import url_has_allowed_host_and_scheme

      class SuccessUrlMixin:
          # ...
          def get_redirect_url(self):
              """Return the user-originating redirect URL if it's safe."""
              redirect_to = self.request.POST.get(
                  self.redirect_field_name, self.request.GET.get(self.redirect_field_name, "")
              )
              url_is_safe = url_has_allowed_host_and_scheme(
                  url=redirect_to,
                  allowed_hosts=self.request.get_host(), # Potentially vulnerable if get_host() is not secure in all environments
                  require_https=self.request.is_secure(),
              )
              return redirect_to if url_is_safe else ""
      ```
    - This function checks if the hostname in the provided URL is in Django's `ALLOWED_HOSTS` setting.
- Missing mitigations:
    - The security relies on the correct configuration of Django's `ALLOWED_HOSTS`. If `ALLOWED_HOSTS` is misconfigured (e.g., set to `['*']` in development or too broadly in production), the `url_has_allowed_host_and_scheme` check can be bypassed.
    - The `allowed_hosts` parameter in `url_has_allowed_host_and_scheme` is set to `self.request.get_host()`. In certain server configurations or behind proxies, `get_host()` might return an untrusted or attacker-controlled value, potentially bypassing the intended host validation.
- Preconditions:
    - The application must be publicly accessible to external attackers.
    - An attacker needs to be able to trigger the hijack or release actions and manipulate the `next` parameter value.
- Source code analysis:
    - `hijack/views.py`: Both `AcquireUserView` and `ReleaseUserView` inherit from `SuccessUrlMixin`, which implements the redirect logic using `get_success_url` and `get_redirect_url`.
    - The `get_redirect_url` method uses `url_has_allowed_host_and_scheme` for validation, but its effectiveness depends on `ALLOWED_HOSTS` and the reliability of `request.get_host()`.
    - **Visualization:**
      ```
      User Action (Hijack/Release with next parameter) --> Browser Request --> AcquireUserView/ReleaseUserView --> SuccessUrlMixin.get_redirect_url --> url_has_allowed_host_and_scheme(url=next, allowed_hosts=request.get_host()) --> Redirect (if url_is_safe)
      ```
- Security test case:
    1. **Set up a test environment with a permissive `ALLOWED_HOSTS`:**
       - In your Django project's `settings.py`, set `ALLOWED_HOSTS` to include a broad domain or a wildcard that could be exploited. For example, in a testing environment, you might use:
         ```python
         # settings.py (for testing ONLY - INSECURE for production)
         ALLOWED_HOSTS = ['.example.com', '*']
         ```
         **Note:** Setting `ALLOWED_HOSTS = ['*']` is highly insecure in production and is only for demonstrating the vulnerability in a controlled test environment.
    2. **Log in as an admin user:**
       - Access your Django admin panel and log in as a superuser who has hijack permissions.
    3. **Craft a malicious `next` URL:**
       - Prepare a URL that points to an external website you control or a safe testing website for demonstration purposes (e.g., `http://malicious.example.com` or `https://www.google.com`).
    4. **Trigger a hijack request with the malicious `next` parameter:**
       - If you are using the Django admin integration, find a user to hijack.
       - Intercept the hijack form submission (e.g., using browser developer tools or a proxy) and modify the form data by adding or changing the `next` parameter to your malicious URL (e.g., `next=http://malicious.example.com`).
       - Submit the modified form.
       - Alternatively, if you are triggering hijack via a custom view, manually craft a POST request to the `hijack:acquire` URL with the `user_pk` and the malicious `next` parameter.
    5. **Verify Open Redirect:**
       - After submitting the hijack request, you should be redirected to the URL you provided in the `next` parameter (e.g., `http://malicious.example.com`).
       - Observe the browser's address bar to confirm the redirection.
    6. **Repeat for Release View:**
       - Perform a similar test for the release view (`hijack:release`). After hijacking a user, intercept the release form submission and modify the `next` parameter to a malicious URL.
       - Verify that you are redirected to the malicious URL after releasing the hijacked user.
    7. **Test with different `ALLOWED_HOSTS` configurations:**
       - Test with more restrictive `ALLOWED_HOSTS` settings to understand how the `url_has_allowed_host_and_scheme` validation behaves and if it can be bypassed with different URL formats or encoding.
    8. **Clean up (Important):**
       - After testing, ensure you revert `ALLOWED_HOSTS` in your `settings.py` to a secure and restrictive configuration that only includes your application's legitimate domains. Do not use wildcard `ALLOWED_HOSTS` in production.