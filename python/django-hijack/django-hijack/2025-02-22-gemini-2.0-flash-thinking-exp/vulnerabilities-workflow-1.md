## Combined Vulnerability List

This document consolidates vulnerabilities identified in the django-hijack project from multiple reports, removing duplicates and providing a comprehensive view of each issue.

### 1. Insecure Custom Permission Function leading to Privilege Escalation

- **Description:**
    If a developer implements a custom permission check function (`HIJACK_PERMISSION_CHECK`) incorrectly, it can lead to privilege escalation. This allows unauthorized users, who should not have hijack permissions, to impersonate other users. This occurs because the `AcquireUserView` directly imports and executes the function defined in `HIJACK_PERMISSION_CHECK` setting without any validation of its security properties. A flawed custom function can grant hijack permissions to unintended users.

    **Steps to trigger:**
    1. Configure `HIJACK_PERMISSION_CHECK` in `settings.py` to use a custom permission function.
    2. Implement a custom permission function with a logical flaw that allows unauthorized users to pass the permission check (e.g., allowing staff users to hijack anyone).
    3. An unauthorized user (e.g., a staff user in the example) attempts to hijack another user.
    4. The vulnerable custom permission function incorrectly grants hijack permission.
    5. The unauthorized user successfully hijacks the target user's account.

- **Impact:**
    Unauthorized account access, privilege escalation, potential data breach or unauthorized actions performed as another user. An attacker could gain access to sensitive data or perform actions on behalf of the hijacked user, depending on the permissions of the target user.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
    - The default permission function `hijack.permissions.superusers_only` is secure and restricts hijacking to superusers only.
    - Documentation in `SECURITY.md`, `docs/security.md`, and `docs/customization.md` warns developers about the security risks of writing custom permission functions and emphasizes the importance of thorough testing.

- **Missing mitigations:**
    - No input validation or security checks are performed on the custom permission function defined in `HIJACK_PERMISSION_CHECK`.
    - The project does not provide tools or guidelines to help developers write secure custom permission functions beyond a warning.
    - No built-in mechanism to prevent overly permissive custom functions (e.g., limiting the scope of permissions that can be granted).

- **Preconditions:**
    - The application must be configured to use a custom permission check function by setting `HIJACK_PERMISSION_CHECK` in `settings.py`.
    - The custom permission function implemented by the developer must contain a logical flaw that results in unintended users being granted hijack permissions.

- **Source code analysis:**
    - `hijack/conf.py`: The `HIJACK_PERMISSION_CHECK` setting is defined as a string that can be configured by the developer.
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
      - `import_string` dynamically imports the function based on the string path from settings.
      - `test_func` directly calls the imported function, relying entirely on the developer's implementation for security.
      - **Visualization:**
        ```
        settings.py (HIJACK_PERMISSION_CHECK = "path.to.custom_function") --> hijack/conf.py --> hijack/views.py (import_string(HIJACK_PERMISSION_CHECK)) --> custom_function (developer implemented, potential vulnerability)
        ```

- **Security test case:**
    1. **Create a vulnerable custom permission function:**
       ```python
       # my_permissions.py
       def insecure_permission_check(*, hijacker, hijacked):
           """Insecure permission check that allows staff users to hijack anyone."""
           if hijacker.is_staff:
               return True
           return False
       ```
    2. **Configure `HIJACK_PERMISSION_CHECK`:**
       ```python
       # settings.py
       HIJACK_PERMISSION_CHECK = "my_permissions.insecure_permission_check"
       ```
    3. **Create a staff user and a regular user.**
    4. **Log in as the staff user.**
    5. **Attempt to hijack the regular user** through the hijack functionality in the application.
    6. **Verify successful hijack:** The staff user is now logged in as the regular user, demonstrating privilege escalation due to the insecure custom permission function.
    7. **Clean up:** Revert `HIJACK_PERMISSION_CHECK` to a secure setting after testing.

### 2. Open Redirect Vulnerability in `next` parameter

- **Description:**
    The `acquire` and `release` views use a `next` parameter to redirect users after actions. If not validated properly, an attacker can inject a malicious URL into the `next` parameter, leading to an open redirect. This can be used for phishing by redirecting users to attacker-controlled sites after they interact with the hijack feature.

    **Steps to trigger:**
    1. Craft a malicious URL to an attacker-controlled website.
    2. Initiate a hijack or release action and include the malicious URL in the `next` parameter (e.g., via GET or POST).
    3. If `ALLOWED_HOSTS` is permissive or `request.get_host()` is unreliable, the `url_has_allowed_host_and_scheme` check may be bypassed.
    4. The user is redirected to the malicious URL after the hijack or release action.

- **Impact:**
    Redirection to malicious websites, potential phishing attacks, and user credential theft if the redirected site mimics a legitimate login page. Users might be tricked into entering credentials or sensitive information on the attacker's site, believing they are still interacting with the legitimate application.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
    - The `SuccessUrlMixin` uses Django's `url_has_allowed_host_and_scheme` to validate the `next` URL against `ALLOWED_HOSTS`.

- **Missing mitigations:**
    - Vulnerability relies on correct `ALLOWED_HOSTS` configuration. Misconfiguration (e.g., `['*']`) bypasses the check.
    - `url_has_allowed_host_and_scheme` uses `request.get_host()` for `allowed_hosts`. In some server setups (proxies), `get_host()` might be untrusted, potentially bypassing host validation.

- **Preconditions:**
    - Application must be publicly accessible.
    - Attacker must be able to trigger hijack/release actions and control the `next` parameter.

- **Source code analysis:**
    - `hijack/views.py`: `AcquireUserView` and `ReleaseUserView` inherit `SuccessUrlMixin`.
    - `SuccessUrlMixin.get_redirect_url` uses `url_has_allowed_host_and_scheme(url=redirect_to, allowed_hosts=self.request.get_host(), ...)` for validation.
    - Security depends on `ALLOWED_HOSTS` and reliability of `request.get_host()`.
    - **Visualization:**
      ```
      User Action (Hijack/Release with next parameter) --> Browser Request --> AcquireUserView/ReleaseUserView --> SuccessUrlMixin.get_redirect_url --> url_has_allowed_host_and_scheme(url=next, allowed_hosts=request.get_host()) --> Redirect (if url_is_safe)
      ```

- **Security test case:**
    1. **Set permissive `ALLOWED_HOSTS` for testing:** `ALLOWED_HOSTS = ['.example.com', '*']` (INSECURE for production!).
    2. **Log in as admin user.**
    3. **Craft malicious `next` URL:** e.g., `http://malicious.example.com`.
    4. **Trigger hijack with malicious `next`:** Intercept hijack form, add/modify `next` parameter.
    5. **Verify Open Redirect:** After hijack, you should be redirected to `http://malicious.example.com`.
    6. **Repeat for Release View.**
    7. **Test with different `ALLOWED_HOSTS` configurations** to understand validation behavior.
    8. **Clean up:** Revert `ALLOWED_HOSTS` to a secure configuration after testing.

### 3. Session Hijack History Manipulation

- **Description:**
    The hijack mechanism stores the original user's identifier in the session under `hijack_history`. On release, the `ReleaseUserView` pops the last ID from `hijack_history` and logs in that user. If Django's session engine uses client-side storage (like signed cookies) and the signing key (`SECRET_KEY`) is weak or compromised, an attacker with an authenticated session can tamper with `hijack_history`. By forging or manipulating this history, an attacker can insert an arbitrary user's ID. When the release endpoint is triggered, this manipulated ID is used to restore the session, leading to unauthorized impersonation and privilege escalation.

    **Steps to trigger:**
    1. Application uses client-side sessions (e.g., signed cookies) and a weak/compromised `SECRET_KEY`.
    2. Attacker obtains an authenticated session (even as a low-privilege user).
    3. Attacker manipulates the session cookie to alter `hijack_history`, inserting the ID of a target user (e.g., a high-privilege admin).
    4. Attacker triggers the release endpoint (`/hijack/release/`).
    5. The application uses the manipulated `hijack_history` to log the attacker in as the target user.

- **Impact:**
    Unauthorized user impersonation, privilege escalation (e.g., gaining superuser access), and access to sensitive information or restricted functionality. The attacker can effectively become any user whose ID they can inject into the session, potentially gaining full control of the application.

- **Vulnerability Rank:** Critical

- **Currently implemented mitigations:**
    - Django's `login()` function is used, which flushes the session on login, mitigating some session fixation risks.
    - Session integrity relies on Django's session framework signing (if properly deployed with a strong `SECRET_KEY`).
    - CSRF protection is applied to hijack acquire and release views.

- **Missing mitigations:**
    - No additional validation or integrity check on `hijack_history` contents beyond session signing. A weak `SECRET_KEY` in client-side sessions allows forging session data.
    - No enforced recommendation to use server-side sessions or ensure a strong `SECRET_KEY` for hijack functionality.
    - No verification that the user ID in `hijack_history` is associated with the original authenticated user beyond a simple lookup during release.

- **Preconditions:**
    - Attacker must have an authenticated session.
    - Application uses client-side session storage (e.g., signed cookies).
    - Weak, default, or compromised `SECRET_KEY` allows forging session data.
    - No server-side validation of `hijack_history` authenticity.

- **Source code analysis:**
    1. **Acquire:** `AcquireUserView.post()` retrieves `hijack_history` from session, appends current user ID, and saves back to session.
    2. **Release:** `ReleaseUserView.post()` pops the last `user_pk` from `hijack_history`.
    3. **Login:** Uses `get_object_or_404(User, pk=user_pk)` to retrieve user and `login(request, hijacker, backend=backend)`.
    4. **Trust:** Mechanism trusts session data (`hijack_history`) without further validation.
    - **Visualization:**
      - **Hijack:** Original session: `{ ..., "hijack_history": [] }` -> After hijack: `{ ..., "hijack_history": ["<original user id>"] }`
      - **Release:** View pops from `hijack_history` to log back in. Manipulation of `hijack_history` can lead to logging in as a target user.

- **Security test case:**
    1. **Setup:** Deploy with client-side sessions (signed cookies) and a weak `SECRET_KEY` (for testing only!). Authenticate as a low-privilege user (attacker account).
    2. **Tamper Session:** Manually modify session cookie to include altered `hijack_history` with a target user's primary key. This may involve decoding, modifying, and re-signing the cookie (if feasible in test setup) or using tools to simulate weak signature bypass.
    3. **Trigger Release:** Send POST request to `/hijack/release/` with CSRF token and tampered session cookie.
    4. **Expected Behavior:** Redirect (HTTP 302) to success URL. Subsequent authenticated request should show the attacker logged in as the target user.
    5. **Verification:** Confirm attacker's session is "released" as the unintended target user, demonstrating session manipulation leading to impersonation.