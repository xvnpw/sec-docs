## Combined Vulnerability List

This document consolidates the following vulnerabilities identified in the social-auth-app-django project. Each vulnerability is detailed below with its description, impact, rank, mitigations, preconditions, source code analysis, and a security test case.

### 1. Insecure Session Expiration Handling leading to Session Fixation or Extended Session Lifetime

- **Description:**
    The `get_session_timeout` function in `social_django/views.py` calculates the session expiration time based on backend settings (`SESSION_EXPIRATION`, `MAX_SESSION_LENGTH`) and the expiration time provided by the social authentication provider (`social_user.expiration_datetime()`). However, if `SESSION_EXPIRATION` is enabled but the social provider does not return an expiration time (`social_user.expiration_datetime()` returns `None`), and `MAX_SESSION_LENGTH` is also not set, the function incorrectly defaults to `DEFAULT_SESSION_TIMEOUT` which is explicitly set to `None`. This results in the session being set to platform default session lifetime instead of a more secure, shorter expiration, potentially leading to session fixation or unnecessarily extended session lifetime.

    Steps to trigger:
    1. Configure a social authentication backend (e.g., Facebook) in Django settings.
    2. Enable session expiration by setting `SOCIAL_AUTH_\[BACKEND_NAME]_SESSION_EXPIRATION = True` in Django settings.
    3. Ensure that `SOCIAL_AUTH_\[BACKEND_NAME]_MAX_SESSION_LENGTH` is not set or is set to `None`.
    4. Authenticate a user using the configured social backend.
    5. If the social authentication provider does not return an expiration time (this behavior depends on the specific provider and its API), the Django session will be set to the platform default lifetime, which might be very long or indefinite.
    6. An attacker could potentially exploit this by performing a session fixation attack before the user authenticates, or by leveraging an excessively long session lifetime if they gain access to a user's session cookie.

- **Impact:**
    High. If session expiration is not properly enforced to a reasonable timeframe, it increases the risk of session fixation and session hijacking. An attacker could potentially gain unauthorized access to a user's account by exploiting a long-lived session.

- **Vulnerability Rank:** high

- **Currently Implemented Mitigations:**
    The code attempts to handle session expiration based on backend settings and provider-supplied expiration. It also includes logic to use `MAX_SESSION_LENGTH` as a maximum session duration.

- **Missing Mitigations:**
    The logic in `get_session_timeout` needs to be corrected to enforce a reasonable default session timeout even when the social provider doesn't return an expiration and `MAX_SESSION_LENGTH` is not configured. A sensible default `MAX_SESSION_LENGTH` should be enforced if `SESSION_EXPIRATION` is enabled to prevent excessively long sessions.

- **Preconditions:**
    1. `SESSION_EXPIRATION` setting is enabled for a social backend.
    2. `MAX_SESSION_LENGTH` is not configured or set to `None` for that backend.
    3. The social authentication provider does not return session expiration information.

- **Source Code Analysis:**
    ```python
    # /code/social_django/views.py

    DEFAULT_SESSION_TIMEOUT = None  # Line 15

    def get_session_timeout(social_user, enable_session_expiration=False, max_session_length=None): # Line 41
        if enable_session_expiration: # Line 42
            expiration = social_user.expiration_datetime() # Line 45

            if expiration: # Line 49
                received_expiration_time = expiration.total_seconds() # Line 50
            else:
                received_expiration_time = DEFAULT_SESSION_TIMEOUT # Line 52  <- Vulnerability: If no provider expiration, defaults to None

            if received_expiration_time is None and max_session_length is None: # Line 56
                session_expiry = DEFAULT_SESSION_TIMEOUT # Line 58 <- Vulnerability: Still None, platform default will be used
            elif received_expiration_time is None and max_session_length is not None: # Line 59
                session_expiry = max_session_length # Line 61
            elif received_expiration_time is not None and max_session_length is None: # Line 62
                session_expiry = received_expiration_time # Line 64
            else:
                session_expiry = min(received_expiration_time, max_session_length) # Line 67
        else: # Line 68
            if max_session_length is None: # Line 71
                session_expiry = DEFAULT_SESSION_TIMEOUT # Line 73 <- Vulnerability: Still None, platform default will be used if expiration disabled and no max_length
            else:
                session_expiry = max_session_length # Line 75

        return session_expiry # Line 78

    def _do_login(backend, user, social_user): # Line 81
        # ...
        session_expiry = get_session_timeout( # Line 105
            social_user,
            enable_session_expiration=enable_session_expiration,
            max_session_length=max_session_length,
        )

        try: # Line 111
            backend.strategy.request.session.set_expiry(session_expiry) # Line 112
        except OverflowError: # Line 113
            backend.strategy.request.session.set_expiry(DEFAULT_SESSION_TIMEOUT) # Line 115
    ```
    The code in `get_session_timeout` function, specifically lines 52 and 58, and lines 73, sets `session_expiry` to `DEFAULT_SESSION_TIMEOUT` (which is `None`) when either the social provider does not provide an expiration time and `MAX_SESSION_LENGTH` is not set, or when session expiration is disabled and `max_session_length` is also not set. This will cause Django to use platform default session expiration, which might be undesirable from a security perspective if a shorter session lifetime is intended.

- **Security Test Case:**
    1. Set up Django project with `social-auth-app-django` and configure a social backend (e.g., Facebook, but any backend that doesn't reliably return session expiration is suitable for testing).
    2. In `settings.py`, enable session expiration for the social backend:
       ```python
       SOCIAL_AUTH_FACEBOOK_SESSION_EXPIRATION = True
       # Ensure MAX_SESSION_LENGTH is NOT set for this backend
       # SOCIAL_AUTH_FACEBOOK_MAX_SESSION_LENGTH = ... # Do not set this
       ```
    3. Log in to the Django application using the configured social backend.
    4. After successful login, inspect the session cookie in the browser or using developer tools. Check the `Expires/Max-Age` attribute of the session cookie.
    5. If the session cookie's expiration is set to a very long time (e.g., weeks, months, or browser session), it indicates the vulnerability. The expected behavior with `SESSION_EXPIRATION = True` should be a shorter, more controlled session timeout, even if the social provider doesn't provide expiration details.
    6. To further confirm, you can check Django's default session expiration setting in your Django project (e.g., `SESSION_COOKIE_AGE` in `settings.py`). If the observed session expiration matches Django's default, it confirms that the social auth session expiration logic is defaulting to the platform default instead of enforcing a secure timeout.

### 2. Open Redirect via SocialAuthExceptionMiddleware

- **Description:**
  An attacker can potentially force an unintended redirection by triggering an authentication exception. Here’s how the vulnerability can be triggered step by step:
  - The social authentication flow uses a middleware—`SocialAuthExceptionMiddleware`—that catches exceptions inheriting from `SocialAuthBaseException` during the authentication process.
  - When such an exception is caught (for example, by providing an invalid or non‐existent backend during the OAuth callback), the middleware calls its helper method `get_redirect_uri()`. This method simply retrieves a URL from the application’s settings using the key `LOGIN_ERROR_URL` (via the strategy’s settings).
  - The middleware then calls Django’s built‑in `redirect()` function with the URL obtained. No additional validation is performed on this URL.
  - If the application’s configuration (i.e. the value of `SOCIAL_AUTH_LOGIN_ERROR_URL`) is misconfigured or is inadvertently set to an absolute URL pointing to an external (or attacker‑controlled) domain rather than a safe relative URL, an attacker can use the authentication error trigger to redirect a user to a malicious site.
  In summary, by deliberately causing an exception in the social authentication flow (for example, by specifying an invalid backend in the URL), and if the application’s error‑redirect setting is not strictly controlled, the attacker can force a redirect to an arbitrary external URL.

- **Impact:**
  Exploitation of this vulnerability could lead to phishing attacks or other forms of social engineering. If a user is redirected without warning to a malicious site, they may unknowingly enter sensitive data (such as credentials), thereby compromising their account and potentially the security of the entire application.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - The redirect URL is obtained solely from the server‑side settings (via `strategy.setting("LOGIN_ERROR_URL")`), which in many deployments is configured as a safe, relative URL (as shown in tests such as `test_login_error_url`).
  - Django’s built‑in redirect function is used, which normally works safely when provided with relative URLs.

- **Missing Mitigations:**
  - There is no explicit validation or sanitization in the middleware to ensure that the URL obtained from `LOGIN_ERROR_URL` is safe (for example, by checking that it is a relative URL or belongs to an allowed whitelist of domains).
  - In the absence of additional checks, a misconfigured or attacker-influenced setting could cause an open redirect.

- **Preconditions:**
  - The application’s settings for social authentication (specifically, `SOCIAL_AUTH_LOGIN_ERROR_URL`) must be misconfigured to an absolute URL or one that points to an untrusted/external domain.
  - An attacker must be able to trigger a social authentication exception (for example, by sending a request to the OAuth callback endpoint with an invalid backend name).

- **Source Code Analysis:**
  1. In `social_django/middleware.py`, the `process_exception()` method is defined to handle any caught exceptions.
  2. When an exception is an instance of `SocialAuthBaseException`, the middleware retrieves the error message and calls `self.get_redirect_uri(request, exception)`.
  3. The `get_redirect_uri()` method calls the strategy’s setting method:
     ```python
     def get_redirect_uri(self, request, exception):
         strategy = getattr(request, "social_strategy", None)
         return strategy.setting("LOGIN_ERROR_URL")
     ```
     This passes the configured `SOCIAL_AUTH_LOGIN_ERROR_URL` (or its equivalent) directly onward.
  4. Finally, the middleware uses the Django `redirect(url)` function with this URL, appending query parameters (including portions of the exception message) without checking whether the URL is relative (internal) or absolute (external).
  5. As a result, if the setting is an absolute URL, the middleware may cause an open redirect to an attacker-controlled domain.

- **Security Test Case:**
  1. **Setup:** Configure the application with a misconfigured `SOCIAL_AUTH_LOGIN_ERROR_URL` (for example, set it in your settings or via an override to an external URL such as `https://malicious.example.com/attack`).
  2. **Trigger the Exception:**
     - Initiate an OAuth callback by sending a GET request to the social authentication complete endpoint (e.g., `/complete/invalid-backend?code=123&state=abc`).
     - Since “invalid-backend” is not a recognized social auth provider, the social authentication pipeline will raise a `SocialAuthBaseException`.
  3. **Observe the Response:**
     - The `SocialAuthExceptionMiddleware` catches the exception and retrieves the redirect URL (which comes from the misconfigured `LOGIN_ERROR_URL`).
     - The response is an HTTP 302 redirect.
  4. **Verification:**
     - Follow the redirect in your testing tool (for example, using curl or a web browser) and verify that the URL redirects to `https://malicious.example.com/attack` (with additional query parameters appended as determined by the middleware).
     - This confirms that an attacker—with knowledge of this misconfiguration—can force users to be redirected to an external site.

### 3. Case-insensitive UID lookup vulnerability in `UserSocialAuth.get_social_auth` on case-insensitive databases (CVE-2024-32879)

- **Vulnerability Name:** Case-insensitive UID lookup vulnerability in `UserSocialAuth.get_social_auth` on case-insensitive databases (CVE-2024-32879)

- **Description:**
    In `social_django/models.py`, the `UserSocialAuth.get_social_auth` method performs a case-insensitive lookup for social authentication records when using database backends like MySQL with default settings, or SQLite. This case-insensitivity can be exploited in scenarios where usernames or UIDs differ only in case. An attacker can potentially link their social account to another user's account if they can create a social account entry with a UID that differs only in case from an existing user's social account UID.

    Steps to trigger:
    1. Use a database backend that is case-insensitive by default for string comparisons (e.g., MySQL with default collation, SQLite).
    2. Have two user accounts in the system, say 'User1' and 'user1' (or, more relevantly, social UIDs differing by case).
    3. User 'Attacker' attempts to link their social account using a social provider.
    4. During the account linking process, the attacker crafts a social UID that is the same as 'User1's UID but with a different case (if 'User1' has a social account linked).
    5. Due to the case-insensitive lookup in `UserSocialAuth.get_social_auth`, the attacker's social account might be incorrectly linked to 'User1's account instead of creating a new account or linking to the attacker's intended account.

- **Impact:**
    High. This vulnerability can lead to account takeover or unauthorized account linking. An attacker might be able to link their social login to a victim's account or gain access to a victim's account by exploiting the case-insensitive UID lookup.

- **Vulnerability Rank:** high

- **Currently Implemented Mitigations:**
    The vulnerability is mitigated in version 5.4.1 and later by enforcing case-sensitive lookups in `UserSocialAuth.get_social_auth`. The fix involves using `iexact=uid` for case-insensitive databases and `exact=uid` for case-sensitive databases, ensuring correct behavior across different database systems.

- **Missing Mitigations:**
    Prior to version 5.4.1, there was no explicit handling for case-sensitive vs. case-insensitive database lookups in `UserSocialAuth.get_social_auth`.

- **Preconditions:**
    1. The Django application uses `social-auth-app-django` version prior to 5.4.1.
    2. The application is configured to use a database backend that is case-insensitive for lookups by default (e.g., MySQL with default collation, SQLite).
    3. There exist user accounts or social UIDs in the system that differ only in case.

- **Source Code Analysis:**
    ```python
    # social_django/models.py (Vulnerable version - before 5.4.1)
    def get_social_auth(cls, provider, uid):
        try:
            return cls.objects.get(provider=provider, uid=uid)  # Case-insensitive lookup on some DBs
        except cls.DoesNotExist:
            return None
    ```
    In vulnerable versions, `UserSocialAuth.get_social_auth` uses `cls.objects.get(provider=provider, uid=uid)`. On case-insensitive databases, the `uid=uid` lookup is performed case-insensitively. This can cause incorrect `UserSocialAuth` records to be retrieved if multiple records exist with UIDs that are the same when case is ignored.

    ```python
    # social_django/models.py (Fixed version - 5.4.1 and later)
    def get_social_auth(cls, provider, uid):
        lookup_kwargs = {'provider': provider}
        if connection.features.has_case_insensitive_like: # Check for case-insensitive DB
            lookup_kwargs['uid__iexact'] = uid # Use iexact for case-insensitive lookup
        else:
            lookup_kwargs['uid'] = uid # Use exact for case-sensitive lookup
        try:
            return cls.objects.get(**lookup_kwargs)
        except cls.DoesNotExist:
            return None
    ```
    The fixed version checks `connection.features.has_case_insensitive_like` to determine if the database performs case-insensitive lookups. If it does, it uses `uid__iexact=uid` to explicitly perform a case-insensitive lookup (which, in this corrected version, is ironically ensuring correct behavior by being *explicitly* case-insensitive where needed and case-sensitive where the DB is case-sensitive by default). For case-sensitive databases, it uses `uid=uid` for a case-sensitive lookup. This ensures that the lookup is always performed correctly according to the database's case sensitivity behavior.

- **Security Test Case:**
    1. Set up a Django project with `social-auth-app-django` version prior to 5.4.1 and configure it to use SQLite or MySQL with default case-insensitive collation.
    2. Create two Django user accounts (e.g., via Django admin or `createsuperuser`).
    3. Manually create `UserSocialAuth` records in the database for each user, using the same `provider` but UIDs that differ only in case (e.g., 'UserID' and 'userid'). You can use Django's shell (`python manage.py shell`) to create these records using the `UserSocialAuth` model.
    4. Implement a view that attempts to retrieve a `UserSocialAuth` record using `UserSocialAuth.get_social_auth` with one of the case-variant UIDs.
    5. Test retrieving the `UserSocialAuth` record using different cases for the UID in the `get_social_auth` call.
    6. Observe that in vulnerable versions, retrieving with either case might incorrectly return the same `UserSocialAuth` record due to the case-insensitive lookup.
    7. Upgrade `social-auth-app-django` to version 5.4.1 or later and repeat the test. Observe that the lookup now behaves case-sensitively (or explicitly case-insensitively where intended), and retrieving with different cases will yield different or no results as expected.
    8. To simulate an attack, attempt to link a social account using a UID that is a case variant of an existing user's social UID and verify if the account is incorrectly linked.