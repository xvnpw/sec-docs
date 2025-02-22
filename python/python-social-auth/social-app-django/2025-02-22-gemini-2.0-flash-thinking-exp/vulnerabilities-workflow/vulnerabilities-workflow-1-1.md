- Vulnerability Name: Insecure Session Expiration Handling leading to Session Fixation or Extended Session Lifetime
- Description:
    The `get_session_timeout` function in `social_django/views.py` calculates the session expiration time based on backend settings (`SESSION_EXPIRATION`, `MAX_SESSION_LENGTH`) and the expiration time provided by the social authentication provider (`social_user.expiration_datetime()`). However, if `SESSION_EXPIRATION` is enabled but the social provider does not return an expiration time (`social_user.expiration_datetime()` returns `None`), and `MAX_SESSION_LENGTH` is also not set, the function incorrectly defaults to `DEFAULT_SESSION_TIMEOUT` which is explicitly set to `None`. This results in the session being set to platform default session lifetime instead of a more secure, shorter expiration, potentially leading to session fixation or unnecessarily extended session lifetime.

    Steps to trigger:
    1. Configure a social authentication backend (e.g., Facebook) in Django settings.
    2. Enable session expiration by setting `SOCIAL_AUTH_\[BACKEND_NAME]_SESSION_EXPIRATION = True` in Django settings.
    3. Ensure that `SOCIAL_AUTH_\[BACKEND_NAME]_MAX_SESSION_LENGTH` is not set or is set to `None`.
    4. Authenticate a user using the configured social backend.
    5. If the social authentication provider does not return an expiration time (this behavior depends on the specific provider and its API), the Django session will be set to the platform default lifetime, which might be very long or indefinite.
    6. An attacker could potentially exploit this by performing a session fixation attack before the user authenticates, or by leveraging an excessively long session lifetime if they gain access to a user's session cookie.

- Impact:
    High. If session expiration is not properly enforced to a reasonable timeframe, it increases the risk of session fixation and session hijacking. An attacker could potentially gain unauthorized access to a user's account by exploiting a long-lived session.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    The code attempts to handle session expiration based on backend settings and provider-supplied expiration. It also includes logic to use `MAX_SESSION_LENGTH` as a maximum session duration.

- Missing Mitigations:
    The logic in `get_session_timeout` needs to be corrected to enforce a reasonable default session timeout even when the social provider doesn't return an expiration and `MAX_SESSION_LENGTH` is not configured. A sensible default `MAX_SESSION_LENGTH` should be enforced if `SESSION_EXPIRATION` is enabled to prevent excessively long sessions.

- Preconditions:
    1. `SESSION_EXPIRATION` setting is enabled for a social backend.
    2. `MAX_SESSION_LENGTH` is not configured or set to `None` for that backend.
    3. The social authentication provider does not return session expiration information.

- Source Code Analysis:
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

- Security Test Case:
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