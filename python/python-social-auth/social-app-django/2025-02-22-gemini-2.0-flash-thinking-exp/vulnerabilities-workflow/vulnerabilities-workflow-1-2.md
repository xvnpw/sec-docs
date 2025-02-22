- **Vulnerability Name:** Open Redirect via SocialAuthExceptionMiddleware

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