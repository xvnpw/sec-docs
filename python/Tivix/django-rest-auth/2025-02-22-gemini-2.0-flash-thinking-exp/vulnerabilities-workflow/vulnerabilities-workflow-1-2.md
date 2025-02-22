- **Vulnerability Name:** Debug Mode Enabled in Production
  **Description:**
  The demo project’s settings have debugging enabled (i.e. `DEBUG = True`) and an empty `ALLOWED_HOSTS` list. An external attacker can deliberately trigger an error (for example, by accessing a non‑existent URL) in order to force Django to display a full debug traceback. This error page will reveal detailed information about the system such as file paths, configuration parameters, versions, and sometimes even environment data.
  **Impact:**
  An attacker who views the debug output may gain valuable intelligence about the internal application structure and configuration—including sensitive variables—which can be used to engineer further attacks (for example, by targeting other misconfigured endpoints or exploiting hard‑coded keys).
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  No mitigation is apparent. The settings file (/code/demo/demo/settings.py) hard-codes `DEBUG = True` and does not restrict permitted hosts.
  **Missing Mitigations:**
  • Set `DEBUG = False` in production deployments.
  • Configure proper `ALLOWED_HOSTS` (including explicit domain names) so that error pages are not exposed.
  **Preconditions:**
  The vulnerable configuration is active when the application is deployed using the demo settings in a production‑like environment.
  **Source Code Analysis:**
  In the file `/code/demo/demo/settings.py`, the beginning of the file contains:
  ```python
  # SECURITY WARNING: don't run with debug turned on in production!
  DEBUG = True
  ALLOWED_HOSTS = []
  ```
  This indicates that the default configuration is meant for development. However, if deployed publicly, any triggered error (for example, by requesting an unknown URL) will cause Django’s debug page—with full stack traces and settings—to be shown.
  **Security Test Case:**
  1. Deploy the application using the current production‑like configuration (using demo settings).
  2. From an external client (or browser), request a non‑existent route (e.g. `https://your-app.example.com/nonexistent`).
  3. Confirm that the resulting error page displays a detailed traceback with system paths, settings, and other sensitive debugging information.

- **Vulnerability Name:** Hard‑coded Secret Key in Production
  **Description:**
  The demo settings include a hard‑coded secret key that is used for cryptographic signing throughout the application. If an attacker gains knowledge of this key, they could forge session cookies, tamper with password reset tokens, and potentially subvert other security‑critical functions provided by Django.
  **Impact:**
  Disclosure of the secret key can lead to authentication bypass, session hijacking, and other attacks that trivially compromise the integrity of the application.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  None. The file `/code/demo/demo/settings.py` contains a static assignment for the secret key:
  ```python
  SECRET_KEY = 'ma3c@7uu!%e0=tynp+i6+q%$)9v@$t(eulqurym_b=48z82&5n'
  ```
  **Missing Mitigations:**
  • Do not hard-code the secret key in source code.
  • Load the secret key at runtime from an environment variable or secure secrets management system.
  **Preconditions:**
  The vulnerability is exploitable when the application instance is deployed with the demo settings containing the fixed key, and the source code (or key value) is accessible to an attacker.
  **Source Code Analysis:**
  In `/code/demo/demo/settings.py`, the secret key is defined as a literal string. There are no conditional steps or runtime overrides that would allow a dynamically generated or environment‑provided value. This means that in any public deployment using these settings, the same secret key is used over and over.
  **Security Test Case:**
  1. Examine the deployed configuration to retrieve the value of `SECRET_KEY`.
  2. Using the known key, attempt to forge or tamper with authentication cookies or password reset tokens.
  3. Verify that the application accepts tokens or cookies signed with that key.

- **Vulnerability Name:** Unsecured JWT Cookie (Missing Secure Flag)
  **Description:**
  When JWT‑based authentication is enabled (i.e. `REST_USE_JWT` is True) and a JWT cookie is to be set via the login view, the cookie is created with the `httponly` attribute but without the `secure` flag. This means that if the application is served over HTTP—or if there is a misconfiguration in TLS—the token may be exposed to network sniffing.
  **Impact:**
  An attacker on the same network or a man‑in‑the‑middle attacker could capture the JWT cookie if it is sent over an insecure channel. With the captured JWT, the attacker could impersonate the legitimate user and access protected resources.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  The cookie is marked as `httponly` in `/code/rest_auth/views.py` (in the `get_response` method of LoginView), which helps mitigate client‑side scripting access.
  **Missing Mitigations:**
  • The cookie needs to be sent with the `secure` flag to ensure it is transmitted only over HTTPS.
  • Enforce strict transport security on the application.
  **Preconditions:**
  • `REST_USE_JWT` is enabled in the settings.
  • The application is accessed over HTTP or on a network where TLS is not guaranteed end‑to‑end.
  **Source Code Analysis:**
  In `/code/rest_auth/views.py`, the following snippet is used when setting the JWT cookie:
  ```python
  if getattr(settings, 'REST_USE_JWT', False):
      from rest_framework_jwt.settings import api_settings as jwt_settings
      if jwt_settings.JWT_AUTH_COOKIE:
          from datetime import datetime
          expiration = (datetime.utcnow() + jwt_settings.JWT_EXPIRATION_DELTA)
          response.set_cookie(jwt_settings.JWT_AUTH_COOKIE,
                              self.token,
                              expires=expiration,
                              httponly=True)
  ```
  Notice that no parameter (e.g. `secure=True`) is set here.
  **Security Test Case:**
  1. Enable JWT‑based authentication in the settings and deploy the application.
  2. From an external client, perform a login request over an HTTP (non‑HTTPS) connection.
  3. Use browser developer tools or a proxy (such as Burp Suite) to inspect the attributes of the JWT cookie and confirm that it lacks the `Secure` flag.
  4. Optionally simulate a network eavesdropping scenario to demonstrate token capture.

- **Vulnerability Name:** Lack of Rate Limiting on Authentication Endpoints
  **Description:**
  The login (and related authentication) views in the project do not implement any form of rate limiting or brute‑force protection. An attacker may send a high volume of login attempts with differing credentials without being throttled or blocked.
  **Impact:**
  This lack of protection exposes the system to brute‑force attacks. Using automated tools, an attacker may try many username/password combinations to eventually break into a user’s account, particularly if weak passwords are in use.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  There is no evidence of any rate‑limiting logic in any of the authentication endpoints (for example, in `/code/rest_auth/views.py` in the LoginView).
  **Missing Mitigations:**
  • Implement a rate limiting mechanism on login and password reset endpoints (for example, using middleware or third‑party packages such as Django Ratelimit or Axes).
  • Consider account lockout policies or CAPTCHA challenges after a defined number of failed attempts.
  **Preconditions:**
  The endpoints for login, password reset, and related actions are publicly available and accept unauthenticated requests.
  **Source Code Analysis:**
  In `/code/rest_auth/views.py`, the `LoginView` class processes POST requests to validate user credentials. There is no code that tracks the number of failed attempts or delays subsequent authentication attempts based on failure counts. This absence means that an attacker can continuously attempt logins without any rate‑limiting intervention.
  **Security Test Case:**
  1. Automate a series of login requests targeting the login endpoint (e.g. using a tool like Burp Suite Intruder or a custom script).
  2. Use an invalid username/password combination in rapid succession.
  3. Observe that the system does not slow down, block, or otherwise throttle the requests after repeated authentication failures.
  4. Verify that the same endpoint continues to respond in a timely manner to each request despite numerous failed attempts.