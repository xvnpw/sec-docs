- **Vulnerability Name:** Insecure Default Django Settings (DEBUG True and Hardcoded SECRET_KEY)
  - **Description:**
    The project’s testing settings (in `tests/settings.py`) use a hardcoded secret key and have `DEBUG` set to `True`. Although these settings are meant for test purposes only, if a publicly available instance is accidentally deployed using these insecure defaults, an external attacker can trigger detailed error pages and gain insight into the application’s internal configuration. This information may then be used to craft further attacks (for example, forging session cookies or exploiting other weaknesses based on the exposed internal state).
    - **Steps to Trigger:**
      1. Deploy the application using the settings module defined in `tests/settings.py` (where `DEBUG = True` and the secret key is hardcoded).
      2. Visit a URL that causes an unhandled exception (or any misconfigured endpoint) so that Django displays its full error page.
      3. An attacker views the debug output, which reveals sensitive information such as the SECRET_KEY, file paths, and stack traces.
  - **Impact:**
    An attacker can obtain sensitive internal details—including the hardcoded SECRET_KEY—that may allow the forging of session cookies, bypass of authentication mechanisms, or further reconnaissance to exploit other vulnerabilities in the application. The disclosure of internal error messages and configurations increases the risk of targeted attacks.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    There are no mitigations in place in the repository. The insecure settings are present in the test configuration file and are not automatically separated from production–capable configurations.
  - **Missing Mitigations:**
    - Do not deploy the test settings in a production environment.
    - Use environment variables (or a secure vault) to inject the `SECRET_KEY` at runtime rather than hardcoding it.
    - Ensure that `DEBUG` is set to `False` in production settings.
    - Clearly separate test/development settings from production settings.
  - **Preconditions:**
    The vulnerability can be exploited if a developer or system operator accidentally deploys the application using the test settings (from `tests/settings.py`) in a publicly accessible environment.
  - **Source Code Analysis:**
    In `tests/settings.py` the following lines expose the sensitive configuration:
    ```python
    SECRET_KEY = "o)04)%_us9ed1l7*cv&5@t(2*r#$^r7o(q^4p@y9@b20_ay_jv"
    DEBUG = True
    ```
    These hardcoded values and the enabled debug mode cause Django to emit detailed error information when an exception occurs.
  - **Security Test Case:**
    1. Deploy the application using the `tests/settings.py` settings module (or simulate a misconfiguration that uses these settings).
    2. Deliberately trigger an error (for example, access a non-existent URL or force an exception in a view).
    3. Confirm that the error page displays extensive debug information—including the SECRET_KEY and stack traces.
    4. Attempt to use the exposed SECRET_KEY to forge Django session cookies (or otherwise tamper with authentication) and verify that you can compromise the session security.