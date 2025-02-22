- **Vulnerability Name:** Unrestricted Access to Feature Flag Configuration Data
  - **Description:**
    The application exposes endpoints (specifically, `/waffle/waffle_status` and `/waffle/wafflejs`) that return complete details about every defined feature flag, switch, and sample. An attacker can simply send a GET request to one of these URLs to obtain a JSON dump (or JavaScript code) revealing internal configuration data such as active states and last‐modified timestamps.
    *Step by step to trigger:*
    1. From an external network (without authentication), browse to the URL `/waffle/waffle_status`.
    2. Observe that the response contains a JSON object detailing all flags, switches, and samples (e.g. each flag’s `is_active` status and `last_modified` value).
    3. Similarly, a GET request to `/waffle/wafflejs` returns JavaScript that embeds the same information.
  - **Impact:**
    Sensitive internal details are disclosed to any unauthenticated user. This information disclosure may allow attackers to learn about experimental or disabled features, internal system states, or scheduling—potentially helping craft further attacks against the application or its administration interfaces.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    There is no access control or authentication check on these endpoints. They are decorated only with `@never_cache` (meant solely to prevent caching) and are included in the public URL patterns.
  - **Missing Mitigations:**
    – Restrict access to the feature configuration endpoints by adding authentication and authorization (for example, by requiring that requests come from internal networks or authenticated admin users).
    – Consider removing or limiting the exposure of this data in production.
  - **Preconditions:**
    The attacker must have network access to the publicly available instance of the application. No credentials are required.
  - **Source Code Analysis:**
    - In `/code/waffle/views.py`, the function `waffle_json(request)` returns a JSON response built by `_generate_waffle_json(request)`. This function queries all flags via
      ```python
      flags = get_waffle_flag_model().get_all()
      flag_values = {f.name: {'is_active': f.is_active(request), 'last_modified': f.modified} for f in flags}
      ```
      and similarly for switches and samples.
    - The URL configuration in `/code/waffle/urls.py` includes paths for these views without any form of access control.
  - **Security Test Case:**
    1. Using a tool such as curl or a browser in an incognito window, send a GET request to `http://<target>/waffle/waffle_status`.
    2. Confirm that the HTTP response code is 200 and that the `Content-Type` header indicates JSON.
    3. Inspect the response body and verify that it includes keys such as `"flags"`, `"switches"`, and `"samples"` along with detailed values (for example, each flag’s active status and modification timestamp).
    4. Repeat the test for `/waffle/wafflejs` and check that the returned JavaScript embeds the same information.
    5. Conclude that internal configuration details have been exposed without access control.

---

- **Vulnerability Name:** Insecure Test Configuration Used in Production
  - **Description:**
    The project includes a settings file (`test_settings.py`) that is used by the provided startup script (`run.sh`) and CI/CD workflows. This file sets critical values insecurely for a production environment—it enables debugging (`DEBUG = True`) and uses a weak, hardcoded secret key (`SECRET_KEY = 'foobar'`). An attacker could exploit the exposed debug information and easily guess or forge cryptographic tokens if this configuration is deployed in a public production environment.
    *Step by step to trigger:*
    1. Deploy the application using the provided `run.sh` script (which exports `DJANGO_SETTINGS_MODULE="test_settings"`).
    2. As an unauthenticated user, trigger an error (for example, by accessing a non-existent route) so that Django’s debug error page is displayed.
    3. Examine the error page for sensitive internal details (such as stack traces and settings).
    4. Optionally, attempt to tamper with or forge session cookies knowing that they are signed using the weak secret key.
  - **Impact:**
    Running with `DEBUG = True` in production can lead to detailed error messages being displayed to attackers; these messages may reveal sensitive information (such as file paths, configuration details, and even portions of source code). In addition, a weak secret key undermines security measures including session signing and cryptographic tokens, making session hijacking or other forgery attacks feasible.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    None. The repository’s default configuration in `test_settings.py` is intended only for testing but is used by default in the startup script and workflows.
  - **Missing Mitigations:**
    – Provide a separate, production-ready settings file that sets `DEBUG = False` and uses a strong, unpredictable secret key.
    – Ensure that the production deployment cannot accidentally use the insecure `test_settings.py`.
  - **Preconditions:**
    The deployed instance must be using `test_settings.py` (or otherwise misconfigured with debugging enabled and a weak secret key) and be publicly accessible.
  - **Source Code Analysis:**
    - In `/code/test_settings.py`, the configuration sets:
      ```python
      DEBUG = True
      SECRET_KEY = 'foobar'
      ```
      and uses SQLite databases.
    - The shell script `run.sh` unconditionally sets `DJANGO_SETTINGS_MODULE="test_settings"`, meaning that even in a production environment, the insecure settings might be used.
  - **Security Test Case:**
    1. Deploy the application using the provided `run.sh` script without modifications.
    2. As an external user, trigger an error (for example, by browsing to a non-existent URL) and verify that a detailed Django debug error page is shown with a stack trace and internal configuration details.
    3. Check that the session cookies (or any cryptographically signed cookies) are being generated with a known value (i.e. that the secret key is the weak string “foobar”).
    4. Confirm that sensitive debugging information is visible and that cryptographic protections may be easily bypassed.
    5. Recommend that production deployments never use these settings.