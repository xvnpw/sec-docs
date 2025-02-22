- **Vulnerability Name:** Insecure Use of Default Test reCAPTCHA Keys in Production
  **Description:**
  The library falls back to using Google’s public test keys (defined in `django_recaptcha/constants.py`) when the production configuration does not specify proper `RECAPTCHA_PUBLIC_KEY` and `RECAPTCHA_PRIVATE_KEY` values. Google’s test keys always validate the captcha response as successful. An attacker does not even need to interact with the widget correctly to pass the captcha verification.
  **Step-by-Step Trigger:**
  1. A production deployment is made without overriding the default test keys (or with keys set to the test values).
  2. The Django application instantiates a form containing a `ReCaptchaField` that automatically uses the test keys.
  3. An attacker visits the public form and submits it with an arbitrary or even absent `g-recaptcha-response` value.
  4. The backend calls `client.submit` (in `django_recaptcha/fields.py`), which passes the test key along with the response to Google’s verification API.
  5. As the test keys always return success, the form’s validation passes, effectively bypassing the reCAPTCHA protection.
  **Impact:**
  The bypassed captcha permits automated submissions. This not only opens the door for spam and abuse, but also makes other automated attacks (e.g. brute force login attempts) more likely, thereby undermining the intended bot prevention mechanism on the publicly available instance.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - A system check is registered in `django_recaptcha/checks.py` that detects and emits a warning if the test keys are detected.
  - However, this check is advisory only and can be silenced using `SILENCED_SYSTEM_CHECKS` in the Django settings.
  **Missing Mitigations:**
  - No enforcement exists to block operation when test keys are in use in a production environment.
  - An automated safeguard (or build-time check) that prevents deployment with the insecure test keys is missing.
  **Preconditions:**
  - The production settings do not override the default test keys (i.e. `RECAPTCHA_PUBLIC_KEY` and `RECAPTCHA_PRIVATE_KEY` remain as defined for testing).
  **Source Code Analysis:**
  - In `django_recaptcha/fields.py`, the `ReCaptchaField.__init__` method assigns:
    ```python
    self.private_key = private_key or getattr(settings, "RECAPTCHA_PRIVATE_KEY", TEST_PRIVATE_KEY)
    self.public_key = public_key or getattr(settings, "RECAPTCHA_PUBLIC_KEY", TEST_PUBLIC_KEY)
    ```
    …meaning that if the settings are omitted, the test keys are used.
  - Meanwhile, the system check in `django_recaptcha/checks.py` compares the supplied keys against the test keys and issues a warning but does not prevent form processing.
  **Security Test Case:**
  1. Deploy the application without setting production reCAPTCHA keys (or explicitly set them to the test keys).
  2. Navigate to a page with a form that includes a `ReCaptchaField`.
  3. Submit the form with any arbitrary value (or even no valid captcha response).
  4. Verify that the form submission is accepted despite bypassing the actual captcha challenge—confirming that test keys are in use and that the captcha verification is effectively disabled.

- **Vulnerability Name:** Unvalidated HTTP_X_FORWARDED_FOR Header Allows IP Spoofing in reCAPTCHA Verification
  **Description:**
  When verifying the reCAPTCHA response (in `django_recaptcha/fields.py`), the library calls the helper method `get_remote_ip` to determine the client’s IP address. This method searches the current request’s metadata for both `REMOTE_ADDR` and `HTTP_X_FORWARDED_FOR`, and it uses the value of `HTTP_X_FORWARDED_FOR` if it exists—without any additional validation. In environments that are not correctly configured to trust only proxy-provided headers, an external attacker can inject or manipulate the `HTTP_X_FORWARDED_FOR` header. In scenarios using reCAPTCHA v3 (which relies on a risk score that is partly determined by the client’s IP address), this spoofing could potentially influence the score returned by Google’s verification and allow borderline or malicious responses to be accepted.
  **Step-by-Step Trigger:**
  1. An attacker crafts an HTTP request to a page that includes a `ReCaptchaField`.
  2. The attacker sets the `HTTP_X_FORWARDED_FOR` header to an arbitrary, attacker‑controlled IP address (preferably one known to have a benign reputation).
  3. The form processes the request. Inside `get_remote_ip`, the presence of `HTTP_X_FORWARDED_FOR` causes this attacker‑supplied IP to be used instead of the true client IP from `REMOTE_ADDR`.
  4. This spoofed IP is sent along with the reCAPTCHA response to Google’s server. For reCAPTCHA v3, the risk analysis may thereby use a more favorable client IP, potentially skewing the returned score in the attacker’s favor.
  **Impact:**
  The risk score computed as part of the reCAPTCHA verification may be improperly elevated. This can lead to automated or malicious submissions bypassing the intended threshold checks, undermining the effectiveness of the captcha challenge and increasing the likelihood of spam, abuse, or more sophisticated attack vectors.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - There is no explicit validation or filtration of the `HTTP_X_FORWARDED_FOR` header in the project code.
  **Missing Mitigations:**
  - The library does not restrict or validate the source of the `HTTP_X_FORWARDED_FOR` header against a list of trusted proxies.
  - It lacks a mechanism to sanitize or verify that the IP address obtained is indeed the true client IP.
  **Preconditions:**
  - The application is deployed in an environment where it is not behind a properly configured reverse proxy that sanitizes client IP information.
  - The attacker is able to control the HTTP headers of the incoming request.
  **Source Code Analysis:**
  - In the file `django_recaptcha/fields.py`, the method is defined as:
    ```python
    def get_remote_ip(self):
        f = sys._getframe()
        while f:
            request = f.f_locals.get("request")
            if request:
                remote_ip = request.META.get("REMOTE_ADDR", "")
                forwarded_ip = request.META.get("HTTP_X_FORWARDED_FOR", "")
                ip = remote_ip if not forwarded_ip else forwarded_ip
                return ip
            f = f.f_back
    ```
    There is no check to ensure that the value in `HTTP_X_FORWARDED_FOR` comes from a trusted source.
  **Security Test Case:**
  1. Deploy the application in a test environment without enforcing trusted proxy settings.
  2. Using a tool such as cURL, Postman, or Burp Suite, craft an HTTP POST request to submit a form that uses `ReCaptchaField`.
  3. Manually add a custom `HTTP_X_FORWARDED_FOR` header with a benign or pre‑specified IP address.
  4. Submit the form with a valid or borderline captcha token (especially in a reCAPTCHA v3 scenario).
  5. Confirm via logging or proxy inspection that the reCAPTCHA verification request sent to Google includes the spoofed IP value, and verify whether this influences the validation outcome (e.g. results in a score that meets the acceptance threshold).