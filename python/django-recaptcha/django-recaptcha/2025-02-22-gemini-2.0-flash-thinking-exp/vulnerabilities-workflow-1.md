## Combined Vulnerability List

This document outlines the combined list of vulnerabilities identified, removing duplicates and consolidating information from the provided lists.

### 1. IP Address Spoofing in reCAPTCHA Validation

- **Description:**
    The `ReCaptchaField` in `django-recaptcha` retrieves the user's IP address using the `get_remote_ip` function, which prioritizes the `HTTP_X_FORWARDED_FOR` header over `REMOTE_ADDR`. In environments behind proxies, the `HTTP_X_FORWARDED_FOR` header can be easily manipulated by attackers. This can lead to IP address spoofing when the application relies on the IP address obtained during reCAPTCHA validation for security purposes, and potentially influence the risk score in reCAPTCHA v3.

    **Steps to trigger vulnerability:**
    1. An attacker sends an HTTP request to an application protected by django-recaptcha, ensuring the application is behind a proxy or in an environment where `HTTP_X_FORWARDED_FOR` is not properly sanitized by a trusted proxy.
    2. The attacker includes a crafted `HTTP_X_FORWARDED_FOR` header in their request, setting it to a spoofed IP address of their choice.
    3. The Django application, using `django-recaptcha`, processes this request. The `ReCaptchaField` in the form will call `get_remote_ip`.
    4. `get_remote_ip` function will prioritize and return the spoofed IP address from the `HTTP_X_FORWARDED_FOR` header without validation.
    5. This spoofed IP address is then sent to Google's reCAPTCHA verification service as part of the validation process. For reCAPTCHA v3, this can influence the risk score.
    6. If the reCAPTCHA verification is successful, and the application proceeds to use the IP address obtained from `ReCaptchaField.get_remote_ip()` for subsequent security decisions (like logging, access control, fraud detection, or risk scoring in v3), it will be using a potentially spoofed IP address.

- **Impact:**
    If the Django application relies on the IP address obtained during reCAPTCHA validation for security-sensitive operations, this vulnerability can lead to:
    - Bypassing IP-based access controls.
    - Inaccurate audit logs, making it difficult to track malicious activity.
    - Circumventing fraud detection mechanisms that rely on IP address verification.
    - Improperly elevated risk score in reCAPTCHA v3, potentially leading to automated or malicious submissions bypassing intended threshold checks.
    In essence, an attacker can misrepresent their origin IP address to the Django application and potentially influence reCAPTCHA v3 score, while still passing the reCAPTCHA challenge, undermining security measures that depend on IP address accuracy after reCAPTCHA validation.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    No mitigations are implemented in the `django-recaptcha` project to address IP address spoofing via `HTTP_X_FORWARDED_FOR`. The `get_remote_ip` function directly uses the value from `HTTP_X_FORWARDED_FOR` if available without any validation or sanitization against spoofing, and there is no explicit validation or filtration of this header in the project code.

- **Missing Mitigations:**
    The project is missing mitigations to handle potential IP address spoofing. Recommended missing mitigations include:
    - Documentation warning: Add a clear warning in the documentation about the risk of relying on IP addresses obtained through `ReCaptchaField.get_remote_ip()` for security decisions, especially in proxy environments, due to the spoofability of `HTTP_X_FORWARDED_FOR`.
    - Consider alternative IP retrieval methods: If IP address accuracy is critical, suggest or implement methods to obtain more reliable client IP addresses in proxy environments, possibly by inspecting other proxy headers or using middleware that correctly handles proxy configurations.
    - Restrict or validate the source of the `HTTP_X_FORWARDED_FOR` header against a list of trusted proxies.
    - Implement a mechanism to sanitize or verify that the IP address obtained is indeed the true client IP.
    However, complete prevention of IP spoofing at the application level is complex and often environment-dependent. The primary mitigation should be to advise developers against relying solely on client IP addresses for critical security decisions derived from `ReCaptchaField.get_remote_ip()`.

- **Preconditions:**
    - The Django application using `django-recaptcha` is deployed behind a proxy server or in an environment where `HTTP_X_FORWARDED_FOR` is not reliably controlled by trusted proxies.
    - The application logic relies on the IP address obtained from `ReCaptchaField.get_remote_ip()` after successful reCAPTCHA validation for security-relevant operations, including access control, logging, fraud prevention, or reCAPTCHA v3 risk assessment.
    - An attacker is able to send HTTP requests to the application and can manipulate the `HTTP_X_FORWARDED_FOR` header.

- **Source Code Analysis:**
    - File: `/code/django_recaptcha/fields.py`
    - Function: `get_remote_ip()`

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

    Visualization:

    ```
    User Request --> Proxy Server --> Django Application (django-recaptcha)

    User Request (with spoofed X-Forwarded-For)
    ----------------------------------------> Proxy Server
                                                |
    Proxy Server forwards request to Django App --> Django Application
                                                    |
    django_recaptcha.fields.ReCaptchaField.get_remote_ip() is called
                                                    |
    get_remote_ip() checks request.META['HTTP_X_FORWARDED_FOR'] --> Spoofed IP is retrieved
                                                    |
    Spoofed IP is used for reCAPTCHA validation request & returned to application
                                                    |
    Application uses Spoofed IP for security logic ----> Vulnerability if application relies on IP
    ```

    The `get_remote_ip` function in `ReCaptchaField` directly retrieves the IP from `HTTP_X_FORWARDED_FOR` if it exists, without validating its source or sanitizing the input. This makes it vulnerable to spoofing if the application is behind a proxy or in an environment where `HTTP_X_FORWARDED_FOR` is not properly handled and the application relies on this IP for security.

- **Security Test Case:**
    1. Set up a Django project with `django-recaptcha` integrated into a form.
    2. Deploy this Django application behind a proxy (e.g., Nginx, Apache) or in a test environment without enforcing trusted proxy settings.
    3. Modify the Django view handling the form to log the IP address obtained from `ReCaptchaField.get_remote_ip()` after successful form validation.
    4. As an attacker, use a tool like `curl`, Postman, Burp Suite, or a browser's developer tools to send a POST request to the form endpoint.
    5. Include a header `X-Forwarded-For: 1.2.3.4` in the request. Ensure a valid reCAPTCHA response is also submitted to pass the reCAPTCHA validation itself. For reCAPTCHA v3 test with both valid and borderline captcha tokens.
    6. After submitting the form, check the application logs or proxy inspection.
    7. Verify that the logged IP address is `1.2.3.4`, the spoofed IP from the `X-Forwarded-For` header, and not the actual IP address of the attacker.
    8. For reCAPTCHA v3, confirm via logging or proxy inspection that the reCAPTCHA verification request sent to Google includes the spoofed IP value, and verify whether this influences the validation outcome (e.g. results in a score that meets the acceptance threshold).
    9. If the application were to use this logged IP address or reCAPTCHA v3 score for any security decision (e.g., blocking IPs, logging locations, adjusting risk thresholds), this test demonstrates the vulnerability as the decision would be based on a spoofed IP.


### 2. Insecure Use of Default Test reCAPTCHA Keys in Production

- **Vulnerability Name:** Insecure Use of Default Test reCAPTCHA Keys in Production

- **Description:**
    The `django-recaptcha` library uses Google’s public test reCAPTCHA keys by default if production keys are not explicitly configured in Django settings. These test keys always validate the captcha response as successful, regardless of the actual user interaction with the widget or the provided response. This effectively disables reCAPTCHA protection in production environments if developers fail to override the default test keys.

    **Step-by-Step Trigger:**
    1. A production Django deployment is made without setting or overriding the `RECAPTCHA_PUBLIC_KEY` and `RECAPTCHA_PRIVATE_KEY` settings in the project's `settings.py` file.
    2. The application uses a form with `ReCaptchaField`, which, upon initialization, defaults to using the test keys defined within `django_recaptcha/constants.py`.
    3. An attacker or automated bot accesses a public form containing the reCAPTCHA field.
    4. The form is submitted with an arbitrary or even missing `g-recaptcha-response` value.
    5. The backend validation process calls `client.submit` within `django_recaptcha/fields.py`, using the default test keys for verification against Google’s reCAPTCHA API.
    6. Google’s reCAPTCHA service, upon receiving a validation request with the test keys, always returns a success response.
    7. Consequently, the form validation in Django passes, bypassing the intended reCAPTCHA protection.

- **Impact:**
    By bypassing reCAPTCHA, the application becomes vulnerable to automated submissions. This can lead to:
    - Spam submissions on forms (e.g., contact forms, registration forms).
    - Abuse of application features reliant on form submissions.
    - Increased risk of automated attacks like brute-force login attempts, as the primary bot prevention mechanism is disabled.
    - Overall undermining of the intended security posture of publicly available instances of the application.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The library includes a system check (`django_recaptcha/checks.py`) that detects if the test keys are being used and issues a warning during Django's system check process.
    - This system check is advisory and generates a warning message, but it does not prevent the application from running with test keys in production.
    - The warning can be silenced using `SILENCED_SYSTEM_CHECKS` in Django settings, potentially leading developers to ignore or suppress the warning inadvertently.

- **Missing Mitigations:**
    - There is no enforced mechanism to prevent the application from running or being deployed with the insecure default test reCAPTCHA keys in a production environment.
    - A safeguard, such as an automated build-time check or a setting to explicitly disallow test keys in production, is missing. This would prevent accidental or negligent deployments with weakened security.

- **Preconditions:**
    - The Django application is deployed to a production environment.
    - The `RECAPTCHA_PUBLIC_KEY` and `RECAPTCHA_PRIVATE_KEY` settings are not explicitly configured in the Django project's `settings.py`, or they are intentionally or mistakenly set to the default test key values.

- **Source Code Analysis:**
    - File: `django_recaptcha/fields.py`
    - Method: `ReCaptchaField.__init__`

    ```python
    # django_recaptcha/fields.py
    from django_recaptcha.conf import settings
    from django_recaptcha.constants import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY

    class ReCaptchaField(fields.CharField):
        def __init__(self, ... , private_key=None, public_key=None, ...):
            super().__init__(...)
            self.widget = widgets.ReCaptchaWidget(api_params=api_params, public_key=public_key, ... )
            self.private_key = private_key or getattr(settings, "RECAPTCHA_PRIVATE_KEY", TEST_PRIVATE_KEY)
            self.public_key = public_key or getattr(settings, "RECAPTCHA_PUBLIC_KEY", TEST_PUBLIC_KEY)
            ...
    ```
    The `ReCaptchaField.__init__` method shows that if `private_key` or `public_key` are not explicitly passed during field instantiation, it falls back to using values from Django settings. If these settings are not defined, it defaults to `TEST_PRIVATE_KEY` and `TEST_PUBLIC_KEY` from `django_recaptcha.constants`.

    - File: `django_recaptcha/checks.py`
    - Function: `check_test_keys_used`

    ```python
    # django_recaptcha/checks.py
    from django.conf import settings
    from django.core.checks import Error, Warning, register

    from django_recaptcha.constants import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY

    @register()
    def check_test_keys_used(app_configs, **kwargs):
        errors = []
        if getattr(settings, "RECAPTCHA_PRIVATE_KEY", None) == TEST_PRIVATE_KEY or \
           getattr(settings, "RECAPTCHA_PUBLIC_KEY", None) == TEST_PUBLIC_KEY:
            errors.append(
                Warning(
                    "Using test keys in production!",
                    hint="You are using the default test reCAPTCHA keys. Please configure RECAPTCHA_PRIVATE_KEY and RECAPTCHA_PUBLIC_KEY in your settings.",
                    obj=None,
                    id="django_recaptcha.W001",
                )
            )
        return errors
    ```
    The system check `check_test_keys_used` verifies if the settings match the test keys and issues a `Warning`, but does not prevent operation.

- **Security Test Case:**
    1. Deploy a Django application to a test or staging environment configured to mimic production, but without explicitly setting `RECAPTCHA_PUBLIC_KEY` and `RECAPTCHA_PRIVATE_KEY` in `settings.py`.
    2. Navigate to a page in the deployed application that contains a form with a `ReCaptchaField`.
    3. Attempt to submit the form without correctly completing the reCAPTCHA challenge, or even without providing any `g-recaptcha-response` value.
    4. Verify that the form submission is successfully processed by the application, indicating that the reCAPTCHA validation has been bypassed due to the use of test keys.
    5. Further confirm by inspecting the reCAPTCHA verification requests (if possible) that test keys were indeed used in the validation process.
    6. Check Django system check output (e.g., during `python manage.py check`) to observe the warning message about using test keys in production, confirming the presence of the implemented, but non-enforcing, mitigation.