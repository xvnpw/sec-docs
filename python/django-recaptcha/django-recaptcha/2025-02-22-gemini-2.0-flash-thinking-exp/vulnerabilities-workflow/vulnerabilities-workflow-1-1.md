### Vulnerability List:

- Vulnerability Name: IP Address Spoofing in reCAPTCHA Validation

- Description:
    The `ReCaptchaField` retrieves the user's IP address from the `HTTP_X_FORWARDED_FOR` or `REMOTE_ADDR` headers. In the `get_remote_ip` function within `django_recaptcha/fields.py`, the code first checks for the `HTTP_X_FORWARDED_FOR` header and uses it if present. If not, it falls back to `REMOTE_ADDR`. In environments behind a proxy (like typical web deployments), the `HTTP_X_FORWARDED_FOR` header can be easily manipulated by an attacker.

    Steps to trigger vulnerability:
    1. An attacker sends an HTTP request to an application protected by django-recaptcha, ensuring the application is behind a proxy.
    2. The attacker includes a crafted `HTTP_X_FORWARDED_FOR` header in their request, setting it to a spoofed IP address of their choice.
    3. The Django application, using `django-recaptcha`, processes this request. The `ReCaptchaField` in the form will call `get_remote_ip`.
    4. `get_remote_ip` function will prioritize and return the spoofed IP address from the `HTTP_X_FORWARDED_FOR` header.
    5. This spoofed IP address is then sent to Google's reCAPTCHA verification service as part of the validation process.
    6. If the reCAPTCHA verification is successful (which is independent of the IP address in many cases), and the application proceeds to use the IP address obtained from `ReCaptchaField.get_remote_ip()` for subsequent security decisions (like logging, access control, or fraud detection), it will be using a potentially spoofed IP address.

- Impact:
    If the Django application relies on the IP address obtained during reCAPTCHA validation for security-sensitive operations, such as access control, auditing, or fraud prevention, this vulnerability can lead to:
    - Bypassing IP-based access controls.
    - Inaccurate audit logs, making it difficult to track malicious activity.
    - Circumventing fraud detection mechanisms that rely on IP address verification.
    In essence, an attacker can misrepresent their origin IP address to the Django application, while still passing the reCAPTCHA challenge, potentially undermining security measures that depend on IP address accuracy after reCAPTCHA validation.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    No mitigations are implemented in the `django-recaptcha` project to address IP address spoofing via `HTTP_X_FORWARDED_FOR`. The `get_remote_ip` function directly uses the value from `HTTP_X_FORWARDED_FOR` if available without any validation or sanitization against spoofing.

- Missing Mitigations:
    The project is missing mitigations to handle potential IP address spoofing. Recommended missing mitigations include:
    - Documentation warning: Add a clear warning in the documentation about the risk of relying on IP addresses obtained through `ReCaptchaField.get_remote_ip()` for security decisions, especially in proxy environments, due to the spoofability of `HTTP_X_FORWARDED_FOR`.
    - Consider alternative IP retrieval methods: If IP address accuracy is critical, suggest or implement methods to obtain more reliable client IP addresses in proxy environments, possibly by inspecting other proxy headers or using middleware that correctly handles proxy configurations. However, complete prevention of IP spoofing at the application level is complex and often environment-dependent. The primary mitigation should be to advise developers against relying solely on client IP addresses for critical security decisions.

- Preconditions:
    - The Django application using `django-recaptcha` is deployed behind a proxy server.
    - The application logic relies on the IP address obtained from `ReCaptchaField.get_remote_ip()` after successful reCAPTCHA validation for security-relevant operations.
    - An attacker is able to send HTTP requests to the application and can manipulate the `HTTP_X_FORWARDED_FOR` header.

- Source Code Analysis:
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

    The `get_remote_ip` function in `ReCaptchaField` directly retrieves the IP from `HTTP_X_FORWARDED_FOR` if it exists, making it vulnerable to spoofing if the application is behind a proxy and relies on this IP for security.

- Security Test Case:
    1. Set up a Django project with `django-recaptcha` integrated into a form.
    2. Deploy this Django application behind a proxy (e.g., Nginx, Apache).
    3. Modify the Django view handling the form to log the IP address obtained from `ReCaptchaField.get_remote_ip()` after successful form validation.
    4. As an attacker, use a tool like `curl` or a browser's developer tools to send a POST request to the form endpoint.
    5. Include a header `X-Forwarded-For: 1.2.3.4` in the request. Ensure a valid reCAPTCHA response is also submitted to pass the reCAPTCHA validation itself.
    6. After submitting the form, check the application logs.
    7. Verify that the logged IP address is `1.2.3.4`, the spoofed IP from the `X-Forwarded-For` header, and not the actual IP address of the attacker.
    8. If the application were to use this logged IP address for any security decision (e.g., blocking IPs, logging locations), this test demonstrates the vulnerability as the decision would be based on a spoofed IP.