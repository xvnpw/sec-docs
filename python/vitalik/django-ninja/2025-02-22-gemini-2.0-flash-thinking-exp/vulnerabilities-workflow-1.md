### Vulnerability List

#### CSRF Protection Misconfiguration Vulnerability

- Vulnerability name: CSRF Protection Misconfiguration Vulnerability
- Description:
    An attacker can induce a state-changing action by luring an authenticated user to a malicious webpage that automatically submits a forged request. This vulnerability occurs when CSRF protection is disabled or misconfigured in a Django Ninja application that uses cookie-based authentication.

    1. An attacker crafts a malicious website containing a Cross-Site Request Forgery (CSRF) attack.
    2. A user authenticates to a Django Ninja application that uses cookie-based authentication (e.g., Django sessions, APIKeyCookie). This results in the application setting a session cookie in the user's browser.
    3. The developer of the Django Ninja application, either unknowingly or intentionally, disables CSRF protection. This can be done by setting `csrf=False` during `NinjaAPI` initialization.
    4. While the user is logged into the Django Ninja application and their session cookie is active, they visit the attacker's malicious website in the same browser.
    5. The malicious website, without the user's awareness, sends a cross-site request to the Django Ninja application. This request is designed to perform an action, such as modifying data or executing administrative functions, that the attacker intends. The browser automatically includes the Django Ninja application's session cookie with this cross-site request.
    6. Because CSRF protection is disabled in the Django Ninja application (due to `csrf=False`), the application does not perform standard CSRF token validation to verify the request's origin.
    7. The Django Ninja application only verifies the presence of a valid session cookie. Since the browser automatically sent the session cookie, the application considers the request to be authenticated.
    8. The Django Ninja application processes the attacker's malicious request as if it were a legitimate user action, leading to the execution of unauthorized actions.
    9. The attacker successfully performs actions on behalf of the logged-in user, potentially leading to account compromise, data breaches, or unintended operations within the application.
- Impact:
    - Account Takeover: An attacker could change user passwords or email addresses, gaining control over user accounts.
    - Data Manipulation: Critical data could be modified, deleted, or corrupted, leading to data integrity issues or loss.
    - Unauthorized Transactions: Users might be unknowingly made to perform actions like financial transactions or data transfers.
    - Privilege Escalation: If an administrative account is targeted, attackers could gain complete control over the Django Ninja application and its data.
- Vulnerability rank: High
- Currently implemented mitigations:
    - Django Ninja framework has an automatic CSRF protection mechanism. When cookie-based authentication methods like `APIKeyCookie`, `SessionAuth`, or `django_auth` are used, CSRF protection is automatically enabled by default. This default behavior is implemented in the `NinjaAPI` constructor in `ninja/main.py` and documented in `/code/docs/docs/reference/csrf.md` and `/code/docs/docs/whatsnew_v1.md`.
    - The `APIKeyCookie` security class in `ninja/security/apikey.py`, which is the base for `SessionAuth` and `SessionAuthSuperUser` in `ninja/security/session.py`, includes CSRF checks by default. The `__init__` method of `APIKeyCookie` sets `self.csrf = csrf` with a default value of `True`, and the `_get_key` method calls `check_csrf(request)` if `self.csrf` is True.
    - The framework’s documentation and sample code explicitly warn that CSRF protection is disabled by default when `csrf=False` is set, and show how to enable it (by setting `csrf=True` or relying on default behavior when using cookie-based auth).
    - A deprecation warning is issued in `ninja/main.py` when the `csrf` argument is used, alerting developers that CSRF is now handled via the auth mechanism—but without enforcing a secure default.
- Missing mitigations:
    - No explicit runtime warning for intentional CSRF disabling: If a developer explicitly sets `csrf=False` in `NinjaAPI` constructor while also using cookie-based authentication, there is no runtime warning or error raised to highlight the security implications. This lack of immediate feedback might lead to unintentional exposure to CSRF attacks if developers are not fully aware of the risks of disabling CSRF in such setups.
    - Documentation prominence and stronger warning: While CSRF protection is documented, the documentation could be improved by:
        - Placing a more prominent warning in the CSRF documentation section about the risks of disabling CSRF, specifically when using cookie-based authentication.
        - Adding a strong recommendation against disabling CSRF unless for very specific use-cases (like public APIs with non-browser clients only) and with a clear understanding of the security consequences.
        - Including guidance on alternative approaches if developers believe they have reasons to disable CSRF, encouraging them to reconsider or implement other security measures.
    - No runtime enforcement exists to automatically enable CSRF protection when cookie‑based authentication is used and `csrf=False` is explicitly set.
    - A more secure default (or a production‑time warning) would help prevent inadvertent deployment with CSRF disabled when using cookie-based authentication.
- Preconditions:
    - Cookie-based Authentication in Use: The Django Ninja application must be configured to use a cookie-based authentication mechanism (e.g., Django sessions, `APIKeyCookie`, `SessionAuth`).
    - CSRF Protection Explicitly Disabled: The `NinjaAPI` constructor must be initialized with `csrf=False`.
    - Active User Session: A user must be logged into the Django Ninja application, possessing a valid session cookie in their browser.
    - User Interaction with External Malicious Content: The logged-in user must visit a website or interact with content controlled by the attacker (e.g., through a link in an email or visiting a malicious site) that is designed to execute a CSRF attack against the Django Ninja application.
    - The API is publicly accessible and deployed using the `csrf=False` setting while relying on cookie‑ or session‑based authentication.
- Source code analysis:
    - `ninja/main.py`:
        - The `NinjaAPI` class constructor handles the `csrf` argument. It automatically enables CSRF protection if `auth` is provided and `csrf` is not explicitly set to `False`.
        ```python
        def __init__(
            self,
            *,
            ...,
            csrf: bool = False,
            auth: Optional[Union[Sequence[Callable], Callable, NOT_SET_TYPE]] = NOT_SET,
            ...
        ):
            ...
            if auth is not NOT_SET and not csrf: # auto csrf
                self.csrf = True
            else:
                self.csrf = csrf
            ...
        ```
    - `ninja/security/apikey.py`:
        - The `APIKeyCookie` class initializes `csrf` to `True` by default and uses the `check_csrf` utility function to validate CSRF tokens if `csrf` is enabled.
        ```python
        class APIKeyCookie(APIKeyBase, ABC):
            openapi_in: str = "cookie"

            def __init__(self, csrf: bool = True) -> None:
                self.csrf = csrf
                super().__init__()

            def _get_key(self, request: HttpRequest) -> Optional[str]:
                if self.csrf:
                    error_response = check_csrf(request)
                    if error_response:
                        raise HttpError(403, "CSRF check Failed")
                return request.COOKIES.get(self.param_name)
        ```
    - `ninja/utils.py`:
        - The `check_csrf` function leverages Django's `CsrfViewMiddleware` to perform CSRF validation.
        ```python
        def check_csrf(
            request: HttpRequest, callback: Callable = _no_view
        ) -> Optional[HttpResponseForbidden]:
            mware = CsrfViewMiddleware(lambda x: HttpResponseForbidden())  # pragma: no cover
            request.csrf_processing_done = False  # type: ignore
            mware.process_request(request)
            return mware.process_view(request, callback, (), {})
        ```
    - `docs/docs/reference/csrf.md` and `docs/docs/whatsnew_v1.md`:
        - Documentation confirms the default CSRF protection behavior and provides information on how to configure and use CSRF protection in Django Ninja.
- Security test case:
    1. Set up a vulnerable Django Ninja API application:
        - Define a Django Ninja API endpoint that is protected with cookie-based authentication. For instance, use `APIKeyCookie` or Django's session authentication (`django_auth`).
        - Initialize the `NinjaAPI` instance with CSRF protection explicitly disabled: `api = NinjaAPI(csrf=False, auth=...)`.
        - Create a POST endpoint, for example `/api/change_email/`, that modifies a user-related attribute (like email). This endpoint should be protected by the configured cookie-based authentication.
    2. Develop a malicious HTML website for CSRF attack:
        - Create an HTML file (can be hosted locally or on a separate server).
        - In the HTML body, include a form that automatically submits a POST request to the `/api/change_email/` endpoint of the Django Ninja application upon page load (using JavaScript for auto-submission).
        - The form should include a field (e.g., `new_email`) with a value chosen by the attacker to demonstrate the exploit.
        ```html
        <html>
        <head>
            <title>CSRF Attack</title>
        </head>
        <body>
            <h1>CSRF Attack!</h1>
            <form id="csrf-form" action="http://your-django-ninja-app.com/api/change_email/" method="POST">
                <input type="hidden" name="new_email" value="attacker@example.com">
            </form>
            <script>
                document.getElementById('csrf-form').submit();
            </script>
        </body>
        </html>
        ```
        - Replace `http://your-django-ninja-app.com/api/change_email/` with the actual URL of your vulnerable endpoint.
    3. Authenticate as a user:
        - Open a web browser and log in to the Django Ninja application with valid user credentials. This establishes a session and stores the session cookie in the browser.
    4. Access the malicious website:
        - In the same browser session where you are logged into the Django Ninja application, navigate to the malicious HTML file you created.
    5. Observe the successful CSRF exploit:
        - Upon loading the malicious HTML page, the embedded form will automatically submit a POST request to the Django Ninja application's `/api/change_email/` endpoint.
        - Verify that the email address associated with the logged-in user in the Django Ninja application has been changed to `attacker@example.com`. This confirms the CSRF attack was successful because the application processed the unauthorized request due to the disabled CSRF protection and the presence of the valid session cookie.

#### Debug Mode Information Disclosure Vulnerability

- Vulnerability name: Debug Mode Information Disclosure Vulnerability
- Description:
    When Django’s `DEBUG` setting is left enabled in production, unhandled exceptions trigger error responses that include detailed tracebacks. Attackers can deliberately send malformed or invalid input to API endpoints to trigger exceptions. The full traceback—including file paths, code snippets, and configuration information—is then returned in the HTTP response.
- Impact:
    Sensitive internal details (such as source code layout, installed modules, and framework configuration) are disclosed, aiding further targeted attacks and simplifying automated vulnerability scanning.
- Vulnerability rank: High
- Currently implemented mitigations:
    - Best practices documented by Django and reinforced by test files specify that `DEBUG` must be set to False in production.
    - The default exception handler (in `ninja/errors.py`) sanitizes error output only when `DEBUG` is False.
- Missing mitigations:
    - There is no safe‑by‑default mode; the framework relies entirely on the developer to set `DEBUG=False` in production.
    - An additional safeguard or runtime warning when detailed error output is detected in a production setting is missing.
- Preconditions:
    - The API instance is deployed with Django’s `DEBUG=True`, and an attacker is able to trigger an unhandled exception on a public endpoint.
- Source code analysis:
    - In `ninja/errors.py`, the `_default_exception()` function returns the full traceback (via `traceback.format_exc()`) as plain text when `settings.DEBUG` is True.
    - The helper function `debug_server_url_reimport()` in `ninja/main.py` is used to detect development‑mode re‐imports but does not mitigate the exposure of sensitive error details.
- Security test case:
    1. Deploy the API with `DEBUG=True` (mimicking a production misconfiguration).
    2. Identify an endpoint and send a request with invalid JSON or deliberately malformed data to trigger an exception.
    3. Capture the HTTP response and inspect its body to verify that it contains a detailed traceback with internal file paths and configuration details.
    4. Expected Outcome: The response discloses the complete traceback, confirming the information disclosure vulnerability.

#### Insufficient Rate Limiting on Authentication Endpoints Vulnerability

- Vulnerability name: Insufficient Rate Limiting on Authentication Endpoints Vulnerability
- Description:
    Throttling classes are available within the framework (such as `AnonRateThrottle`, `AuthRateThrottle`, and `UserRateThrottle` defined in `ninja/throttling.py`); however, if developers do not explicitly configure throttle limits on sensitive endpoints (for instance, those validating API keys), then no rate limiting is enforced. This lack of default protections allows attackers to script rapid, repeated authentication attempts (brute‑forcing credentials) with minimal delay.
- Impact:
    Attackers might guess valid API keys or credentials by exploiting the absence of conservative rate limits, leading to unauthorized access.
- Vulnerability rank: High
- Currently implemented mitigations:
    - The framework provides robust, configurable throttle classes and includes tests that demonstrate their functionality when explicitly applied.
- Missing mitigations:
    - There is no secure‑by‑default throttle configuration for authentication endpoints; if developers overlook specifying throttle objects (leaving the throttle attribute as NOT_SET), the endpoints remain open to rapid repeated requests.
    - A default conservative rate limit (e.g. a few attempts per minute per IP) would mitigate brute‑force risks.
- Preconditions:
    - The API is publicly accessible on endpoints that use API Key (or other sensitive) authentication, and no explicit throttling is configured—thus the default (NOT_SET) throttle is in effect.
- Source code analysis:
    - In `ninja/throttling.py`, the `SimpleRateThrottle` class’s `allow_request()` method checks the request history stored in the cache. When no throttle is attached (or the developer leaves throttle as NOT_SET), there is no enforcement to limit the rate of incoming requests.
    - Test modules illustrate that when explicit throttle objects are not provided, the API processes authentication requests without delays or rate limits.
- Security test case:
    1. Create and deploy an API endpoint that uses API Key–based authentication, ensuring that no throttle object is configured (i.e. throttle remains as NOT_SET).
    2. Using an automated script, send a large number of authentication requests with incorrect API keys from one or more IP addresses.
    3. Observe that the API processes every request immediately with no throttling (i.e. no HTTP 429 status responses).
    4. Expected Outcome: The absence of default rate limiting allows rapid repeated requests, facilitating brute‑force attacks.

#### Public Exposure of OpenAPI Documentation Vulnerability

- Vulnerability name: Public Exposure of OpenAPI Documentation Vulnerability
- Description:
    By default, the NinjaAPI instance (see `ninja/main.py`) is configured with `docs_url` set to “/docs” and `openapi_url` set to “/openapi.json”. The OpenAPI specification and interactive documentation are then added to Django’s URL configuration (see `ninja/openapi/urls.py`) without any authentication or access restrictions. An unauthenticated attacker can directly access these endpoints to retrieve detailed information on the API’s routes, parameters, and models.
- Impact:
    Full exposure of the API’s internal structure can enable attackers to map out endpoints and craft more sophisticated, targeted attacks; it also simplifies automated vulnerability scanning.
- Vulnerability rank: High
- Currently implemented mitigations:
    - The framework supports disabling these documentation endpoints by setting `docs_url=None` and/or `openapi_url=None`, and it provides the option to wrap the endpoints using an authentication decorator (see documentation examples).
- Missing mitigations:
    - Out‑of‑the‑box, documentation endpoints remain enabled and are publicly accessible, leaving the API fully documented without any access control.
    - A secure‑by‑default behavior (such as restricting access in production) would considerably reduce the attack surface.
- Preconditions:
    - The API instance is deployed with the default configuration where `docs_url` and `openapi_url` are enabled and not protected by any authentication or authorization mechanism.
- Source code analysis:
    - In `ninja/main.py`, the constructor sets default values for `docs_url` ("/docs") and `openapi_url` ("/openapi.json").
    - In `ninja/openapi/urls.py`, these endpoints are automatically added to the URL configuration without any built‑in safeguards.
- Security test case:
    1. Deploy the API using the default configuration (i.e. with `docs_url` and `openapi_url` enabled).
    2. From an external, unauthenticated network, access the endpoints “/docs” and “/openapi.json” using a web browser or a HTTP client.
    3. Verify that the full OpenAPI specification is disclosed, revealing endpoints, parameter definitions, and even default values.
    4. Expected Outcome: The API documentation is accessible without any form of authentication, thereby confirming the vulnerability.

#### Throttling Bypass via X-Forwarded-For Header Manipulation

- Vulnerability name: Throttling Bypass via X-Forwarded-For Header Manipulation
- Description:
    An attacker can bypass IP-based throttling mechanisms (like `AnonRateThrottle`, `UserRateThrottle`) by manipulating the `X-Forwarded-For` HTTP header. This vulnerability occurs because the application might not be correctly configured to handle requests behind a proxy, specifically regarding the number of proxies (`NUM_PROXIES` setting). If `NUM_PROXIES` is not set or incorrectly set, the system might use the attacker-controlled IP address from the `X-Forwarded-For` header instead of the actual client IP address for throttling.

    Steps to trigger vulnerability:
    1. Application is deployed behind a proxy (e.g., CDN, load balancer).
    2. Throttling is implemented using `AnonRateThrottle` or `UserRateThrottle` which rely on IP address for rate limiting.
    3. Attacker sends multiple requests to the application, including a crafted `X-Forwarded-For` header with a spoofed IP address.
    4. If `NUM_PROXIES` setting is not properly configured to reflect the number of proxies in front of the application, the throttling mechanism will use the spoofed IP from `X-Forwarded-For` instead of the actual client IP.
    5. Attacker can bypass throttling by changing the spoofed IP address in subsequent requests, as the system will treat each request as coming from a different IP.
- Impact:
    Successful exploitation of this vulnerability allows attackers to bypass rate limiting, potentially leading to:
    * Brute-force attacks: Attackers can make unlimited login attempts or other security-sensitive actions without being throttled.
    * Resource exhaustion: Attackers can send a high volume of requests, overwhelming the server and potentially leading to service disruptions or increased operational costs.
    * Circumvention of security measures: Throttling is often used as a security measure to protect against various attacks. Bypassing it weakens the overall security posture of the application.
- Vulnerability rank: High
- Currently implemented mitigations:
    The `SimpleRateThrottle` class in `ninja/throttling.py` includes logic to handle proxy headers using the `NUM_PROXIES` setting from `ninja.conf.settings`.
    ```python
    def get_ident(self, request: HttpRequest) -> Optional[str]:
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            xff_hosts = xff.split(",")
            num_proxies = settings.NUM_PROXIES
            if num_proxies is None:
                return xff_hosts[-1].strip()  # default behavior
            elif num_proxies >= 1:
                return xff_hosts[-(num_proxies + 1)].strip()  # last proxy addr in the list
            else:  # num_proxies == 0
                return xff_hosts[0].strip() # client addr (first in the list)

        return request.META.get("REMOTE_ADDR")
    ```
    This code attempts to retrieve the correct client IP based on `NUM_PROXIES`. However, misconfiguration of `NUM_PROXIES` leads to vulnerability.
- Missing mitigations:
    * **Configuration Guidance and Best Practices:** The project lacks clear documentation and warnings about the importance of correctly configuring `NUM_PROXIES` when deploying behind proxies. This should include guidelines on how to determine the correct value for `NUM_PROXIES` based on the deployment environment.
    * **Automatic Proxy Detection (Optional but Recommended):**  While not always feasible, exploring options for automatic detection of proxy setups or providing tools to help administrators determine the correct `NUM_PROXIES` value could improve security.
    * **Rate Limiting based on other factors:** Consider supplementing or offering alternatives to solely IP-based throttling, such as token-based or user-account based throttling, which are less susceptible to IP spoofing.
- Preconditions:
    1. Django Ninja application is deployed behind at least one proxy server (e.g., CDN, load balancer, reverse proxy).
    2. IP-based throttling is enabled using `AnonRateThrottle` or `UserRateThrottle`.
    3. The `NUM_PROXIES` setting in Django settings is either not set, set to `None` (default, which might be insecure in proxy setups), or incorrectly configured for the actual number of proxies.
- Source code analysis:
    1. **`ninja/throttling.py` - `SimpleRateThrottle.get_ident()`:**
        - The `get_ident` method retrieves the client's IP address.
        - It first checks for the `HTTP_X_FORWARDED_FOR` header from `request.META`.
        - If the header is present, it splits the header value by commas into a list of IP addresses (`xff_hosts`).
        - It retrieves the `NUM_PROXIES` setting from `ninja.conf.settings`.
        - **Case 1: `num_proxies is None` (Default):** It returns `xff_hosts[-1].strip()`, which is the *last* IP address in the `X-Forwarded-For` header. In a typical proxy setup, the last IP is usually the *proxy's* IP, not the client's original IP. This is the default behavior and is vulnerable if `NUM_PROXIES` is not configured when behind proxies.
        - **Case 2: `num_proxies >= 1`:** It returns `xff_hosts[-(num_proxies + 1)].strip()`. This attempts to get the client IP by going back `num_proxies + 1` hops in the `X-Forwarded-For` list. For example, if `NUM_PROXIES = 1`, it takes the second to last IP. This is intended for setups with a known number of proxies.
        - **Case 3: `num_proxies == 0`:** It returns `xff_hosts[0].strip()`, which is the *first* IP in the `X-Forwarded-For` list. This is meant to be the client IP when `NUM_PROXIES` is set to 0, assuming the first IP is the originating client.
        - If the `HTTP_X_FORWARDED_FOR` header is not present, it falls back to `request.META.get("REMOTE_ADDR")`, which is the IP address of the immediate connection to the server (typically the proxy in a proxy setup, or the client directly if no proxy).
- Security test case:
    1. **Setup:** Deploy a Django Ninja application with IP-based throttling (`AnonRateThrottle` applied to a publicly accessible endpoint) behind an Nginx reverse proxy. Ensure the Django application is configured to use the default `NUM_PROXIES = None` or explicitly set it to `None`.
    2. **Baseline Test:** Send several requests from a single IP address to the throttled endpoint *without* the `X-Forwarded-For` header. Verify that after exceeding the rate limit, the server correctly applies throttling and returns 429 status codes.
    3. **Throttling Bypass Attempt via X-Forwarded-For:**
        - Use a tool like `curl` or a Python script to send requests to the throttled endpoint from the same source IP address used in the baseline test.
        - For each request, include the `X-Forwarded-For` header, crafting it to contain a list of IPs. The *last* IP in the list should be the IP address of your Nginx proxy server. The IP addresses *before* the proxy IP in the list should be spoofed, unique IP addresses. For example: `X-Forwarded-For: 1.1.1.1, <Nginx_Proxy_IP>`, `X-Forwarded-For: 1.1.1.2, <Nginx_Proxy_IP>`, `X-Forwarded-For: 1.1.1.3, <Nginx_Proxy_IP>`, and so on.  Increment the spoofed IP (1.1.1.x) for each subsequent request.
        - Observe the responses. If the vulnerability is present, the server will continue to respond with 200 OK even after exceeding the intended rate limit. This is because the default `NUM_PROXIES = None` configuration causes `get_ident()` to use the *last* IP in `X-Forwarded-For` (the proxy IP), or in some cases, the attacker-controlled spoofed IP, effectively bypassing the IP-based throttling.
    4. **Verification of Mitigation:**
        - Correctly configure the Django Ninja application by setting `NUM_PROXIES = 1` (assuming there is one reverse proxy in front).
        - Repeat steps 2 and 3 (baseline and bypass attempts).
        - With `NUM_PROXIES = 1`, the throttling should now be correctly applied based on the *actual* client IP address (which Ninja will extract from the `X-Forwarded-For` header). The bypass attempt using spoofed `X-Forwarded-For` headers should no longer be effective. After exceeding the rate limit, the server should return 429 status codes, even with manipulated `X-Forwarded-For` headers.