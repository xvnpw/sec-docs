## Vulnerability List for django-waffle Project

### 1. Information Exposure via `waffle_status` endpoint

- Description:
    - The `waffle` application exposes an endpoint `/waffle_status` (named URL `waffle_status`) that returns a JSON response containing the names and active status of all defined flags, switches, and samples.
    - An external attacker can access this endpoint without any authentication.
    - By accessing this endpoint, the attacker can enumerate all feature flags, switches, and samples configured in the application.
    - This information can reveal details about upcoming features, internal application logic, and potentially sensitive configuration if flag, switch, or sample names are chosen descriptively or contain sensitive keywords.
    - Step-by-step trigger:
        1. Identify the publicly accessible URL for the `waffle_status` endpoint (typically `/waffle_status`).
        2. Send an HTTP GET request to this URL using a web browser or a tool like `curl`.
        3. Observe the JSON response which lists all flags, switches, and samples with their active status.

- Impact:
    - **Information Leakage**: Exposure of feature flag, switch, and sample names, and their status.
    - **Security Misconfiguration**: Revealing internal application configuration details through feature toggle names.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The `/waffle_status` endpoint is publicly accessible without any authentication or authorization checks.

- Missing Mitigations:
    - **Access Control**: Implement access control to the `/waffle_status` endpoint. Restrict access to authenticated administrators or internal services only. This can be achieved by:
        - Requiring authentication for access to this endpoint.
        - Implementing IP-based whitelisting to allow access only from trusted networks.
        - Using Django's permission system to restrict access based on user roles.

- Preconditions:
    - The `waffle.urls` are included in the project's `urlpatterns`.
    - The application is deployed and publicly accessible.

- Source Code Analysis:
    - File: `/code/waffle/urls.py`
    ```python
    from django.urls import path

    from waffle.views import wafflejs, waffle_json

    urlpatterns = [
        path('wafflejs', wafflejs, name='wafflejs'),
        path('waffle_status', waffle_json, name='waffle_status'), # Vulnerable endpoint
    ]
    ```
    - File: `/code/waffle/views.py`
    ```python
    @never_cache
    def waffle_json(request): # Function handling the endpoint
        return JsonResponse(_generate_waffle_json(request))

    def _generate_waffle_json(request: HttpRequest) -> dict[str, dict[str, Any]]:
        flags = get_waffle_flag_model().get_all() # Retrieves all flags
        flag_values = {
            f.name: {
                'is_active': f.is_active(request),
                'last_modified': f.modified,
            }
            for f in flags
        }

        switches = get_waffle_switch_model().get_all() # Retrieves all switches
        switch_values = {
            s.name: {
                'is_active': s.is_active(),
                'last_modified': s.modified,
            }
            for s in switches
        }

        samples = get_waffle_sample_model().get_all() # Retrieves all samples
        sample_values = {
            s.name: {
                'is_active': s.is_active(),
                'last_modified': s.modified,
            }
            for s in samples
        }

        return {
            'flags': flag_values,
            'switches': switch_values,
            'samples': sample_values,
        }
    ```
    - The code shows that `waffle_json` view, mapped to `/waffle_status` URL, retrieves all flags, switches, and samples and returns their names and active status in a JSON response without any access control.

- Security Test Case:
    1. Deploy the django-waffle example application or an application using django-waffle with at least one Flag, Switch and Sample defined.
    2. Access the `/waffle_status` endpoint using a web browser or `curl` from outside the application's network (as an external attacker). For example: `curl http://<your-application-url>/waffle_status`
    3. Verify that the response is a JSON object.
    4. Examine the JSON response and confirm that it contains a list of `flags`, `switches`, and `samples`.
    5. For each item in the lists, verify that the `name` and `is_active` status are exposed.
    6. **Expected Result**: The test should confirm that an unauthenticated external attacker can successfully retrieve a list of all flags, switches, and samples along with their status by accessing the `/waffle_status` endpoint.

### 2. Insecure Cookie Settings for Testing Flags

- Description:
    - When a Flag is created with `testing=True`, the `waffle` middleware sets a cookie named `dwft_%s` (where `%s` is the flag name) to enable testing override of the flag's behavior.
    - This cookie, used for testing purposes, is set without the `HttpOnly` and `Secure` flags by default.
    - If an attacker can perform a Cross-Site Scripting (XSS) attack on the application, they can potentially access this cookie via JavaScript.
    - If an attacker performs a Man-in-the-Middle (MITM) attack over an insecure HTTP connection, they could potentially intercept this cookie.
    - By obtaining or manipulating this cookie, an attacker could potentially enable or disable features for a victim user in a testing scenario, potentially leading to unexpected application behavior or bypassing intended feature restrictions.
    - Step-by-step trigger:
        1. Create a Flag in the Django admin panel with `testing` option enabled.
        2. Access a page in the application where this flag might be evaluated. Observe the `dwft_<flag_name>` cookie being set in the browser's developer tools (if the flag logic is executed).
        3. Using browser developer tools or a network intercepting proxy, inspect the attributes of the `dwft_<flag_name>` cookie.
        4. Verify that the `HttpOnly` and `Secure` flags are not set for this cookie.

- Impact:
    - **Session Hijacking/Manipulation**: Potential for an attacker to manipulate the testing cookie if XSS or MITM is possible.
    - **Feature Bypass**: Attacker might be able to bypass intended feature restrictions or enable features not meant for them in a testing context.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - The `WaffleMiddleware` sets cookies for both regular flags (`dwf_%s`) and testing flags (`dwft_%s`). However, only the regular flag cookies respect the `SECURE` setting. The testing cookies do not explicitly set `HttpOnly` or `Secure` flags.

- Missing Mitigations:
    - **Set `HttpOnly` flag**: Set the `HttpOnly` flag to `True` for the `dwft_%s` cookies to prevent client-side JavaScript from accessing the cookie, mitigating XSS-based attacks targeting this cookie.
    - **Set `Secure` flag**: Set the `Secure` flag to `True` for the `dwft_%s` cookies to ensure they are only transmitted over HTTPS, mitigating MITM attacks if the application uses HTTPS.

- Preconditions:
    - A Flag is created with `testing=True`.
    - The application evaluates this flag, causing the `dwft_%s` cookie to be set.
    - The application is vulnerable to XSS or is used over insecure HTTP connections, making MITM attacks possible.

- Source Code Analysis:
    - File: `/code/waffle/middleware.py`
    ```python
    class WaffleMiddleware(MiddlewareMixin):
        def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
            secure = get_setting('SECURE') # SECURE setting is retrieved
            max_age = get_setting('MAX_AGE')

            if hasattr(request, 'waffles'):
                for k in request.waffles:
                    name = smart_str(get_setting('COOKIE') % k)
                    active, rollout = request.waffles[k]
                    if rollout and not active:
                        age = None
                    else:
                        age = max_age
                    response.set_cookie(name, value=active, max_age=age,
                                        secure=secure) # secure flag used here for dwf_%s cookies
            if hasattr(request, 'waffle_tests'):
                for k in request.waffle_tests:
                    name = smart_str(get_setting('TEST_COOKIE') % k)
                    value = request.waffle_tests[k]
                    response.set_cookie(name, value=value) # secure and httponly flags are NOT used for dwft_%s cookies

            return response
    ```
    - The code shows that `response.set_cookie` for testing cookies (in `waffle_tests` block) does not include `secure=secure` or `httponly=True` arguments, making them insecure by default.

- Security Test Case:
    1. Deploy the django-waffle example application or an application using django-waffle.
    2. Create a Flag named `test_flag_xss` in the Django admin panel and set `Testing` to `Yes`.
    3. Access any page in the application.
    4. Using browser's developer tools, inspect the cookies set for the domain. Look for the `dwft_test_flag_xss` cookie.
    5. Check the attributes of the `dwft_test_flag_xss` cookie.
    6. Verify that the `HttpOnly` flag is `False` or not present.
    7. Verify that the `Secure` flag is `False` or not present.
    8. **Expected Result**: The test should confirm that the `dwft_test_flag_xss` cookie is set without `HttpOnly` and `Secure` flags, making it potentially vulnerable to XSS and MITM attacks.