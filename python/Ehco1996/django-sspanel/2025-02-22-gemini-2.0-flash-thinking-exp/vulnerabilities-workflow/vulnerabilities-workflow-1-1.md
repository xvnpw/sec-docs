## Vulnerability List:

- Vulnerability Name: Default MySQL Root Password
- Description: The `docker-compose.yml` file sets a default, weak password "yourpass" for the MySQL root user if the `MYSQL_PASSWORD` environment variable is not explicitly set during deployment. An attacker could potentially gain unauthorized access to the MySQL database if this default password is used in a production environment.
- Impact:  An attacker gaining access to the MySQL database could read, modify, or delete sensitive data, including user credentials, subscription information, and payment details. This can lead to a complete compromise of the application's backend and data integrity.
- Vulnerability rank: High
- Currently implemented mitigations: None in the provided files. The `docker-compose.yml` uses environment variables, which is a standard practice for configuration, but it relies on the user to override the default password.
- Missing mitigations:
    - The default password in `docker-compose.yml` should be removed or set to a strong, randomly generated value.
    - Documentation should explicitly warn users about the security risk of using default passwords and instruct them to set a strong `MYSQL_PASSWORD` environment variable before deploying the application.
    - The application could include a startup check to ensure that the MySQL root password has been changed from the default and refuse to start if it hasn't.
- Preconditions:
    - The application is deployed using `docker-compose.yml` without setting a strong `MYSQL_PASSWORD` environment variable.
    - The MySQL port (default 3306) is exposed to the attacker's network, either directly or indirectly through application vulnerabilities.
- Source code analysis:
    - File: `/code/docker-compose.yml`
    ```yaml
    mysql:
      image: mysql:8.2
      container_name: mysql
      restart: always
      environment:
        MYSQL_ROOT_PASSWORD: ${MYSQL_PASSWORD:-yourpass}
        MYSQL_DATABASE: sspanel
    ```
    - The line `MYSQL_ROOT_PASSWORD: ${MYSQL_PASSWORD:-yourpass}` sets the MySQL root password. The `:-yourpass` part means that if the environment variable `MYSQL_PASSWORD` is not set, it will default to "yourpass".
- Security test case:
    1. Deploy the application using `docker-compose up` without setting the `MYSQL_PASSWORD` environment variable.
    2. Attempt to connect to the MySQL database from outside the Docker container using the root user and password "yourpass", targeting the exposed MySQL port (if any, or within the Docker network).
    3. If the connection is successful, it confirms the vulnerability. For example, using `mysql -h <docker-host-ip> -P <exposed-mysql-port> -u root -p`.

- Vulnerability Name: Insecure API Key Authentication
- Description: The API authentication mechanism uses a simple token-based approach where the API key (`settings.TOKEN`) is expected to be passed as a query parameter named `token` in GET requests. This method is vulnerable because API keys in query parameters can be easily exposed in server logs, browser history, and network traffic. An attacker could intercept or discover this API key and reuse it to gain unauthorized access to API endpoints. This issue is present in the `@api_authorized` decorator used for API authentication and also when generating API endpoints in models like `ProxyNode` and `RelayNode`, where the token is directly embedded in the URL.
- Impact: If the API key is compromised, an attacker can bypass authentication and access all API endpoints protected by the `@api_authorized` decorator or directly access endpoints using the generated URLs. Based on `openapi.yaml` and code analysis, these endpoints include functionalities to manage proxy nodes, relay nodes, user information, and retrieve configurations, potentially allowing attackers to manipulate the service, access user data, or perform administrative actions.
- Vulnerability rank: High
- Currently implemented mitigations:  The project implements a basic API key check using the `@api_authorized` decorator in `apps/utils.py` and `OpenAPIStaffAuthentication` in `apps/openapi/utils.py`.
- Missing mitigations:
    - API key should not be passed in query parameters, including in dynamically generated URLs.
    - Implement a more secure method for API key authentication for both `@api_authorized` decorator and OpenAPI, such as using:
        - API keys in request headers (e.g., `Authorization: Bearer <API_KEY>` or `X-API-KEY`). The OpenAPI already uses `X-API-KEY`, but `@api_authorized` decorator still uses query parameter.
        - OAuth 2.0 or JWT for more robust authentication and authorization.
        - HTTPS should be enforced to encrypt network traffic and protect API keys during transmission.
- Preconditions:
    - API endpoints are protected using the `@api_authorized` decorator or accessed via URLs containing the API key.
    - The application is deployed with API endpoints accessible over the network.
    - An attacker is able to observe network traffic, access server logs, or browser history where the API key might be exposed in URLs.
- Source code analysis:
    - File: `/code/apps/utils.py`
    ```python
    def api_authorized(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            token = request.GET.get("token", "")
            if token != settings.TOKEN:
                return JsonResponse({"msg": "auth error"})
            return view_func(request, *args, **kwargs)
        return wrapper
    ```
    - The `api_authorized` decorator retrieves the API key from `request.GET.get("token", "")`, indicating that the API key is expected in the query parameter `token`.
    - File: `/code/apps/api/views.py`
    ```python
    class ProxyConfigsView(View):
        # ...
        @method_decorator(api_authorized)
        def get(self, request, node_id):
            # ...
        @method_decorator(api_authorized)
        def post(self, request, node_id):
            # ...
    ```
    - The `@method_decorator(api_authorized)` is used to protect API views like `ProxyConfigsView`, enforcing the API key check.
    - File: `/code/apps/proxy/models.py` & `/code/apps/relay/models.py`
    ```python
    class ProxyNode(BaseNodeModel, SequenceMixin):
        # ...
        @property
        def api_endpoint(self):
            params = {"token": settings.TOKEN}
            return f"{settings.SITE_HOST}/api/proxy_configs/{self.id}/?{urlencode(params)}"

    class RelayNode(BaseNodeModel):
        # ...
        @property
        def api_endpoint(self):
            params = {"token": settings.TOKEN}
            return (
                f"{settings.SITE_HOST}/api/ehco_relay_config/{self.id}/?{urlencode(params)}"
            )
    ```
    - The `api_endpoint` property in `ProxyNode` and `RelayNode` models generates URLs that include the API key in the `token` query parameter.
- Security test case:
    1. Identify an API endpoint protected by `@api_authorized`, for example, `/api/proxy_configs/<node_id>/`.
    2. Access the API endpoint without providing the `token` query parameter. Verify that access is denied with a JSON response `{"msg": "auth error"}`.
    3. Access the API endpoint with the correct `token` query parameter (assuming you have obtained or guessed the `settings.TOKEN` value). Verify that access is granted and you receive the expected API response.
    4. Monitor network traffic (e.g., using a proxy like Burp Suite or browser developer tools) when accessing the API with the `token` in the query parameter. Observe that the API key is visible in the URL within the network request.
    5. Check server logs and browser history to confirm that the API key is also logged in these locations if requests with the API key are made.
    6. Access the `api_endpoint` URLs generated by `ProxyNode` or `RelayNode` models (e.g., by inspecting the HTML source in the admin panel if these URLs are used there). Verify that the API key is present in the URL.

- Vulnerability Name: Sensitive Information Disclosure via `settings_value` Template Tag
- Description: The `settings_value` template tag in `ehcofilter.py` allows rendering Django settings values directly in templates. If a template using this tag is rendered and accessible to users, and if the `name` argument to the tag corresponds to a sensitive setting (like `SECRET_KEY`, database credentials, API keys, etc.), then an attacker could potentially view these sensitive values.
- Impact: Exposure of sensitive settings can lead to severe security breaches. For example, exposing `SECRET_KEY` can allow session hijacking, signing arbitrary data, and other attacks. Exposing database credentials or API keys can lead to unauthorized access to backend systems and data.
- Vulnerability rank: High
- Currently implemented mitigations: None in the provided code.
- Missing mitigations:
    - Avoid using the `settings_value` template tag in templates accessible to users, especially with settings names that could be sensitive.
    - If the tag is necessary, restrict its usage to admin-only templates and ensure that only non-sensitive settings are accessed through it.
    - Review all templates to identify usages of `settings_value` and assess the risk of information disclosure.
- Preconditions:
    - A template using the `settings_value` tag is rendered and accessible to an attacker (either anonymously or through user account access).
    - The `name` argument passed to `settings_value` in the template corresponds to a sensitive Django setting.
- Source code analysis:
    - File: `/code/apps/sspanel/templatetags/ehcofilter.py`
    ```python
    @register.simple_tag
    def settings_value(name):
        return getattr(settings, name, "")
    ```
    - The `settings_value` tag directly retrieves and returns the value of the Django setting specified by the `name` argument. There is no sanitization or access control in this tag. If a template uses `{% settings_value 'SECRET_KEY' %}`, it will output the `SECRET_KEY` value in the rendered HTML.
- Security test case:
    1. Identify a template in the application that is accessible to users (e.g., a user profile page, a public information page, etc.).
    2. Modify this template (if possible in a test environment, or by patching the template file) to include the following template tag: `{% load ehcofilter %}{% settings_value 'SECRET_KEY' %}`.
    3. Access the modified template through the application in a browser.
    4. Inspect the HTML source of the page. If the `SECRET_KEY` (or any other sensitive setting) is visible in the HTML, the vulnerability is confirmed.
    5. Alternatively, try to guess other potentially sensitive setting names (e.g., `DEBUG`, `DATABASE_PASSWORD`, `API_TOKEN`, etc.) and test if they are also disclosed.