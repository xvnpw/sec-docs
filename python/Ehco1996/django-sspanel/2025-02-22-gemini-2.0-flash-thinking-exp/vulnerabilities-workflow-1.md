## Combined Vulnerability List

### Vulnerability Name: Default MySQL Root Password

- **Description:** The `docker-compose.yml` file sets a default, weak password "yourpass" for the MySQL root user if the `MYSQL_PASSWORD` environment variable is not explicitly set during deployment. An attacker could potentially gain unauthorized access to the MySQL database if this default password is used in a production environment.
- **Impact:**  An attacker gaining access to the MySQL database could read, modify, or delete sensitive data, including user credentials, subscription information, and payment details. This can lead to a complete compromise of the application's backend and data integrity.
- **Vulnerability rank:** High
- **Currently implemented mitigations:** None in the provided files. The `docker-compose.yml` uses environment variables, which is a standard practice for configuration, but it relies on the user to override the default password.
- **Missing mitigations:**
    - The default password in `docker-compose.yml` should be removed or set to a strong, randomly generated value.
    - Documentation should explicitly warn users about the security risk of using default passwords and instruct them to set a strong `MYSQL_PASSWORD` environment variable before deploying the application.
    - The application could include a startup check to ensure that the MySQL root password has been changed from the default and refuse to start if it hasn't.
- **Preconditions:**
    - The application is deployed using `docker-compose.yml` without setting a strong `MYSQL_PASSWORD` environment variable.
    - The MySQL port (default 3306) is exposed to the attacker's network, either directly or indirectly through application vulnerabilities.
- **Source code analysis:**
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
- **Security test case:**
    1. Deploy the application using `docker-compose up` without setting the `MYSQL_PASSWORD` environment variable.
    2. Attempt to connect to the MySQL database from outside the Docker container using the root user and password "yourpass", targeting the exposed MySQL port (if any, or within the Docker network).
    3. If the connection is successful, it confirms the vulnerability. For example, using `mysql -h <docker-host-ip> -P <exposed-mysql-port> -u root -p`.

### Vulnerability Name: Insecure API Key Authentication

- **Description:** The API authentication mechanism uses a simple token-based approach where the API key (`settings.TOKEN`) is expected to be passed as a query parameter named `token` in GET requests. This method is vulnerable because API keys in query parameters can be easily exposed in server logs, browser history, and network traffic. An attacker could intercept or discover this API key and reuse it to gain unauthorized access to API endpoints. This issue is present in the `@api_authorized` decorator used for API authentication and also when generating API endpoints in models like `ProxyNode` and `RelayNode`, where the token is directly embedded in the URL.
- **Impact:** If the API key is compromised, an attacker can bypass authentication and access all API endpoints protected by the `@api_authorized` decorator or directly access endpoints using the generated URLs. Based on `openapi.yaml` and code analysis, these endpoints include functionalities to manage proxy nodes, relay nodes, user information, and retrieve configurations, potentially allowing attackers to manipulate the service, access user data, or perform administrative actions.
- **Vulnerability rank:** High
- **Currently implemented mitigations:**  The project implements a basic API key check using the `@api_authorized` decorator in `apps/utils.py` and `OpenAPIStaffAuthentication` in `apps/openapi/utils.py`.
- **Missing mitigations:**
    - API key should not be passed in query parameters, including in dynamically generated URLs.
    - Implement a more secure method for API key authentication for both `@api_authorized` decorator and OpenAPI, such as using:
        - API keys in request headers (e.g., `Authorization: Bearer <API_KEY>` or `X-API-KEY`). The OpenAPI already uses `X-API-KEY`, but `@api_authorized` decorator still uses query parameter.
        - OAuth 2.0 or JWT for more robust authentication and authorization.
        - HTTPS should be enforced to encrypt network traffic and protect API keys during transmission.
- **Preconditions:**
    - API endpoints are protected using the `@api_authorized` decorator or accessed via URLs containing the API key.
    - The application is deployed with API endpoints accessible over the network.
    - An attacker is able to observe network traffic, access server logs, or browser history where the API key might be exposed in URLs.
- **Source code analysis:**
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
- **Security test case:**
    1. Identify an API endpoint protected by `@api_authorized`, for example, `/api/proxy_configs/<node_id>/`.
    2. Access the API endpoint without providing the `token` query parameter. Verify that access is denied with a JSON response `{"msg": "auth error"}`.
    3. Access the API endpoint with the correct `token` query parameter (assuming you have obtained or guessed the `settings.TOKEN` value). Verify that access is granted and you receive the expected API response.
    4. Monitor network traffic (e.g., using a proxy like Burp Suite or browser developer tools) when accessing the API with the `token` in the query parameter. Observe that the API key is visible in the URL within the network request.
    5. Check server logs and browser history to confirm that the API key is also logged in these locations if requests with the API key are made.
    6. Access the `api_endpoint` URLs generated by `ProxyNode` or `RelayNode` models (e.g., by inspecting the HTML source in the admin panel if these URLs are used there). Verify that the API key is present in the URL.

### Vulnerability Name: Sensitive Information Disclosure via `settings_value` Template Tag

- **Description:** The `settings_value` template tag in `ehcofilter.py` allows rendering Django settings values directly in templates. If a template using this tag is rendered and accessible to users, and if the `name` argument to the tag corresponds to a sensitive setting (like `SECRET_KEY`, database credentials, API keys, etc.), then an attacker could potentially view these sensitive values.
- **Impact:** Exposure of sensitive settings can lead to severe security breaches. For example, exposing `SECRET_KEY` can allow session hijacking, signing arbitrary data, and other attacks. Exposing database credentials or API keys can lead to unauthorized access to backend systems and data.
- **Vulnerability rank:** High
- **Currently implemented mitigations:** None in the provided code.
- **Missing mitigations:**
    - Avoid using the `settings_value` template tag in templates accessible to users, especially with settings names that could be sensitive.
    - If the tag is necessary, restrict its usage to admin-only templates and ensure that only non-sensitive settings are accessed through it.
    - Review all templates to identify usages of `settings_value` and assess the risk of information disclosure.
- **Preconditions:**
    - A template using the `settings_value` tag is rendered and accessible to an attacker (either anonymously or through user account access).
    - The `name` argument passed to `settings_value` in the template corresponds to a sensitive Django setting.
- **Source code analysis:**
    - File: `/code/apps/sspanel/templatetags/ehcofilter.py`
    ```python
    @register.simple_tag
    def settings_value(name):
        return getattr(settings, name, "")
    ```
    - The `settings_value` tag directly retrieves and returns the value of the Django setting specified by the `name` argument. There is no sanitization or access control in this tag. If a template uses `{% settings_value 'SECRET_KEY' %}`, it will output the `SECRET_KEY` value in the rendered HTML.
- **Security test case:**
    1. Identify a template in the application that is accessible to users (e.g., a user profile page, a public information page, etc.).
    2. Modify this template (if possible in a test environment, or by patching the template file) to include the following template tag: `{% load ehcofilter %}{% settings_value 'SECRET_KEY' %}`.
    3. Access the modified template through the application in a browser.
    4. Inspect the HTML source of the page. If the `SECRET_KEY` (or any other sensitive setting) is visible in the HTML, the vulnerability is confirmed.
    5. Alternatively, try to guess other potentially sensitive setting names (e.g., `DEBUG`, `DATABASE_PASSWORD`, `API_TOKEN`, etc.) and test if they are also disclosed.

### Vulnerability Name: Weak Random Number Generation for Sensitive Tokens

- **Description:**  The project defines a custom function (e.g. in `/code/apps/utils.py` via `get_random_string` or similar functions used by the User model’s default value for passwords/invite codes) to create tokens for sensitive purposes. This function obtains randomness from Python’s built‑in `random` module, re‑seeding it on every call using predictable values (such as the current state, time, and a hardcoded string). An attacker who can approximate the time window may be able to reproduce the seed and guess the generated tokens.
- **Impact:**  An attacker may predict or reproduce sensitive tokens (such as proxy passwords or invite codes), granting unauthorized access or allowing further compromise of subscription‑based resources.
- **Vulnerability Rank:** High (potentially Critical if used for critical credentials)
- **Currently Implemented Mitigations:**  The project currently uses the insecure Python `random` module for token generation without incorporating additional entropy or cryptographically secure alternatives.
- **Missing Mitigations:**
    - Use a cryptographically secure random source (for example, Python’s `secrets` module or `os.urandom()`).
    - Avoid re‑seeding on every call and adopt a secure mechanism that does not expose predictable state.
- **Preconditions:**  Token generation is triggered during user account creation or when generating sensitive unique codes, and the attacker can estimate the generation time.
- **Source Code Analysis:**
    - In the User migration file (e.g. `/code/apps/sspanel/migrations/0001_squashed_0055_auto_20200726_0847.py`), the User model’s password field uses a default of `apps.utils.get_short_random_string` (later renamed to `proxy_password` in a subsequent migration).
    - The token generation logic re‑seeds the RNG with a hash of the current state, time, and a hardcoded secret, resulting in largely predictable outputs.
- **Security Test Case:**
    1. Trigger the generation of new tokens by creating several user accounts (or actions that generate invite codes/proxy passwords).
    2. Record the approximate generation time and the produced tokens.
    3. Replicate the seeding and token generation logic in a controlled script using the same predictable inputs.
    4. Verify that the tokens can be re‑generated and used to access sensitive endpoints.

### Vulnerability Name: CSRF Vulnerability on User Settings Update Endpoint

- **Description:**  The endpoint for updating a user’s proxy configuration (in the `UserSettingsView` in `/code/apps/api/views.py`) is decorated with `@csrf_exempt`. Although the view requires that the user is authenticated via `login_required`, the removal of Django’s CSRF protection allows an attacker to force a logged‑in user’s browser into submitting an unwanted POST request that updates their proxy settings.
- **Impact:**  An attacker may alter a user’s proxy configuration (for example, by changing the proxy password to an attacker‑controlled value), leading to account hijacking or misrouted network traffic.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**  The view enforces that a user must be logged in; however, the explicit use of `@csrf_exempt` disables a key defense against CSRF.
- **Missing Mitigations:**
    - Remove the `@csrf_exempt` decorator or implement robust CSRF token verification on state‑changing endpoints.
    - Enforce that only genuine requests from the user’s browser (with a valid CSRF token) are permitted.
- **Preconditions:**  The victim must be logged in using their browser, and the attacker must cause the victim’s browser to send a forged POST (via a hidden form or XHR) to the vulnerable endpoint.
- **Source Code Analysis:**
    - In `/code/apps/api/views.py`, the `UserSettingsView` is defined with a `dispatch` method decorated by `@csrf_exempt` and a `post` method that updates proxy configuration based solely on POST data.
    - The lack of a CSRF token check means that a third party can trigger unwanted changes when the user is authenticated.
- **Security Test Case:**
    1. Log in to the application in a web browser as an authenticated user.
    2. Host a malicious HTML page that automatically submits a form to `/api/user/settings/` with altered proxy configuration data.
    3. Visit the malicious page while still logged into the application.
    4. Verify that the proxy configuration has been changed as specified by the forged request.

### Vulnerability Name: Insecure Deserialization in Redis Cache Using Pickle

- **Description:**  The caching layer implemented in the file `/code/apps/extensions/cachext.py` uses Python’s `pickle` for serializing and deserializing objects when interacting with Redis. Specifically, the `RedisClient.get()` method retrieves data from Redis and directly passes it to `pickle.loads()` without any validation or integrity checking. If an attacker can inject or manipulate data stored in Redis—perhaps by exploiting a misconfigured Redis instance or an SSRF that allows arbitrary writes—the malicious pickle payload could trigger arbitrary code execution upon deserialization.
- **Impact:**  Exploiting this vulnerability can lead to arbitrary code execution on the host server. An attacker who successfully deserializes a crafted payload may execute arbitrary Python code, compromise the application’s integrity and confidentiality, and potentially pivot to further compromise internal systems.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**  There are no safeguards in the caching layer to authenticate or verify the integrity of the data retrieved from Redis. The use of `pickle.loads()` occurs directly, relying solely on Redis for storing serialized data.
- **Missing Mitigations:**
    - Use a safe serialization format such as JSON for caching data instead of pickle (which allows arbitrary code execution).
    - Restrict network access to the Redis instance (using firewalls, proper configuration, and authentication) so that attackers cannot inject data.
    - Optionally, sign cached data and verify the signature before deserialization.
- **Preconditions:**  An attacker must be able to inject or modify cached data in the Redis instance. This could happen if Redis is misconfigured (e.g., exposed to the public internet without authentication) or if an SSRF or other vulnerability elsewhere in the application allows writing arbitrary data into the cache.
- **Source Code Analysis:**
    - In `/code/apps/extensions/cachext.py`, the `RedisClient` class defines the `get()` method that retrieves data with `self._client.get(key)`.
    - When a value is returned, it is immediately passed to `pickle.loads(v)` without any validation of the payload.
    - This unsafeguarded deserialization process means that any malicious payload stored in Redis would be executed when the application reads that key.
- **Security Test Case:**
    1. Set up a test environment where the Redis server is intentionally misconfigured to allow external writes (or simulate an attacker’s injection into the Redis cache).
    2. Using a controlled tool/script, write a malicious pickle payload to a cache key that the application is expected to read (for example, one generated by the `make_default_key` function used by the caching decorator).
    3. Invoke an application function that triggers a cache lookup for that key (e.g., call a cached function via its API endpoint).
    4. Observe that upon deserialization via `pickle.loads()`, the malicious payload is executed, confirming the presence of insecure deserialization.

### Vulnerability Name: Permissive ALLOWED_HOSTS Configuration Leading to Host Header Injection

- **Description:**  In the file `/code/configs/default/sites.py`, the configuration sets `ALLOWED_HOSTS = ["*"]`. This wildcard setting causes Django to accept requests with any Host header. An attacker can exploit this misconfiguration to inject malicious host headers, potentially influencing how the application constructs absolute URLs, processes session cookies, or applies security policies.
- **Impact:**  An attacker may leverage host header injection to perform cache poisoning, facilitate password reset poisoning attacks, or bypass certain security controls that rely on host names, thereby undermining the integrity of application responses.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**  The application’s configuration does not further validate or restrict incoming Host header values beyond the wildcard setting in `ALLOWED_HOSTS`.
- **Missing Mitigations:**
    - Restrict the `ALLOWED_HOSTS` setting to include only trusted domain names or IP addresses instead of using a wildcard.
    - Employ reverse proxy or firewall rules that enforce valid Host header values before requests reach the application.
- **Preconditions:**  The application is directly accessible to the public internet and the underlying network infrastructure does not enforce host header restrictions.
- **Source Code Analysis:**
    - In `/code/configs/default/sites.py`, the line `ALLOWED_HOSTS = ["*"]` is present.
    - This means that any Host header (including those set by an attacker) will be accepted by Django without additional checks.
    - Maliciously crafted requests with attacker-controlled Host headers can therefore influence URL/email generation and other host-dependent functionality.
- **Security Test Case:**
    1. Deploy the application using the current configuration.
    2. Craft an HTTP request to the server with a malicious `Host` header (e.g., `Host: malicious.com`).
    3. Monitor the response to verify that the application uses the supplied Host header when generating links or handling sessions.
    4. Assess whether the manipulated Host header can facilitate further attacks (for example, by checking for unexpected redirects or modifications in session cookie behavior).

### Vulnerability Name: Default or Weak Django SECRET_KEY in Production

- **Description:**  The configuration in `/code/configs/default/sites.py` sets the `SECRET_KEY` using the environment variable `SECRET_KEY` with a fallback default value of `"aasdasdas"`. If this default value is deployed in a production environment, it severely undermines Django’s cryptographic signing mechanisms. An attacker who knows or can guess this key may forge session cookies, CSRF tokens, and other signed data.
- **Impact:**  With a predictable or default secret key, an attacker could compromise session integrity, hijack user accounts, and bypass numerous security measures that depend on cryptographic signatures, leading to a full compromise of user authentication and data integrity.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**  The project does not enforce the mandatory provision of a strong, unique secret key in production environments; it falls back to an insecure default if the `SECRET_KEY` environment variable is not set.
- **Missing Mitigations:**
    - Enforce the use of a strong, unique, and unpredictable secret key in production, potentially aborting startup if one is not provided via environment variables.
    - Remove insecure fallback defaults from the code.
- **Preconditions:**  The application is deployed in a production-like environment without properly overriding the default `SECRET_KEY` via environment variables.
- **Source Code Analysis:**
    - In `/code/configs/default/sites.py`, the line `SECRET_KEY = os.getenv("SECRET_KEY", "aasdasdas")` sets the secret key.
    - If the `SECRET_KEY` environment variable is absent, the default insecure value ("aasdasdas") is used.
    - This predictable key compromises all cryptographic signatures, impacting session cookies, CSRF tokens, and other security-critical operations.
- **Security Test Case:**
    1. Deploy the application in an environment without setting the `SECRET_KEY` environment variable.
    2. Confirm that the application falls back to using the default insecure key.
    3. Attempt to forge a session cookie or tamper with any signed data (e.g., CSRF token) using the known default key.
    4. Verify that the application accepts the forged or tampered data, demonstrating a breach of cryptographic integrity.

### Vulnerability Name: Insecure Direct Object Reference (IDOR) on Proxy Node Configurations

- **Description:**
    1. An attacker obtains a valid API key.
    2. The attacker sends a GET request to `/api/proxy_configs/{node_id}/` endpoint, replacing `{node_id}` with the ID of a proxy node.
    3. The server authenticates the request using the API key.
    4. The server retrieves the proxy node configuration based on the provided `node_id`.
    5. The server returns the proxy node configurations in JSON format without verifying if the API key is authorized to access the configuration of this specific node.
    6. The attacker can iterate through different `node_id` values to retrieve configurations for various proxy nodes.
- **Impact:**
    - Exposure of sensitive proxy node configuration details such as server addresses, ports, encryption methods, and passwords if included in configurations.
    - Attackers can use this information to directly target proxy servers, potentially bypassing application-level security controls, launching denial-of-service attacks against proxy nodes, or attempting to intercept user traffic.
- **Vulnerability Rank:** High
- **Currently implemented mitigations:**
    - API key authentication is implemented using the `@api_authorized` decorator in `apps/api/views.py`, which verifies the presence and validity of an API key in the request. This is a basic authentication measure.
- **Missing mitigations:**
    - Missing authorization checks to verify if the authenticated API key has the necessary permissions to access the configuration of the requested proxy node (`node_id`).
    - Role-based access control (RBAC) or Access Control Lists (ACLs) are not implemented to manage API key permissions and restrict access to specific resources.
- **Preconditions:**
    - A publicly accessible instance of the django-sspanel application must be deployed.
    - An attacker must possess a valid API key. This could be obtained through legitimate means (if API keys are intended for general use without authorization controls), or through compromising an administrative account or exploiting another vulnerability to retrieve an API key.
- **Source code analysis:**
    ```python
    # File: /code/apps/api/views.py
    from django.views import View
    from django.http import JsonResponse, HttpResponseBadRequest
    from django.utils.decorators import method_decorator

    from apps.utils import api_authorized
    from apps.proxy import models as m

    class ProxyConfigsView(View):
        @method_decorator(api_authorized)
        def get(self, request, node_id):
            node = m.ProxyNode.get_or_none(node_id) # [POINT OF VULNERABILITY] - Retrieves node by ID without authorization check
            return (
                JsonResponse(node.get_proxy_configs()) if node else HttpResponseBadRequest()
            )
    ```
    - The `ProxyConfigsView` in `/code/apps/api/views.py` is protected by the `@api_authorized` decorator, which provides authentication by checking the API key. However, after successful authentication, the code directly retrieves the `ProxyNode` based on the `node_id` path parameter using `m.ProxyNode.get_or_none(node_id)` without any further authorization checks. This means any valid API key, regardless of its intended scope or permissions, can be used to access the configurations of any `ProxyNode` by simply altering the `node_id` in the request. There is no mechanism to ensure that the API key is authorized to access the configuration of the specific `ProxyNode` being requested.

- **Security test case:**
    1. **Setup:** Deploy a publicly accessible instance of django-sspanel with at least two proxy nodes, for example, Node A (ID: 1) and Node B (ID: 2). Obtain a valid API key. Assume for this test that any valid API key grants access after authentication, which reflects the lack of authorization in the code.
    2. **Step 1: Request Configuration for Node A:** As an attacker, send a GET request to the endpoint for retrieving proxy configurations for Node A. Use the obtained API key in the `token` parameter and set `node_id` to 1.
        ```
        GET /api/proxy_configs/1/?token=<YOUR_API_KEY> HTTP/1.1
        Host: <YOUR_DJANGO_SSPANEL_INSTANCE>
        ```
    3. **Step 2: Observe Response for Node A:** Examine the response from the server. It should return a JSON response containing the proxy configurations for Node A, indicating successful access.
    4. **Step 3: Request Configuration for Node B:** Now, send a similar GET request, but this time, change the `node_id` to 2 to target Node B, while using the same API key.
        ```
        GET /api/proxy_configs/2/?token=<YOUR_API_KEY> HTTP/1.1
        Host: <YOUR_DJANGO_SSPANEL_INSTANCE>
        ```
    5. **Step 4: Observe Response for Node B:** Examine the response for this second request. It should also return a JSON response containing the proxy configurations for Node B, even though there was no specific authorization granted for this API key to access Node B's configuration.
    6. **Step 5: Verify Vulnerability:** If both requests are successful and return the configurations for different proxy nodes using the same API key, it confirms the Insecure Direct Object Reference vulnerability. This demonstrates that the API key, once authenticated, can access configurations of arbitrary proxy nodes without proper authorization checks.