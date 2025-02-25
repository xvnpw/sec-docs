### 1. Insecure ALLOWED_HOSTS Configuration (Host Header Injection)

- **Description**:
  The Django settings (in both `config/common.py` and `config/production.py`) are configured with
  `ALLOWED_HOSTS = ["*"]`. This means that the application will accept requests with any Host header. An attacker can spoof the Host header when sending HTTP requests to the publicly available instance.
  **Trigger Steps**:
  1. Identify a publicly available API endpoint (e.g. `/api/v1/users/`).
  2. Craft an HTTP request that includes a malicious Host header (for example, `Host: malicious.example.com`).
  3. Send the request and observe that the request is processed normally despite the spoofed header.

- **Impact**:
  The acceptance of arbitrary Host headers can lead to host header injection. This may enable cache poisoning, abuse of dynamically generated links (e.g. in password-reset emails), or other unforeseen downstream attacks that rely on the host value.

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**:
  None. The configuration explicitly allows all hosts via the wildcard without additional validation.

- **Missing Mitigations**:
  • Restrict `ALLOWED_HOSTS` to the actual, expected host names or domains used in production.
  • Optionally add middleware or filters to sanitize or validate the Host header further.

- **Preconditions**:
  The application must be deployed in an environment that is accessible from the public Internet while using the default insecure ALLOWED_HOSTS setting.

- **Source Code Analysis**:
  • In *`{{cookiecutter.app_name}}/config/common.py`*, the line:
  `ALLOWED_HOSTS = ["*"]`
  • In *`{{cookiecutter.app_name}}/config/production.py`*, the inherited setting from Common is retained without further restriction.
  This means that no matter what Host header is sent, Django accepts the request as long as the remainder of the request is valid.

- **Security Test Case**:
  1. Deploy the application using the production settings.
  2. Using a tool such as curl or Postman, send an HTTP request to a known endpoint while deliberately setting a rogue Host header (e.g.,
     ```
     curl -H "Host: attacker.com" http://<public-ip>:8000/api/v1/users/
     ```
     ).
  3. Verify that the response is processed without error and that the system does not reject the request due to an invalid host.
  4. Optionally, inspect any links in the response that may reflect the malicious Host header.

---

### 2. Insecure Default DJANGO_SECRET_KEY

- **Description**:
  The project retrieves the Django secret key via `os.getenv('DJANGO_SECRET_KEY')` in the common configuration. However, in the provided docker-compose configuration the environment variable is explicitly set to a predictable value (`"local"`). An attacker who is aware of (or can guess) the secret key can create forged session cookies or tamper with token signatures.
  **Trigger Steps**:
  1. Deploy the instance using the provided docker-compose file (which sets `DJANGO_SECRET_KEY=local`).
  2. An attacker, knowing the key is “local”, can craft or alter session cookies or signed data (such as password-reset tokens) that Django relies on its secret key to secure.

- **Impact**:
  An attacker who knows the secret key can forge sessions, bypass authentication, or manipulate cookies and security tokens. This can lead to privilege escalation or unauthorized data access, effectively compromising the application’s integrity and confidentiality.

- **Vulnerability Rank**: Critical

- **Currently Implemented Mitigations**:
  In production the project expects `DJANGO_SECRET_KEY` to be provided via environment variable. However, in the included docker-compose file the default value remains set to `"local"`.

- **Missing Mitigations**:
  • Ensure that in any publicly deployed environment a strong, unpredictable secret key is provided via the environment.
  • Remove or change the default value in docker-compose for production usage.

- **Preconditions**:
  The deployment must use the provided docker-compose configuration without overriding the insecure default secret key.

- **Source Code Analysis**:
  • In *`{{cookiecutter.app_name}}/config/common.py`* the secret key is set by:
  `SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')`
  • In the docker-compose file (see `/code/docker-compose.yml`), the environment for the web service is set as:
  `- DJANGO_SECRET_KEY=local`
  This makes “local” the effective secret key if not changed.

- **Security Test Case**:
  1. Deploy the application using the provided docker-compose configuration.
  2. Verify (e.g., by inspection or through a controlled testing environment) that the secret key used by Django is “local”.
  3. Attempt to craft a forged session cookie or token using the known key “local”.
  4. Validate that the application accepts the forged credentials—demonstrating that an attacker could exploit the weak key in a live environment.

---

### 3. Use of Django Development Server in Production

- **Description**:
  Although the Dockerfile’s final `CMD` uses gunicorn for production, the docker-compose file overrides this by launching the Django development server with the command:
  `python3 wait_for_postgres.py && ./manage.py migrate && ./manage.py runserver 0.0.0.0:8000`.
  Django’s built‑in development server is not hardened for production, lacks robust security features, and may inadvertently expose debugging or sensitive information if errors occur.

- **Impact**:
  Running the insecure development server in a production environment can make the service more vulnerable to attacks. Its lack of advanced request handling, limited logging, and absence of production-grade security features (such as proper error pages and throttling) increase the attack surface. Furthermore, unexpected error pages might leak sensitive data.

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**:
  The Dockerfile specifies a production command using gunicorn. However, the docker-compose configuration (which is what is used to run the container) explicitly overrides this with a command that launches `runserver`.

- **Missing Mitigations**:
  • Modify the docker-compose configuration for production deployments to use the production command (i.e. gunicorn via the Dockerfile CMD).
  • Ensure that automated migration (and similar startup tasks) are handled externally from the command that starts the application server.

- **Preconditions**:
  The deployment must use the docker-compose configuration as-is (or its production equivalent) so that the web container is started with the `runserver` command rather than a production WSGI server.

- **Source Code Analysis**:
  • In *`Dockerfile`* the final stage sets the command to:
  `CMD newrelic-admin run-program gunicorn --bind 0.0.0.0:$PORT --access-logfile - {{cookiecutter.app_name}}.wsgi:application`
  • In *`docker-compose.yml`* under the “web” service the command is overridden with:
  ```
  command: >
      bash -c "python3 wait_for_postgres.py &&
               ./manage.py migrate &&
               ./manage.py runserver 0.0.0.0:8000"
  ```
  This override forces the use of Django’s development server.

- **Security Test Case**:
  1. Deploy the application using the provided docker-compose file.
  2. From an external network, access the application on port 8000 and inspect response headers or error pages to confirm that Django’s development server is in use (e.g., by its distinctive error page format or verbose logging).
  3. Attempt to trigger an error (for example, by sending a malformed request) and verify if debugging information or stack traces are leaked.

---

### 4. Missing Enforcement of HTTPS and Secure Cookie Settings

- **Description**:
  In the production configuration (as seen in *`config/production.py`*), there is no explicit enforcement of HTTPS traffic (e.g. via `SECURE_SSL_REDIRECT`) and secure cookie settings (such as `SESSION_COOKIE_SECURE` or `CSRF_COOKIE_SECURE`). This omission makes it possible for an attacker intercepting unsecured HTTP traffic to capture session cookies or tokens, especially if TLS is not terminated by a reverse proxy.

- **Impact**:
  Without enforced HTTPS and secure cookies, communications (including session IDs and auth tokens) can be intercepted or modified by a man‑in‑the‑middle attacker. This compromises user session integrity and the confidentiality of sensitive transactions.

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**:
  Some security middleware is present (for example, `SecurityMiddleware`), but the lack of explicit HTTPS redirection and cookie-security settings leaves this area unprotected if the application is deployed without a properly configured reverse proxy or load balancer handling TLS.

- **Missing Mitigations**:
  • Set `SECURE_SSL_REDIRECT = True` in production to force HTTPS.
  • Define `SESSION_COOKIE_SECURE = True` and `CSRF_COOKIE_SECURE = True` so that cookies are only sent over secure channels.
  • Optionally set HTTP Strict Transport Security (HSTS) headers (e.g. `SECURE_HSTS_SECONDS`) to enforce HTTPS even if a user requests HTTP.

- **Preconditions**:
  The risk applies when the public instance is accessed over plain HTTP or when TLS termination is not properly handled by an upstream proxy.

- **Source Code Analysis**:
  • In *`config/common.py`* and *`config/production.py`*, while the security middleware is included, there are no settings enforcing SSL redirection or marking cookies as secure.
  • This means that if the application is deployed without TLS offloading elsewhere, cookies and sessions are at risk.

- **Security Test Case**:
  1. Deploy the application in a production-like environment without an external TLS termination proxy.
  2. Access the application via HTTP (not HTTPS) and verify that the application does not automatically redirect to HTTPS.
  3. Inspect the cookies in the browser (or via curl) to check that the Secure attribute is missing.
  4. Capture network traffic to demonstrate that sensitive tokens or session cookies are sent in clear text.

---

### 5. Insecure Database Trust Authentication Configuration

- **Description**:
  The docker-compose configuration for the PostgreSQL service uses the environment variable
  `POSTGRES_HOST_AUTH_METHOD=trust`
  and the connection string in the Django settings defaults to a connection without a password (e.g. `postgres://postgres:@postgres:5432/postgres`). Although by default the postgres container has no port mapping (thus not directly exposed), if the container network is misconfigured or exposed, an attacker may connect to the database without credentials.

- **Impact**:
  In scenarios where the database container becomes reachable from the public network (whether inadvertently or by network misconfiguration), an attacker could connect without authentication and read or modify sensitive data stored in the database.

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**:
  The docker-compose file does not expose the PostgreSQL port externally in its current configuration; however, the use of trust authentication remains very risky if network boundaries are not properly enforced.

- **Missing Mitigations**:
  • Use strong database authentication (set a proper password and use PostgreSQL’s standard authentication methods rather than trust).
  • Ensure that the database ports are not exposed beyond the necessary internal Docker networks.
  • Consider enforcing network-level restrictions (for example via firewall rules) on database access.

- **Preconditions**:
  The vulnerability is triggered only if the PostgreSQL container’s network is misconfigured (or deliberately exposed) to include external access.

- **Source Code Analysis**:
  • In *`docker-compose.yml`*, the postgres service sets:
  `environment: - POSTGRES_HOST_AUTH_METHOD=trust`
  • The default connection string in *`config/common.py`* (via `dj_database_url.config`) does not specify a password, thereby relying on trust authentication.
  While this might be safe for an isolated local development environment, it is dangerous if deployed in a production setting with broader network exposure.

- **Security Test Case**:
  1. Deploy the docker-compose stack in an environment where the Postgres container is (or can be made) accessible from an external network (for testing purposes only).
  2. Attempt to establish a connection to the PostgreSQL service using a PostgreSQL client from an external host without specifying a password.
  3. Verify whether the connection is accepted and then attempt to read or modify data in the database.
  4. Confirm that the absence of proper authentication allows unauthorized database access.