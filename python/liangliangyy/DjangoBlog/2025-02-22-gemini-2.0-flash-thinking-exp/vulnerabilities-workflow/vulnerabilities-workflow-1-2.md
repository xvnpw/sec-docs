- **Vulnerability Name:** Insecure Default SECRET_KEY Configuration
  - **Description:**
    The Django settings fall back to a hardcoded SECRET_KEY when the DJANGO_SECRET_KEY environment variable is missing. An external attacker who knows or can guess this default key can sign session cookies, CSRF tokens, or other signed data.
    *Steps to trigger:*
    1. Deploy the application without setting DJANGO_SECRET_KEY.
    2. Read the repository to discover the hardcoded default key.
    3. Construct forged signed tokens (e.g. session cookies) using the default key and present them to the application.
  - **Impact:**
    Forged tokens may enable session hijacking, CSRF bypass, and account impersonation by undermining cryptographic integrity.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The code attempts to load the key with `os.environ.get('DJANGO_SECRET_KEY')` but falls back to the hardcoded value.
  - **Missing Mitigations:**
    There is no requirement that a production deployment provide an override; the insecure default remains in the source code.
  - **Preconditions:**
    The application is deployed without setting DJANGO_SECRET_KEY so that the fallback (insecure default) is used.
  - **Source Code Analysis:**
    In `/code/djangoblog/settings.py`, the assignment:
    ```python
    SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY') or 'n9ceqv38)#&mwuat@(mjb_p%em$e8$qyr#fw9ot!=ba6lijx-6'
    ```
    means that when DJANGO_SECRET_KEY is absent, the default value is used.
  - **Security Test Case:**
    1. Deploy the application without defining DJANGO_SECRET_KEY.
    2. Using the known default key, craft a signed token (e.g. a session cookie) by signing arbitrary data.
    3. Present the forged token and verify that the application accepts it (for example, by gaining authenticated access).

---

- **Vulnerability Name:** Insecure ALLOWED_HOSTS Configuration Allowing Host Header Injection
  - **Description:**
    ALLOWED_HOSTS is configured to include the wildcard (`'*'`), meaning that the application accepts requests with any Host header.
    *Steps to trigger:*
    1. Send an HTTPS request to the deployed instance with a custom Host header (e.g. “evil.example.com”).
    2. Initiate functionality (such as a password reset) that constructs absolute URLs.
    3. Observe that the generated URLs use the attacker-controlled Host header.
  - **Impact:**
    This can allow phishing attacks, cache poisoning, or redirects to malicious sites since absolute URLs include the attacker‑controlled host.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The project sets ALLOWED_HOSTS but includes `'*'`, effectively disabling host restriction.
  - **Missing Mitigations:**
    Remove the wildcard and list only the valid hostnames expected in production.
  - **Preconditions:**
    The application is deployed with the current ALLOWED_HOSTS configuration.
  - **Source Code Analysis:**
    In `/code/djangoblog/settings.py` the ALLOWED_HOSTS is defined as:
    ```python
    ALLOWED_HOSTS = ['*', '127.0.0.1', 'example.com']
    ```
    so any Host header is accepted.
  - **Security Test Case:**
    1. Send an HTTP request with a custom Host header (e.g. “evil.example.com”).
    2. Trigger a feature that returns absolute URLs (such as a password reset email).
    3. Verify that the generated URL uses the attacker-controlled host, which could lead to phishing.

---

- **Vulnerability Name:** Missing OAuth State Parameter in OAuth Authentication Flows
  - **Description:**
    The OAuth managers (for providers such as Weibo, Google, GitHub, Facebook, and QQ) generate authorization URLs without including a state parameter—a key defense against CSRF in OAuth flows.
    *Steps to trigger:*
    1. Initiate an OAuth login flow where an attacker modifies or omits the state value in the authorization URL.
    2. Intercept the redirect callback and supply a forged code.
    3. The application, lacking state validation, exchanges the bogus code and may be deceived into linking or hijacking the account.
  - **Impact:**
    This flaw can allow CSRF attacks on the OAuth login process, enabling account linking hijack or bypassing standard authentication checks.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    No state parameter is included in the authorization URLs.
  - **Missing Mitigations:**
    Generate a random state parameter in the authorization request and validate it upon receiving the callback.
  - **Preconditions:**
    The application is configured with one or more OAuth providers and an attacker can intervene in the OAuth flow.
  - **Source Code Analysis:**
    In `/code/oauth/oauthmanager.py`, the code builds an authorization URL with parameters that do not include “state”:
    ```python
    params = {
        'client_id': self.client_id,
        'response_type': 'code',
        'redirect_uri': self.callback_url + '&next_url=' + nexturl
    }
    ```
    Similar omissions occur in other OAuth managers.
  - **Security Test Case:**
    1. Initiate an OAuth login using one of the providers (e.g. Weibo).
    2. Inspect the generated URL to confirm that no state parameter is present.
    3. Simulate a callback with an altered or missing state value and verify that the application does not reject the forged callback.

---

- **Vulnerability Name:** SSRF via Unvalidated External Avatar URL in OAuth Integration
  - **Description:**
    The function `save_user_avatar` downloads an external URL (provided by an OAuth provider) without sufficient validation. An attacker controlling the “picture” field in the OAuth response could supply a URL that targets an internal system.
    *Steps to trigger:*
    1. During an OAuth login, supply a malicious URL (such as “http://127.0.0.1/admin”) as the user’s avatar URL.
    2. The application calls `requests.get(url, timeout=2)` in the `save_user_avatar` function without verifying the host or scheme.
    3. The server makes an internal HTTP request to a sensitive resource.
  - **Impact:**
    An attacker may use SSRF to probe internal networks, access restricted services, or retrieve sensitive data indirectly.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The code checks the file extension (e.g. “.jpg”, “.png”) but does not validate the full URL (domain whitelisting, allowed protocols, or internal IP filtering).
  - **Missing Mitigations:**
    Enforce strict URL validation—whitelist allowed domains, permit only HTTP/HTTPS schemes, and filter out internal IP ranges.
  - **Preconditions:**
    An attacker is able to influence the avatar URL via the OAuth provider’s data or via direct user input.
  - **Source Code Analysis:**
    In `/code/djangoblog/utils.py`, the `save_user_avatar` function performs:
    ```python
    rsp = requests.get(url, timeout=2)
    if rsp.status_code == 200:
        ...
        ext = os.path.splitext(url)[1] if isimage else '.jpg'
        ...
    ```
    There is no check on the hostname or the URL scheme before making the request.
  - **Security Test Case:**
    1. Through an OAuth simulation or direct testing, supply a URL such as “http://127.0.0.1/private-info.jpg” as the avatar URL.
    2. Monitor the server’s outbound requests to confirm that it attempts to connect to the supplied URL.
    3. Verify that the request is not blocked or validated, confirming the SSRF vulnerability.

---

- **Vulnerability Name:** DEBUG Mode Enabled by Default in Production
  - **Description:**
    The Django settings use a helper (`env_to_bool`) to set the DEBUG flag, which defaults to True if DJANGO_DEBUG is not provided. When DEBUG is enabled, detailed error pages containing sensitive information (such as server config, file paths, and code snippets) are visible.
    *Steps to trigger:*
    1. Deploy the application in a production environment without setting DJANGO_DEBUG to False.
    2. Trigger an error by accessing a non-existent URL or causing an exception in a view.
    3. The resulting detailed error page is shown to the attacker.
  - **Impact:**
    Revealing detailed error messages and configuration data can help an attacker craft further targeted attacks.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The code reads DJANGO_DEBUG from the environment; however, its default is True.
  - **Missing Mitigations:**
    Ensure that DEBUG is explicitly set to False in production (for example, by using a production settings file that hardcodes `DEBUG = False`) and remove any insecure defaults from the repository.
  - **Preconditions:**
    The application is deployed in production without defining DJANGO_DEBUG or with it set to True.
  - **Source Code Analysis:**
    In `/code/djangoblog/settings.py`, DEBUG is configured as follows:
    ```python
    DEBUG = env_to_bool('DJANGO_DEBUG', True)
    ```
    This means that if DJANGO_DEBUG is not set, DEBUG remains enabled.
  - **Security Test Case:**
    1. Deploy the application without overriding DEBUG (or explicitly setting it to True).
    2. Force an application error by visiting an invalid URL.
    3. Confirm that the detailed Django error page (with sensitive details) is displayed.

---

- **Vulnerability Name:** Unauthenticated File Upload via Weak Signature Verification
  - **Description:**
    The `/upload` endpoint (implemented in `/code/blog/views.py`) is used to provide image hosting but is decorated with `@csrf_exempt` and does not require traditional authentication. Instead, it relies solely on a GET parameter (`sign`) that must equal a double‑hash of the application’s SECRET_KEY. If the application is deployed using an insecure (or known) SECRET_KEY, an attacker can compute the valid signature and upload arbitrary files.
    *Steps to trigger:*
    1. Deploy the application without overriding the insecure default SECRET_KEY.
    2. Compute the valid sign value by applying the same double‑hash (i.e. obtain `get_sha256(get_sha256(DEFAULT_SECRET_KEY))`).
    3. Send a POST request to `/upload` with the computed sign and include a file (for example, a file with a permitted extension like “.jpg”) containing malicious content.
    4. Observe that the file is saved on the server in the configured static files directory.
  - **Impact:**
    An attacker may upload malicious files that, if later executed (in case of misconfiguration of static file handling) or served to unsuspecting users, could lead to remote code execution, malware hosting, or further compromise of the server.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The endpoint checks for a valid sign derived from `settings.SECRET_KEY`. However, it:
    - Relies solely on this weak signature without additional authentication or content validations.
    - Uses only filename extensions (not file content or MIME type) to classify files as images.
  - **Missing Mitigations:**
    – Require proper user authentication or an API key rather than relying only on a predictable signature.
    – Validate file contents by checking MIME types and scanning for dangerous content.
    – Consider implementing CSRF protection and storing uploads in a secure, non‐executable location.
  - **Preconditions:**
    The application is deployed using the insecure default SECRET_KEY (or one that is guessable) and the file upload endpoint is publicly accessible.
  - **Source Code Analysis:**
    In `/code/blog/views.py`, the `fileupload` view:
    - Is decorated with `@csrf_exempt` so no CSRF token is required.
    - Reads the GET parameter `sign` and compares it with `get_sha256(get_sha256(settings.SECRET_KEY))`.
    - Iterates over `request.FILES` and (based solely on the file’s extension) determines whether the file is an image before storing it under a dynamically generated path.
    These measures are insufficient if the secret key is insecure or known from the repository, allowing an attacker to compute the sign value and upload files.
  - **Security Test Case:**
    1. Deploy the application without customizing the SECRET_KEY (so the default is used).
    2. Independently compute the valid sign by applying `get_sha256` twice to the known default SECRET_KEY.
    3. Craft a POST request to `/upload?sign=<computed-sign>` with a file payload (e.g. a file named “malicious.jpg”) that contains potentially malicious content.
    4. Verify that the upload succeeds (for example, by checking that the file is saved to disk and that its URL is included in the response).
    5. Evaluate whether the saved file could be used to trigger further attacks given the server’s configuration.