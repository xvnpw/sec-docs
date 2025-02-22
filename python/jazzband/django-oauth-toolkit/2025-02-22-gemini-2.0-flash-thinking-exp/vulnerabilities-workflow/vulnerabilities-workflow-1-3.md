### Vulnerability List:

- Vulnerability Name: Permissive CORS Policy due to Wildcard Allowed Origins
- Description:
    - An OAuth2 application can be configured with a wildcard (`*`) in the `allowed_origins` field.
    - When a request is made to the token endpoint with an `Origin` header that matches the `allowed_origins` (including wildcard), the server responds with an `Access-Control-Allow-Origin` header set to the request's origin or the wildcard.
    - If `allowed_origins` is set to a wildcard (`*`), this effectively disables CORS protection, allowing any website to make cross-origin requests and potentially obtain access tokens.
    - Step-by-step trigger:
        1. Create an OAuth2 application and set `allowed_origins` to `*`.
        2. From a malicious website (e.g., `http://malicious.attacker.com`), initiate an OAuth2 authorization code flow targeting the vulnerable OAuth2 provider.
        3. After the user authorizes the application, the malicious website receives an authorization code.
        4. The malicious website sends a POST request to the token endpoint (`/o/token/`) with the received authorization code, client credentials, and `Origin: http://malicious.attacker.com` header.
        5. The server responds with `Access-Control-Allow-Origin: *` or `Access-Control-Allow-Origin: http://malicious.attacker.com` header, along with the access token.
        6. The malicious website can now access the access token and use it to access protected resources on behalf of the user.
- Impact:
    - **Account Takeover Risk**: If an attacker successfully obtains an access token, they can impersonate the legitimate user and access their protected resources, potentially leading to data theft, unauthorized actions, and complete account takeover.
    - **Data Breach**:  Access tokens can grant broad permissions depending on the scopes requested. A successful exploit can lead to a significant breach of user data accessible through the OAuth2 API.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - CORS is implemented and controlled by the `allowed_origins` field on the `Application` model.
    - The code checks the `Origin` header against the `allowed_origins` list in `OAuthLibCore.verify_request()` (`oauth2_provider/oauth2_backends.py`).
    - Tests in `test_token_endpoint_cors.py` verify basic CORS functionality based on `allowed_origins`.
- Missing Mitigations:
    - **Input Validation for `allowed_origins`**: There is no validation on the format or content of the `allowed_origins` field. It allows wildcard `*` without any warnings or specific documentation discouraging its use in production.
    - **Guidance against Wildcard Origins**: Documentation and best practices should explicitly warn against using wildcard (`*`) in `allowed_origins` in production environments.
    - **Default Secure Configuration**:  The default behavior should be more secure, perhaps by disallowing wildcard origins unless explicitly enabled via a setting with a clear security warning.
- Preconditions:
    - An OAuth2 Application is configured with `allowed_origins = '*'`.
    - The application uses a grant type that involves token endpoint interaction from the client-side (e.g., authorization code grant with a client-side application).
    - CORS is enabled (implicitly enabled when `allowed_origins` is set).
- Source Code Analysis:
    - `oauth2_provider/views/mixins.py`: `OAuthLibMixin.get_oauthlib_core()` is responsible for creating `OAuthLibCore` instance.
    - `oauth2_provider/oauth2_backends.py`: `OAuthLibCore.verify_request()` method checks for `Origin` header and `application.allowed_origins`.
    ```python
    # File: /code/oauth2_provider/oauth2_backends.py
    # Visualization: Control flow for CORS check in OAuthLibCore.verify_request()

    # ... (code before) ...

    def verify_request(self, uri, http_method='GET', body=None, headers=None, scopes=None, client_id=None,
                       client_secret=None, assertion=None, username=None, password=None, code=None,
                       redirect_uri=None, refresh_token=None, request_type=''):
        # ... (other checks) ...

        if request_type in ['access_token', 'refresh_token']: # Token endpoint requests
            origin = headers.get('Origin')
            if origin:
                allowed_origins = self.application.allowed_origins.split() if self.application.allowed_origins else []
                if "*" in allowed_origins or origin in allowed_origins: # Vulnerability: Wildcard check
                    self.response_headers['Access-Control-Allow-Origin'] = origin if origin not in ["*"] else "*" # Sets ACAO header, wildcard is allowed
                    self.response_headers['Access-Control-Allow-Credentials'] = 'true'
        # ... (code after) ...
    ```
    - The code directly checks for wildcard `"*"` in `allowed_origins` and sets `Access-Control-Allow-Origin: *` if found, leading to the vulnerability.
- Security Test Case:
    1. **Setup:**
        - Create a new OAuth2 Application in the Django Admin panel.
        - Set `Name`: "Malicious App CORS Test"
        - Set `Client type`: Confidential
        - Set `Authorization grant type`: Authorization code
        - Set `Allowed origins`: `*`
        - Save the application and note the `Client ID` and `Client secret`.
        - Ensure `PKCE_REQUIRED` setting is `False` for simplicity.
    2. **Attacker's Malicious Website:**
        - Create a simple HTML file (e.g., `malicious.html`) hosted on `http://malicious.attacker.com`.
        - Include JavaScript code to perform the OAuth2 authorization code flow and token exchange.
        ```html
        <!DOCTYPE html>
        <html>
        <head>
            <title>Malicious Website</title>
        </head>
        <body>
            <h1>Malicious Website</h1>
            <button id="authButton">Get Access Token</button>
            <div id="output"></div>

            <script>
                const authButton = document.getElementById('authButton');
                const outputDiv = document.getElementById('output');
                const clientId = 'YOUR_CLIENT_ID'; // Replace with Client ID from step 1
                const redirectUri = 'http://malicious.attacker.com/malicious.html';
                const authorizationEndpoint = 'http://localhost:8000/o/authorize/'; // Replace with your authorization endpoint
                const tokenEndpoint = 'http://localhost:8000/o/token/'; // Replace with your token endpoint

                authButton.addEventListener('click', () => {
                    const authorizationUrl = `${authorizationEndpoint}?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=read`;
                    window.location.href = authorizationUrl;
                });

                const urlParams = new URLSearchParams(window.location.search);
                const authorizationCode = urlParams.get('code');

                if (authorizationCode) {
                    fetch(tokenEndpoint, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Origin': 'http://malicious.attacker.com' // Set malicious origin
                        },
                        body: new URLSearchParams({
                            'grant_type': 'authorization_code',
                            'code': authorizationCode,
                            'redirect_uri': redirectUri,
                            'client_id': clientId,
                            'client_secret': 'YOUR_CLIENT_SECRET' // Replace with Client Secret from step 1
                        })
                    })
                    .then(response => response.json())
                    .then(data => {
                        outputDiv.innerHTML = `<p>Access Token: ${data.access_token}</p>`;
                        // In a real attack, the attacker would exfiltrate the access_token
                        console.log('Access Token:', data.access_token);
                    })
                    .catch(error => {
                        outputDiv.innerHTML = `<p>Error: ${error.message}</p>`;
                    });
                }
            </script>
        </body>
        </html>
        ```
        - **Replace placeholders**: In the `malicious.html` file, replace `YOUR_CLIENT_ID` and `YOUR_CLIENT_SECRET` with the Client ID and Client secret of the application created in step 1. Update `authorizationEndpoint` and `tokenEndpoint` if your endpoints are different.
    3. **Victim Interaction:**
        - Host the `malicious.html` file on a server accessible as `http://malicious.attacker.com/malicious.html`.
        - Send the link `http://malicious.attacker.com/malicious.html` to a victim user.
        - The victim user clicks the "Get Access Token" button on the malicious website and authorizes the OAuth2 application on the provider's site (e.g., `http://localhost:8000`).
    4. **Verification:**
        - After authorization, the victim is redirected back to `http://malicious.attacker.com/malicious.html`.
        - Observe the "Access Token: ..." displayed on the malicious website.
        - Check the browser's developer console (Console tab) for `Access Token: ...` output, confirming the access token was successfully retrieved by the malicious website due to the wildcard CORS configuration.