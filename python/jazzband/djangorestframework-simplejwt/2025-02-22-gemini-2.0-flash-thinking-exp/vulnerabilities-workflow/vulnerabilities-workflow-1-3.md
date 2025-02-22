## Vulnerability List

### Vulnerability Name: JWK URL Injection leading to Token Forgery

* Description:
    1. The `rest_framework_simplejwt` library allows configuration of a JWK URL (`JWK_URL` setting) for verifying JWT signatures.
    2. If an attacker can control or influence the `JWK_URL` setting, they can point it to a malicious endpoint serving a crafted JWK set.
    3. This malicious JWK set can contain a public key controlled by the attacker.
    4. The attacker can then generate a JWT token signed with the corresponding private key.
    5. When the application receives this forged JWT token and attempts to verify it using the compromised JWK URL, the attacker's public key will be used for verification.
    6. As a result, the forged token will be considered valid, bypassing authentication.

* Impact:
    - Authentication bypass: Attackers can forge valid JWT tokens and gain unauthorized access to the application's resources, impersonating any user.
    - Data breach: If the application handles sensitive data, successful authentication bypass can lead to unauthorized data access and exfiltration.
    - Account takeover: Attackers can forge tokens for any user, effectively taking over their accounts.
    - Full application compromise: Depending on the application's logic and permissions, successful authentication bypass can lead to complete compromise of the application and its underlying infrastructure.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    - None. The library does not validate or sanitize the `JWK_URL` setting. It directly uses the provided URL to fetch JWK sets.

* Missing mitigations:
    - JWK URL validation: Implement validation and sanitization of the `JWK_URL` setting to ensure it points to a trusted and legitimate endpoint. This could include:
        - URL scheme validation (e.g., only allow "https").
        - Domain validation (e.g., restrict to known and trusted domains).
        - Input sanitization to prevent injection attacks within the URL itself.
    - Consider implementing certificate pinning for HTTPS connections to the JWK URL to prevent Man-in-the-Middle attacks and ensure connection to the intended server.
    - Documentation should strongly recommend securing the configuration and restricting access to settings files.

* Preconditions:
    - The application using `rest_framework_simplejwt` must be configured to use JWK-based key verification by setting `SIMPLE_JWT['JWK_URL']` in Django settings.
    - An attacker must be able to control or influence the `JWK_URL` setting. This could be through various means, such as:
        - Misconfiguration of the application's settings management.
        - Vulnerabilities in the application's configuration mechanisms.
        - Insecure deployment practices that expose configuration files.

* Source code analysis:
    1. File: `/code/rest_framework_simplejwt/backends.py`
    2. Class `TokenBackend` `__init__` method initializes `jwks_client` using `api_settings.JWK_URL` without any validation:
    ```python
    if JWK_CLIENT_AVAILABLE:
        self.jwks_client = PyJWKClient(jwk_url) if jwk_url else None
    else:
        self.jwks_client = None
    ```
    3. The `get_verifying_key` method in `TokenBackend` fetches the verifying key from the JWK URL using `jwks_client.get_signing_key_from_jwt(token)`:
    ```python
    def get_verifying_key(self, token: Token) -> Any:
        ...
        if self.jwks_client:
            try:
                return self.jwks_client.get_signing_key_from_jwt(token).key
            except PyJWKClientError as ex:
                raise TokenBackendError(_("Token is invalid")) from ex
        ...
    ```
    4. The `jwt.decode` function in `TokenBackend.decode` uses the key obtained from `get_verifying_key` to verify the token signature:
    ```python
    def decode(self, token: Token, verify: bool = True) -> dict[str, Any]:
        ...
        try:
            return jwt.decode(
                token,
                self.get_verifying_key(token), # Verifying key fetched from JWK URL
                algorithms=[self.algorithm],
                ...
                options={
                    "verify_aud": self.audience is not None,
                    "verify_signature": verify,
                },
            )
        ...
    ```
    5. There is no validation of the `jwk_url` in the code. If `api_settings.JWK_URL` is set to a malicious URL, the application will fetch attacker-controlled keys and use them to verify forged tokens.

* Security test case:
    1. **Setup:**
        - Deploy a Django application using `rest_framework_simplejwt` for JWT authentication.
        - Configure `rest_framework_simplejwt` to use JWK-based verification by setting `SIMPLE_JWT['ALGORITHM'] = 'RS256'` and `SIMPLE_JWT['JWK_URL'] = 'http://localhost:8001/jwks.json'` in the Django settings. (Initially use a legitimate JWK endpoint for testing setup).
        - Create a protected API endpoint that requires JWT authentication.
    2. **Create Malicious JWK Endpoint:**
        - Set up a simple HTTP server (e.g., using Python's `http.server`) on `http://localhost:8001` that serves a JSON file (`jwks.json`) containing a crafted JWK set.
        - Generate an RSA key pair.
        - Create `jwks.json` with a JWK that includes the *public key* from the generated key pair. Example `jwks.json`:
        ```json
        {
          "keys": [
            {
              "kty": "RSA",
              "n": "...", // Public key modulus (base64url encoded)
              "e": "AQAB",
              "kid": "testkey"
            }
          ]
        }
        ```
        - Replace `"..."` with the base64url encoded modulus of your public RSA key.
    3. **Forge JWT Token:**
        - Using the *private key* corresponding to the public key in `jwks.json`, generate a JWT token. You can use libraries like `PyJWT` for this. The token should have a valid structure and claims (e.g., user ID).  The header should indicate `RS256` algorithm and include the `kid` from `jwks.json`.
        ```python
        import jwt
        import json

        private_key = open('private.pem').read() # Load your private key
        payload = {'user_id': 1} # Example payload
        headers = {'kid': 'testkey'} # kid matching JWK
        algorithm = 'RS256' # Algorithm matching JWK

        forged_token = jwt.encode(payload, private_key, algorithm=algorithm, headers=headers)
        print(forged_token)
        ```
    4. **Exploit:**
        - Change the `SIMPLE_JWT['JWK_URL']` setting in your Django application to point to your malicious JWK endpoint: `SIMPLE_JWT['JWK_URL'] = 'http://localhost:8001/jwks.json'`.
        - Send a request to the protected API endpoint, including the `forged_token` in the `Authorization` header (e.g., `Authorization: Bearer <forged_token>`).
    5. **Verification:**
        - Observe that the request to the protected API endpoint is successful and returns a 200 OK response, indicating that the forged token was accepted as valid.
        - This confirms the JWK URL injection vulnerability, as the application incorrectly validated the forged token using the attacker-controlled JWK set.