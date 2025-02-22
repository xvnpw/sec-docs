### Vulnerability List

- Vulnerability Name: Refresh Token Reuse without Reuse Protection
- Description:
    - An attacker can reuse a refresh token to obtain new access tokens if refresh token reuse protection is not enabled.
    - Step 1: An attacker intercepts or steals a valid refresh token belonging to a legitimate user.
    - Step 2: The attacker uses the stolen refresh token to request a new access token from the token endpoint.
    - Step 3: The server, if not configured with refresh token reuse protection, grants a new access token using the same refresh token.
    - Step 4: The attacker can repeat Step 2 and Step 3 multiple times, continuously obtaining valid access tokens as long as the refresh token is valid and not expired or revoked by other means.
- Impact:
    - Account takeover. An attacker with a stolen refresh token can persistently access the user's resources, even after the user's session has ended or the user has changed their password. This grants long-term unauthorized access to the protected resources.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Refresh token rotation (`ROTATE_REFRESH_TOKEN` setting): This feature, if enabled, rotates refresh tokens upon each use, reducing the window of opportunity for reuse, but it does not inherently prevent reuse of the *previous* refresh token before rotation.
    - Setting `REFRESH_TOKEN_REUSE_PROTECTION` exists: This setting, when enabled, revokes the refresh token after it's used once, effectively preventing reuse. However, it is not enabled by default.
- Missing Mitigations:
    - Enable `REFRESH_TOKEN_REUSE_PROTECTION` setting by default.
    - If enabling by default is not desired, prominently recommend enabling `REFRESH_TOKEN_REUSE_PROTECTION` in the documentation, especially when `ROTATE_REFRESH_TOKEN` is also enabled, as it's a crucial security best practice.
- Preconditions:
    - `ROTATE_REFRESH_TOKEN` setting is enabled (which is a recommended security practice).
    - `REFRESH_TOKEN_REUSE_PROTECTION` setting is disabled (which is the default setting).
    - An attacker must successfully obtain a valid refresh token, for example, through network interception, phishing, or malware.
- Source Code Analysis:
    - (Analysis is based on project settings, documentation, existing tests and general OAuth2 flow understanding. Source code for core token handling logic is not directly present in the provided PROJECT FILES, but test files and settings files provide enough context.)
    - The vulnerability is not directly found in the provided code *files* themselves, but rather in the *default configuration* of the django-oauth-toolkit project.
    - The `settings.py` file (from PROJECT FILES) defines `REFRESH_TOKEN_REUSE_PROTECTION` in `DEFAULTS` as `False`, implying it defaults to `False` as per the library's default settings.
    - The `oauth2_provider/oauth2_validators.py` file contains `validate_refresh_token` method, which includes the logic for refresh token reuse protection:
    ```python
    if oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION and rt.token_family:
        rt_token_family = RefreshToken.objects.filter(token_family=rt.token_family)
        for related_rt in rt_token_family.all():
            related_rt.revoke()
    ```
    - This code snippet confirms that `REFRESH_TOKEN_REUSE_PROTECTION` setting controls the reuse protection behavior. When enabled, it revokes all refresh tokens in the same family upon reuse.
    - By default, without explicit configuration in a project's `settings.py`, `django-oauth-toolkit` does not enable refresh token reuse protection. This means that if `ROTATE_REFRESH_TOKEN` is enabled (which is common for security), the system will rotate refresh tokens on use, but the *old* refresh token remains valid until a *new* refresh token is used. During this window, if an attacker steals the refresh token, they can reuse it multiple times to obtain new access tokens.
    - Enabling `REFRESH_TOKEN_REUSE_PROTECTION = True` in the project's `settings.py` activates the intended mitigation, ensuring that each refresh token can be used only once. Upon successful use, the refresh token is revoked, and subsequent attempts to use the same refresh token will fail.

- Security Test Case:
    - Step 1: Set up a test environment of django-oauth-toolkit. Configure `settings.py` to include:
        ```python
        OAUTH2_PROVIDER = {
            'ROTATE_REFRESH_TOKEN': True,
            'REFRESH_TOKEN_REUSE_PROTECTION': False, # Vulnerable configuration
        }
        ```
    - Step 2: Register a confidential client application.
    - Step 3: Using a test user, initiate the Authorization Code Grant flow with the registered client. Obtain an authorization code and then exchange it for an access token and a refresh token.
    - Step 4: Store the obtained refresh token (let's call it `refresh_token_original`).
    - Step 5: Use `refresh_token_original` to request a new access token from the token endpoint using a `POST` request with `grant_type=refresh_token`, `refresh_token=refresh_token_original`, `client_id` and `client_secret` for the registered client. This request should succeed, and you will receive a new access token and a new refresh token (due to rotation).
    - Step 6: Again, use the *same* `refresh_token_original` (from Step 4) to request another new access token from the token endpoint, using the same parameters as in Step 5.
    - Step 7: Verify that this second request in Step 6 is also successful and a new access token is granted. This confirms the refresh token reuse vulnerability because the original refresh token was used more than once successfully.
    - Step 8: Now, change the configuration in `settings.py` to enable reuse protection:
        ```python
        OAUTH2_PROVIDER = {
            'ROTATE_REFRESH_TOKEN': True,
            'REFRESH_TOKEN_REUSE_PROTECTION': True, # Mitigated configuration
        }
        ```
    - Step 9: Repeat Steps 2-5 to obtain a new `refresh_token_original`.
    - Step 10: Use `refresh_token_original` to request a new access token (as in Step 5). This should succeed.
    - Step 11: Replay the *same* `refresh_token_original` (from Step 9) to request another new access token (as in Step 6).
    - Step 12: Verify that this second request in Step 11 now fails. The server should return an error, such as `invalid_grant`, indicating that the refresh token has been invalidated after its first use, and reuse protection is working correctly.

- Vulnerability Name: Redirect URI Validation Bypass via Wildcard Domain
- Description:
    - If `ALLOW_URI_WILDCARDS` is enabled, a malicious client may be able to register a redirect URI with a wildcard that bypasses intended validation logic. This occurs because the wildcard validation logic in `oauth2_provider.models.redirect_to_uri_allowed` and `oauth2_provider.validators.AllowedURIValidator` might not correctly handle all edge cases, particularly when wildcards are used in conjunction with specific URI structures. The current implementation checks if wildcard is not in top level or second level domain by checking if `len(domain_parts) < 3`, which is insufficient and can be bypassed using domains like `test.*.co.uk`.
    - Step 1: An attacker registers a new OAuth2 client application or updates an existing one (if allowed) with `ALLOW_URI_WILDCARDS = True`.
    - Step 2: In the application registration form, the attacker provides a malicious redirect URI containing a wildcard, such as `https://test.*.co.uk`. The intention is to bypass validation that should prevent wildcards in top-level or second-level domains.
    - Step 3: The system's redirect URI validator, specifically `AllowedURIValidator` and the `redirect_to_uri_allowed` function, incorrectly validates this malicious wildcard redirect URI. It fails to properly enforce restrictions on wildcard placement due to insufficient check `len(domain_parts) < 3`.
    - Step 4: A legitimate user initiates an OAuth2 authorization flow with the attacker's client application.
    - Step 5: Upon successful authentication, the authorization server generates an authorization code and redirects the user to the attacker-controlled redirect URI (`https://test.attacker.co.uk`, which is considered valid by the flawed wildcard validation).
    - Step 6: The attacker intercepts the authorization code from the redirect URI and can then exchange it for an access token, potentially gaining unauthorized access to the user's resources.
- Impact:
    - Authorization code interception. Successful exploitation allows an attacker to redirect users to attacker-controlled domains after successful authentication, intercepting the authorization code in the redirect URI. This can be further used to obtain access tokens and potentially lead to account takeover or data breaches.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - `AllowedURIValidator` (in `oauth2_provider/validators.py`): This validator is used to check the validity of redirect URIs during application registration and authorization requests. It is designed to enforce allowed schemes and handle wildcard domains based on the `ALLOW_URI_WILDCARDS` setting.
    - The validator includes a check `if len(domain_parts) < 3:` in `AllowedURIValidator.__call__` to prevent wildcards in top-level and second-level domains when `ALLOW_HOSTNAME_WILDCARD` is enabled.
    - `redirect_to_uri_allowed` function (in `oauth2_provider/models.py`): This function uses `AllowedURIValidator` to check if a given URI is within the allowed redirect URIs for a client application. It includes logic for wildcard hostname matching.
- Missing Mitigations:
    - More robust and comprehensive wildcard validation logic within `AllowedURIValidator` and `redirect_to_uri_allowed`. The current check `if len(domain_parts) < 3:` in `AllowedURIValidator.__call__` is not sufficient to prevent wildcard bypasses in domains like `test.*.co.uk`. This should include stricter rules to prevent wildcards in top-level and second-level domains and to handle various edge cases in wildcard pattern matching to avoid bypasses.
    - Implement more specific and restrictive regular expressions or dedicated parsing logic for wildcard domain validation to ensure that only intended wildcard patterns are permitted and malicious patterns are rejected. For example, ensure that wildcard `*` is only allowed as the leftmost part of the hostname and is followed by at least a second level domain and a top level domain.
- Preconditions:
    - `ALLOW_URI_WILDCARDS` setting must be enabled in the django-oauth-toolkit configuration.
    - Application registration functionality must be enabled and accessible to potential attackers, or there must be a way for attackers to modify existing application configurations.
    - A vulnerable wildcard redirect URI pattern, such as `https://test.*.co.uk`, must be used that bypasses the current validation logic.
- Source Code Analysis:
    - Analyze `oauth2_provider/validators.py` - `AllowedURIValidator.__call__` function:
        ```python
        class AllowedURIValidator(URIValidator):
            # ...
            def __call__(self, value):
                # ...
                if self.allow_hostname_wildcard and "*" in netloc:
                    domain_parts = netloc.split(".")
                    if netloc.count("*") > 1:
                        # ...
                    if not netloc.startswith("*"):
                        # ...
                    if len(domain_parts) < 3: # Insecure check
                        # ...
                    # ...
        ```
        - The wildcard validation logic in `AllowedURIValidator.__call__` checks for the number of domain parts using `len(domain_parts) < 3`.
        - Vulnerability: The condition `len(domain_parts) < 3` is insufficient to prevent wildcard bypasses. It incorrectly allows wildcards in domains with more than 2 parts, such as `test.*.co.uk`, where `domain_parts` would be `['test', '*', 'co', 'uk']` and `len(domain_parts)` is 4, which is not less than 3, thus bypassing the intended restriction. This allows attackers to register redirect URIs with wildcards in effectively third-level domains and beyond, leading to potential redirect URI bypass.
    - Analyze `oauth2_provider/models.py` - `redirect_to_uri_allowed` function:
        - This function uses `AllowedURIValidator` to perform the actual validation, thus inheriting the flawed wildcard validation logic.
- Security Test Case:
    - Step 1: Set up a test environment of django-oauth-toolkit with `ALLOW_URI_WILDCARDS = True` in `settings.py`.
    - Step 2: Log in as a superuser or a user who can register OAuth2 applications (if registration is enabled).
    - Step 3: Attempt to register a new confidential client application with the following redirect URI: `https://test.*.co.uk`. Fill in other required fields for application registration (name, client type, grant type, etc.).
    - Step 4: Submit the application registration form.
    - Step 5: Check the response.
        - Expected behavior (secure): The application registration should fail with a validation error, indicating that the redirect URI is invalid due to the wildcard in the third-level domain.
        - Vulnerable behavior: The application registration succeeds, and the malicious redirect URI is accepted.
    - Step 6: If the application registration is successful (vulnerable behavior), initiate an Authorization Code Grant flow with this newly registered application. Use a valid user account and authorize the application.
    - Step 7: Observe the redirect URI after authorization. If the redirect goes to a URI like `https://test.attacker.co.uk/?code=...`, it confirms the wildcard bypass because `attacker.co.uk` was not intended to be a valid redirect URI for `https://test.*.co.uk`.
    - Step 8: Attempt to exchange the intercepted authorization code for an access token. If successful, it further confirms the vulnerability, as an attacker can now obtain access tokens using a bypassed redirect URI.