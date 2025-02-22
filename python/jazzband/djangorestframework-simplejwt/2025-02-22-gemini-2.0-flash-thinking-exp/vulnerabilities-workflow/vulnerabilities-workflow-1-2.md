- **Inactive User Authentication Misconfiguration Risk**
  **Description:**
  1. The project originally disabled refresh-token generation for inactive users and then later added an option to “allow inactive user authentication and token generation” (as noted in the changelog).
  2. If an administrator (or a misconfigured deployment) enables this option, a valid token may be issued even when a user’s account is marked inactive.
  3. An external attacker who finds or creates an account marked inactive (or exploits an account that has been deactivated due to suspicious activity) could then obtain a token and bypass intended account disablement.
  **Impact:**
  The authentication and access controls are undermined because expected protections (i.e. inactive accounts should never be able to access protected resources) are bypassed—potentially leading to unauthorized access and privilege escalation.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  • The default behavior (and the `USER_AUTHENTICATION_RULE` used in the serializers) does check that a user is active.
  **Missing Mitigations:**
  • There is no forced safeguard against enabling inactive‑user token issuance. The library could add extra logging/warnings or even require an explicit “opt‑in” (with additional checks) so that administrators understand the risk when enabling this option.
  **Preconditions:**
  • The system must be configured to allow inactive users to authenticate (i.e. the option introduced in a recent changelog is enabled).
  **Source Code Analysis:**
  • In the various authentication and serializer modules (for example in the `TokenObtainSerializer.validate` method and in tests such as `test_user_inactive` in the views tests), a check is performed on `user.is_active`. However, if the configuration is changed to allow inactive user tokens, these checks can be bypassed.
  **Security Test Case:**
  1. Configure the application so that inactive users are allowed to obtain a JWT (simulate the misconfiguration).
  2. Create a user account and then mark it inactive (i.e. set `is_active = False`).
  3. Submit valid credentials for the inactive account to the token obtain endpoint.
  4. Verify that a valid token is issued.
  5. Use the token to access a protected resource and confirm that it returns a successful response despite the user’s inactive status.

- **Refresh Token Replay Vulnerability**
  **Description:**
  1. The library supports refresh token rotation (where a new access token—and optionally a new refresh token—is issued when a refresh is requested).
  2. However, if the system is configured with token rotation enabled but token blacklisting is not (i.e. `ROTATE_REFRESH_TOKENS` is true and `BLACKLIST_AFTER_ROTATION` is false or the blacklist app is not installed), then a refresh token that has already been used is still valid.
  3. An attacker who intercepts a refresh token may replay it multiple times to acquire several fresh access tokens.
  **Impact:**
  This vulnerability enables session hijacking and prolonged unauthorized access since an intercepted refresh token can be used repeatedly to obtain valid access tokens.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  • The library provides an option to blacklist refresh tokens on rotation; when enabled, a used refresh token is marked as blacklisted.
  **Missing Mitigations:**
  • By default (or in misconfigured deployments), if blacklisting is not enabled, there is no safeguard to prevent reuse of a refresh token.
  • It is recommended to enforce refresh token revocation (for example, setting `BLACKLIST_AFTER_ROTATION` to true) and/or implement one‑time use constraints on refresh tokens.
  **Preconditions:**
  • The system is deployed with refresh token rotation enabled but without refresh token blacklisting, thus leaving used tokens valid for subsequent replay.
  **Source Code Analysis:**
  • In `TokenRefreshSerializer` (located in `rest_framework_simplejwt/serializers.py`), after validating the refresh token and issuing a new access token the code checks if refresh token rotation is enabled. If so, it attempts to blacklist the token (if the blacklist app is available). Otherwise, if blacklisting is not enforced, the refresh token remains valid.
  **Security Test Case:**
  1. Deploy the application with `ROTATE_REFRESH_TOKENS` enabled but with `BLACKLIST_AFTER_ROTATION` disabled (or without the blacklist app installed).
  2. Log in and obtain a refresh token and the corresponding access token.
  3. Submit a refresh request using the refresh token and obtain a new access token.
  4. Reuse the same refresh token again successfully to obtain yet another access token.
  5. Demonstrate that the refresh token has not been invalidated between uses, proving that a replay attack is possible.

- **Weak JWT Signing Key Misconfiguration**
  **Description:**
  1. By default the library’s settings set the JWT signing key to Django’s `SECRET_KEY` (see the default in the settings file and in `setup.py`), without enforcing any minimum complexity requirements.
  2. In deployments where the same secret is used and/or it is chosen with insufficient entropy, an attacker can mount a brute‑force or dictionary attack against the signing key.
  3. Once the attacker discovers the weak key, they can forge tokens (by crafting a token with appropriate claims and signing it with the discovered key) that will pass the signature check.
  **Impact:**
  An attacker may impersonate any user and bypass all authentication checks, ultimately gaining full access to protected endpoints and sensitive data.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  • The library simply pulls the value of the JWT signing key from the Django settings (via the default setting for `SIGNING_KEY`). No key-strength validation is performed.
  **Missing Mitigations:**
  • Enforce or validate key “strength” (for example, by not relying on a developer’s Django `SECRET_KEY` or by requiring a dedicated, high‐entropy key for JWT signing).
  • Recommend (and/or enforce) the use of asymmetric (e.g. RSA) keys when appropriate.
  **Preconditions:**
  • The system is deployed with the default configuration where `SIGNING_KEY = settings.SECRET_KEY` and the secret key is weak or guessable.
  **Source Code Analysis:**
  • In `setup.py` and in the settings defaults in `rest_framework_simplejwt/settings.py`, the signing key is set to `settings.SECRET_KEY`.
  • The `TokenBackend` in `backends.py` uses this key (after a very simple preparation via PyJWT) both for token encoding and for signature verification.
  **Security Test Case:**
  1. Identify an instance of the deployed application where the JWT signing key is taken from a weak Django `SECRET_KEY`.
  2. Using a JWT tool, attempt to brute‑force the key (for example, target the HS256‑signed tokens).
  3. After recovering the key, forge a token with a chosen payload (e.g. impersonate an administrator) and sign it with the recovered key.
  4. Use the forged token to access a protected endpoint and confirm that unauthorized access is achieved.