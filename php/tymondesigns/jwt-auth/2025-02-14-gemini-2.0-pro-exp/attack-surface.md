# Attack Surface Analysis for tymondesigns/jwt-auth

## Attack Surface: [Weak or Exposed Secret Key](./attack_surfaces/weak_or_exposed_secret_key.md)

**Description:** The core vulnerability.  A compromised secret key allows complete impersonation and unauthorized access.
    *   **`jwt-auth` Contribution:** `jwt-auth` *entirely depends* on the `JWT_SECRET` for signing and verifying tokens.  The library provides *no* built-in protection against weak or exposed keys; this is solely the developer's responsibility.
    *   **Example:**
        *   Using a default or easily guessable `JWT_SECRET`.
        *   Exposing the `.env` file containing the secret key due to server misconfiguration.
        *   Accidentally committing the secret key to a public code repository.
    *   **Impact:** Complete system compromise; attackers can impersonate any user.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strong, Random Keys:** Generate a cryptographically secure random key (at least 64 characters, preferably longer). Use tools like `openssl rand -base64 64`.
        *   **Secure Storage (Environment Variables/KMS):** *Never* store the secret in version control. Use environment variables or, ideally, a dedicated Key Management System (KMS) like AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault.
        *   **Key Rotation:** Implement a regular key rotation policy (e.g., every 3-6 months).
        *   **Least Privilege Access:** Restrict access to the secret key to only the necessary application components.

## Attack Surface: [Algorithm Downgrade Attacks (Algorithm Confusion)](./attack_surfaces/algorithm_downgrade_attacks__algorithm_confusion_.md)

*   **Description:** Attackers manipulate the `alg` header to use a weaker or "none" algorithm, bypassing signature verification.
    *   **`jwt-auth` Contribution:** `jwt-auth` supports multiple algorithms.  If not explicitly configured to restrict the allowed algorithms, it's vulnerable.
    *   **Example:** An attacker changes the `alg` header to "none" and removes the signature.  If the server doesn't validate the `alg` header, it might accept the forged token.
    *   **Impact:** Token forgery; unauthorized access.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Algorithm Whitelist:** In `config/jwt.php`, *explicitly* set `supported_algs` to *only* the intended algorithm(s) (e.g., `['HS256']` or `['RS256']`).
        *   **Disable "none":**  Double-check that the "none" algorithm is *disabled* in the configuration.  This should be the default, but verification is crucial.
        *   **Pre-Validation:** Before passing the token to `jwt-auth`, the application code should independently validate the `alg` header against the configured whitelist.

## Attack Surface: [Missing or Inadequate Expiration (`exp`) Claim Validation](./attack_surfaces/missing_or_inadequate_expiration___exp___claim_validation.md)

*   **Description:**  If expiration is not enforced or is set too far in the future, stolen tokens remain valid for an extended period.
    *   **`jwt-auth` Contribution:** `jwt-auth` *does* validate the `exp` claim *by default*, but the developer *must* set a reasonable (short) expiration time.  The library won't enforce a specific duration.
    *   **Example:** A developer sets a very long `ttl` (time-to-live) in `config/jwt.php` (e.g., days or weeks), effectively disabling expiration checks.
    *   **Impact:** Extended unauthorized access; increased window for replay attacks.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Short `ttl`:** Set a short `ttl` in `config/jwt.php` (e.g., 5-15 minutes for most web applications).
        *   **Refresh Tokens (Securely):** For longer sessions, use short-lived access tokens *and* a securely implemented refresh token mechanism (see below, but note that insecure refresh tokens are also a high risk).
        *   **Confirm `exp` is Required:** Ensure that `jwt-auth` is configured to *require* the `exp` claim (it should be by default, but verify).

## Attack Surface: [Insecure Refresh Token Handling](./attack_surfaces/insecure_refresh_token_handling.md)

*   **Description:**  If using `jwt-auth`'s refresh token feature, vulnerabilities arise from improper storage, lack of rotation, or long lifespans.
    *   **`jwt-auth` Contribution:** `jwt-auth` *provides* the refresh token functionality, but secure implementation (storage, rotation, revocation) is *entirely* the developer's responsibility.  The library doesn't enforce secure practices.
    *   **Example:**
        *   Storing refresh tokens in client-side JavaScript-accessible storage (vulnerable to XSS).
        *   Using the same refresh token indefinitely without rotation.
        *   Not implementing a blacklist for revoked refresh tokens.
    *   **Impact:** Extended unauthorized access; session hijacking.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Short-Lived Refresh Tokens:** Use refresh tokens with a shorter lifespan than access tokens, but longer than the access token itself.
        *   **Refresh Token Rotation:** Issue a *new* refresh token with *each* access token refresh.
        *   **Secure Storage (HTTP-Only, Secure Cookies or Server-Side):** *Never* store refresh tokens in client-side JavaScript-accessible storage. Use HTTP-only, secure cookies (with `SameSite=Strict`) or a secure server-side store.
        *   **Revocation/Blacklisting:** Implement a mechanism to revoke refresh tokens (e.g., on logout, password change) and maintain a blacklist of revoked tokens.

