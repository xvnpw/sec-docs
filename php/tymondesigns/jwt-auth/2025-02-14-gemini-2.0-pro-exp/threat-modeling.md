# Threat Model Analysis for tymondesigns/jwt-auth

## Threat: [Secret Key Compromise](./threats/secret_key_compromise.md)

*   **Threat:** Secret Key Compromise

    *   **Description:** An attacker gains access to the `JWT_SECRET` used to sign JWTs. This could happen through various means: weak key generation, accidental exposure in source code (e.g., committed to Git), configuration file leaks, server compromise, or brute-forcing a weak key.
    *   **Impact:** Complete system compromise. The attacker can forge JWTs for any user, granting them full access to the application and its data. They can impersonate any user, bypass all authentication, and potentially escalate privileges.
    *   **Affected Component:** `tymondesigns\JWTAuth\Providers\JWT\Provider` (specifically, the signing and verification logic that uses the secret key), configuration (`config/jwt.php` and `.env`).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use a cryptographically strong, randomly generated secret key (at least 256 bits, preferably 512 bits for HMAC).
        *   Store the secret key *outside* the codebase, using environment variables or a dedicated secrets management service (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault).
        *   *Never* commit the secret key to version control.
        *   Regularly rotate the secret key. Implement a phased approach to avoid invalidating all existing tokens at once.
        *   Protect the server environment to prevent unauthorized access to the secret key.
        *   Consider using asymmetric algorithms (RS256, ES256) to separate signing (private key) and verification (public key).

## Threat: [JWT Replay Attack](./threats/jwt_replay_attack.md)

*   **Threat:** JWT Replay Attack

    *   **Description:** An attacker intercepts a valid JWT (e.g., through a man-in-the-middle attack, even with HTTPS if there are vulnerabilities, or by accessing browser storage) and reuses it to gain unauthorized access. The attacker doesn't need to modify the token; they simply replay a previously valid one.
    *   **Impact:** The attacker gains access to the application with the privileges of the user whose token was intercepted, until the token expires. This can lead to unauthorized data access, modification, or other malicious actions.
    *   **Affected Component:** `tymondesigns\JWTAuth\JWT` (the token itself), `tymondesigns\JWTAuth\Manager` (token validation).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use short-lived JWTs (set a low `ttl` in `config/jwt.php`).
        *   Implement token refresh mechanisms using `tymondesigns\JWTAuth\JWT::refresh()`. Use short-lived access tokens and longer-lived, securely stored refresh tokens.
        *   Consider using the "jti" (JWT ID) claim and a blacklist (`tymondesigns\JWTAuth\Blacklist`) to revoke specific tokens. This adds statefulness but allows for immediate invalidation.
        *   Enforce HTTPS strictly, including HSTS, to prevent interception of tokens in transit.
        *   Store refresh tokens as HttpOnly cookies to prevent client-side JavaScript access.

## Threat: [Algorithm Confusion/Downgrade](./threats/algorithm_confusiondowngrade.md)

*   **Threat:** Algorithm Confusion/Downgrade

    *   **Description:** An attacker modifies the JWT header to change the signing algorithm to a weaker one (e.g., from RS256 to HS256, or to "none") and then signs the token with a known or empty secret. The attacker exploits a vulnerability where the server doesn't properly validate the algorithm before verifying the signature.
    *   **Impact:** The attacker can forge JWTs with arbitrary claims, bypassing authentication and gaining unauthorized access. The impact is similar to secret key compromise.
    *   **Affected Component:** `tymondesigns\JWTAuth\Providers\JWT\Provider` (specifically, the algorithm validation and signature verification logic).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Explicitly configure the allowed algorithms in `config/jwt.php`. *Never* allow the "none" algorithm.
        *   Ensure the library and its dependencies (especially `lcobucci/jwt`) are up-to-date to benefit from security patches.
        *   Verify that the library correctly validates the algorithm in the header against the configured allowed algorithms *before* signature verification.

