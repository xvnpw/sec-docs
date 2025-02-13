# Mitigation Strategies Analysis for facebook/facebook-android-sdk

## Mitigation Strategy: [Strict Permission Control and Data Access Minimization (using SDK methods)](./mitigation_strategies/strict_permission_control_and_data_access_minimization__using_sdk_methods_.md)

*   **Description:**
    1.  **Identify Essential Functionality:** Determine the minimal Facebook features your app requires.
    2.  **Permission Audit:** Consult the Facebook Permissions Reference ([https://developers.facebook.com/docs/permissions/](https://developers.facebook.com/docs/permissions/)).
    3.  **Minimal Permission Request (SDK):** Use the `facebook-android-sdk`'s `LoginManager` class.  Specifically, use `logInWithReadPermissions(Activity activity, Collection<String> permissions)` or `logInWithPublishPermissions(Activity activity, Collection<String> permissions)`.  The `permissions` collection should contain *only* the absolutely necessary permission strings (e.g., `"public_profile"`, `"email"` – but only if truly needed).  *Do not* request all permissions at once.
    4.  **Runtime Requests (SDK):** Use `LoginManager` to request permissions at the time they are needed, not during app startup.  This provides better context to the user.  The SDK provides callbacks to handle the results of the permission request.
    5.  **Check Existing Permissions (SDK):** Before requesting a permission, use `AccessToken.getCurrentAccessToken().getPermissions().contains("permission_name")` to check if the permission has already been granted.
    6.  **Handle Denials (SDK):** Implement the `FacebookCallback<LoginResult>` interface to handle the results of the login and permission request.  This includes handling `onCancel()` (user canceled) and `onError(FacebookException error)` (an error occurred).  Provide user-friendly messages and alternative flows if a permission is denied.
    7.  **Regular Reviews:** Periodically review the requested permissions, especially after SDK updates.

*   **Threats Mitigated:**
    *   **Excessive Data Collection (Severity: High):** Directly controls the data the SDK can access.
    *   **Data Breach Impact (Severity: High):** Limits the scope of potential data breaches.
    *   **Reputational Damage (Severity: Medium):** Improves user trust by requesting only necessary permissions.
    *   **App Store Rejection (Severity: Medium):** Avoids rejection due to excessive permission requests.

*   **Impact:**
    *   **Excessive Data Collection:** Risk reduced significantly (High impact).
    *   **Data Breach Impact:** Risk reduced significantly (High impact).
    *   **Reputational Damage:** Risk reduced moderately (Medium impact).
    *   **App Store Rejection:** Risk reduced moderately (Medium impact).

*   **Currently Implemented:**
    *   `LoginManager.getInstance().logInWithReadPermissions()` used with `public_profile` in `LoginActivity.java`.
    *   Basic runtime permission check.

*   **Missing Implementation:**
    *   No regular permission audit.
    *   Improved handling of permission denials needed.
    *   No review after SDK updates.

## Mitigation Strategy: [Secure Access Token Handling (using SDK features)](./mitigation_strategies/secure_access_token_handling__using_sdk_features_.md)

*   **Description:**
    1.  **Never Hardcode:** Access tokens must never be hardcoded.
    2.  **Secure Storage:** Use the Android Keystore System (`AndroidKeyStore`) for secure storage. This is *separate* from the SDK, but crucial for securing the token the SDK provides.
    3.  **No Logging:** Never log access tokens.
    4.  **Expiration Handling (SDK):** Use `AccessToken.getCurrentAccessToken()` to get the current token.  Check `isExpired()` to see if it's still valid.  Implement `AccessTokenTracker` to receive notifications about token changes (expiration, refresh).  This is a *direct SDK feature*.  Override `onCurrentAccessTokenChanged(AccessToken oldAccessToken, AccessToken currentAccessToken)` to handle these changes.
    5.  **Refresh Tokens (if applicable, SDK):** If using refresh tokens, handle them securely. The SDK may handle refresh token management automatically, but verify this in the documentation.
    6.  **Logout (SDK):** When the user logs out, *always* call `LoginManager.getInstance().logOut()`. This is a *critical SDK method* that invalidates the Facebook session and clears the access token managed by the SDK.

*   **Threats Mitigated:**
    *   **Token Theft (Severity: High):** Prevents unauthorized access to the user's Facebook account.
    *   **Session Hijacking (Severity: High):** Makes session hijacking much more difficult.
    *   **Unauthorized API Access (Severity: High):** Prevents unauthorized use of the Facebook API.

*   **Impact:**
    *   **Token Theft:** Risk reduced significantly (High impact).
    *   **Session Hijacking:** Risk reduced significantly (High impact).
    *   **Unauthorized API Access:** Risk reduced significantly (High impact).

*   **Currently Implemented:**
    *   `AccessToken.getCurrentAccessToken()` is used.
    *   `LoginManager.getInstance().logOut()` is called on logout.

*   **Missing Implementation:**
    *   Access token stored in `SharedPreferences` (unencrypted) – needs migration to `AndroidKeyStore`.
    *   No `AccessTokenTracker` implementation for proactive expiration handling.

## Mitigation Strategy: [Keep SDK Updated](./mitigation_strategies/keep_sdk_updated.md)

*   **Description:**
    1.  **Dependency Management:** Use Gradle to manage the `facebook-android-sdk` dependency.
    2.  **Regular Updates:** Check for updates to the `facebook-android-sdk` frequently (e.g., monthly). Update to the latest stable version promptly.  This is crucial because Facebook releases security patches through SDK updates.
    3.  **Security Advisories:** Subscribe to Facebook's developer security alerts.
    4.  **Rollback Plan:** Have a plan to revert to a previous SDK version if necessary.

*   **Threats Mitigated:**
    *   **Exploitation of Known SDK Vulnerabilities (Severity: Variable, potentially High):** Directly addresses vulnerabilities patched by Facebook in SDK updates.

*   **Impact:**
    *   **Exploitation of Known SDK Vulnerabilities:** Risk reduced significantly (High to Medium impact, depending on the vulnerability).

*   **Currently Implemented:**
    *   SDK included as a Gradle dependency.

*   **Missing Implementation:**
    *   No automated update checks.
    *   Not subscribed to security alerts.
    *   No rollback plan.

