# Threat Model Analysis for airbnb/mavericks

## Threat: [Unintentional Sensitive State Exposure via Persistence](./threats/unintentional_sensitive_state_exposure_via_persistence.md)

*   **Description:** An attacker gains access to the device's storage and reads the persisted Mavericks state, which contains sensitive information like user credentials, API keys, or PII. The attacker might use a rooted device or exploit file system vulnerabilities.  This is *directly* related to Mavericks because it's Mavericks' persistence mechanism (`persistState = true`) that is storing the data.
    *   **Impact:**
        *   Compromise of user accounts.
        *   Unauthorized access to protected resources.
        *   Data breaches and privacy violations.
        *   Reputational damage.
        *   Financial loss.
    *   **Affected Component:** `MavericksViewModel` with `persistState = true` and the underlying persistence mechanism (likely `SharedPreferences` or a custom implementation). The `copy` method of the state data class is also directly involved if it doesn't handle sensitive data properly during persistence.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid Persisting Sensitive Data:** The best mitigation is to avoid persisting sensitive data.
        *   **Encrypt Persisted State:** If persistence is unavoidable, encrypt the state using Android's Keystore System and a strong encryption algorithm (e.g., AES-GCM).
        *   **Use Secure Storage Alternatives:** Consider `EncryptedSharedPreferences` or a secure database (e.g., SQLCipher).
        *   **Selective Persistence:** Only persist the absolute minimum necessary data.
        *   **Custom `copy` Method:** Implement a custom `copy` method that excludes or sanitizes sensitive fields.
        *   **Regular Security Audits:** Conduct regular security audits.

## Threat: [State Exposure via Logging](./threats/state_exposure_via_logging.md)

*   **Description:** An attacker gains access to system logs and extracts sensitive information that was inadvertently logged from the Mavericks state. This is *directly* related to Mavericks because it's the Mavericks state object that is being logged (potentially carelessly).
    *   **Impact:**
        *   Disclosure of sensitive information (PII, credentials, etc.).
        *   Potential for further attacks.
        *   Privacy violations.
    *   **Affected Component:** `MavericksViewModel` and any logging calls (e.g., `Log.d`, `Timber.i`) that output the state or parts of the state.  The developer's use of Mavericks' state within logging statements is the direct link.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Never Log Sensitive Data:** Avoid logging the entire state object or sensitive fields.
        *   **Use a Production-Ready Logging Library:** Use a library like Timber with filtering and redaction.
        *   **Configure Log Levels:** Set appropriate log levels for different environments.
        *   **Redact Sensitive Information:** Redact sensitive parts before logging.
        *   **Review Logging Code:** Regularly review logging statements.

## Threat: [State Manipulation via Malicious Deep Link](./threats/state_manipulation_via_malicious_deep_link.md)

*   **Description:**  An attacker crafts a malicious deep link that sets the Mavericks *state* to a malicious value, bypassing security checks or triggering unintended actions. This is *directly* related to Mavericks because the deep link is being used to (incorrectly) initialize or modify the Mavericks state.
    *   **Impact:**
        *   Bypassing of authentication/authorization.
        *   Execution of unauthorized actions.
        *   Data corruption.
        *   Potential denial-of-service.
    *   **Affected Component:** `MavericksViewModel` and the application's deep link handling, specifically the code that uses deep link data to set the `initialState` or otherwise modify the state via `setState`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Input Validation:** Validate and sanitize all deep link parameters.
        *   **Whitelist Allowed Parameters:** Define a whitelist of allowed parameters.
        *   **Avoid Directly Setting State:** Don't directly set state from parameters; use them to trigger actions.
        *   **Use Intent Filters Carefully:** Define restrictive Intent filters.
        *   **Implement App Links:** Use Android App Links (verified deep links).

## Threat: [Vulnerability in Mavericks Library](./threats/vulnerability_in_mavericks_library.md)

*   **Description:** A security vulnerability exists in the Mavericks library itself (or one of its *direct* dependencies, as managed by Mavericks). An attacker exploits this to compromise the application.
    *   **Impact:** Varies; could range from information disclosure to arbitrary code execution.
    *   **Affected Component:** The Mavericks library itself (`com.airbnb.android:mavericks`, `com.airbnb.android:mavericks-core`, etc.) and its *direct* dependencies.
    *   **Risk Severity:** Critical or High (depending on the vulnerability).
    *   **Mitigation Strategies:**
        *   **Keep Mavericks Updated:** Regularly update to the latest stable version.
        *   **Monitor Security Advisories:** Subscribe to security advisories and vulnerability databases.
        *   **Use Dependency Scanning Tools:** Employ tools like Snyk or OWASP Dependency-Check.
        *   **Promptly Apply Patches:** Apply patches or updates immediately when available.

