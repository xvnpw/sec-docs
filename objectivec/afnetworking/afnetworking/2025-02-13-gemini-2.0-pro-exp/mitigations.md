# Mitigation Strategies Analysis for afnetworking/afnetworking

## Mitigation Strategy: [Certificate Pinning](./mitigation_strategies/certificate_pinning.md)

*   **Description:**
    1.  **Obtain Server Certificate/Public Key:** Obtain the SSL/TLS certificate or, preferably, the public key of your server's certificate.
    2.  **Store Securely:** Store the certificate data (or a hash of the public key) as a resource file within your application.
    3.  **Configure `AFSecurityPolicy`:**
        *   Create an instance of `AFSecurityPolicy`.
        *   Set the `pinningMode` to `AFSSLPinningModePublicKey` (recommended) or `AFSSLPinningModeCertificate`.
        *   Set `allowInvalidCertificates` to `NO`.
        *   Set `validatesDomainName` to `YES`.
        *   Load the certificate data.
        *   Set the `pinnedCertificates` property to an `NSSet` containing the loaded certificate data.
    4.  **Apply to `AFHTTPSessionManager`:** Assign the configured `AFSecurityPolicy` to the `securityPolicy` property of your `AFHTTPSessionManager`.
    5.  **Implement Update Mechanism:** Have a process to update the pinned certificate/key *before* expiration.
    6.  **Thorough Testing:** Simulate MitM attacks to verify correct implementation.

*   **Threats Mitigated:**
    *   **Man-in-the-Middle (MitM) Attacks:** (Severity: **Critical**)
    *   **Compromised Certificate Authority (CA):** (Severity: **Critical**)

*   **Impact:**
    *   **MitM Attacks:** Risk reduced from **Critical** to **Very Low**.
    *   **Compromised CA:** Risk reduced from **Critical** to **Very Low**.

*   **Currently Implemented:**
    *   Implemented in `NetworkManager.m`.
    *   Uses `AFSSLPinningModePublicKey`.
    *   Certificate data in `server_pubkey.cer`.
    *   Update: Manual app update.

*   **Missing Implementation:**
    *   No automated certificate update. (**High** priority)
    *   No secondary pinned certificate. (**Medium** priority)
    *   Not implemented for `images.example.com`. (**Medium** priority)

## Mitigation Strategy: [Secure `AFSecurityPolicy` Configuration](./mitigation_strategies/secure__afsecuritypolicy__configuration.md)

*   **Description:**
    1.  **`allowInvalidCertificates`:** Set to `NO` in production. Use preprocessor macros for conditional use in debug builds.
    2.  **`validatesDomainName`:** Set to `YES` in production.
    3.  **Code Review:** Check these settings in code reviews.
    4.  **Automated Testing:** Verify settings with unit tests.

*   **Threats Mitigated:**
    *   **Accidental Misconfiguration:** (Severity: **High**)
    *   **Hostname Spoofing:** (Severity: **High**)

*   **Impact:**
    *   **Accidental Misconfiguration:** Risk reduced from **High** to **Low**.
    *   **Hostname Spoofing:** Risk reduced from **High** to **Low**.

*   **Currently Implemented:**
    *   `allowInvalidCertificates` is `NO` in release.
    *   `validatesDomainName` is `YES` in all configurations.
    *   Code review checklist includes these settings.

*   **Missing Implementation:**
    *   No unit tests for `AFSecurityPolicy` settings. (**Medium** priority)

## Mitigation Strategy: [Secure Serialization/Deserialization (AFNetworking Serializers)](./mitigation_strategies/secure_serializationdeserialization__afnetworking_serializers_.md)

*   **Description:**
    1.  **Prefer `AFJSONResponseSerializer`:** Use for JSON responses.
    2.  **Avoid `AFPropertyListResponseSerializer` with Untrusted Data:** If used, rigorously validate before and after deserialization.
    3.  **Never Use `NSKeyedUnarchiver` with Untrusted Data:**  Avoid any custom serializer configuration that might use this.
    4. **Input Validation:** Validate data against schema after deserialization.

*   **Threats Mitigated:**
    *   **Remote Code Execution (RCE):** (Severity: **Critical**)
    *   **Data Tampering:** (Severity: **High**)

*   **Impact:**
    *   **RCE:** Risk reduced from **Critical** to **Low** (with proper validation).
    *   **Data Tampering:** Risk reduced from **High** to **Medium**.

*   **Currently Implemented:**
    *   `AFJSONResponseSerializer` is used.
    *   Basic input validation (checking for `nil`).

*   **Missing Implementation:**
    *   No strict schema validation. (**High** priority)

## Mitigation Strategy: [`HTTPShouldHandleCookies` Awareness](./mitigation_strategies/_httpshouldhandlecookies__awareness.md)

*   **Description:**
    1.  **Understand Default Behavior:** Be aware that AFNetworking handles cookies automatically by default (using the system's cookie storage).
    2.  **Manual Control (If Needed):** Set `HTTPShouldHandleCookies` to `NO` on the `AFHTTPSessionManager` if you require fine-grained control over cookie handling.  This is *not* usually necessary, but the option exists.

*   **Threats Mitigated:**
    *   **Unintentional Cookie Handling Issues:** (Severity: **Low**)  Ensures you're aware of how cookies are being managed and can intervene if the default behavior is not suitable.

*   **Impact:**
    *   **Unintentional Cookie Handling Issues:** Risk reduced from **Low** to **Very Low** (by increasing awareness).

*   **Currently Implemented:**
    *   `HTTPShouldHandleCookies` is at the default (`YES`).

*   **Missing Implementation:**
    *   None. This strategy is about *awareness* of the setting.

## Mitigation Strategy: [Request Timeouts](./mitigation_strategies/request_timeouts.md)

*   **Description:**
    1.  **Set `timeoutInterval`:** Set a reasonable timeout (e.g., 30-60 seconds) on the `NSURLRequest` or the `AFHTTPSessionManager` using the `timeoutInterval` property.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS):** (Severity: **Medium**)
    *   **Application Unresponsiveness:** (Severity: **Medium**)

*   **Impact:**
    *   **DoS:** Risk reduced from **Medium** to **Low**.
    *   **Application Unresponsiveness:** Risk reduced from **Medium** to **Low**.

*   **Currently Implemented:**
    *   60-second timeout on `AFHTTPSessionManager`.

*   **Missing Implementation:**
    *   No specific error handling for timeouts. (**Low** priority)
    *   No retry mechanism. (**Low** priority)

## Mitigation Strategy: [Avoid Deprecated Methods](./mitigation_strategies/avoid_deprecated_methods.md)

* **Description:**
    1.  **Code Reviews:** Check for deprecated AFNetworking methods.
    2.  **Compiler Warnings:** Address warnings about deprecated methods.
    3.  **Documentation:** Use AFNetworking documentation for replacements.
    4.  **Refactor:** Replace deprecated methods.

* **Threats Mitigated:**
    * **Unknown Vulnerabilities:** (Severity: **Variable**)
    * **Unexpected Behavior:** (Severity: **Medium**)

* **Impact:**
    * **Unknown Vulnerabilities:** Risk reduced from **Variable** to **Low**.
    * **Unexpected Behavior:** Risk reduced from **Medium** to **Low**.

* **Currently Implemented:**
    * Code reviews check for deprecated methods.

* **Missing Implementation:**
    * No automated tooling. (**Low** priority)

