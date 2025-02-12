# Threat Model Analysis for facebook/react-native

## Threat: [OTA Update Manipulation](./threats/ota_update_manipulation.md)

*   **Description:** An attacker intercepts the Over-the-Air (OTA) update process (e.g., via a man-in-the-middle attack). They replace the legitimate, signed update bundle with a malicious one containing modified JavaScript code.  This allows the attacker to execute arbitrary code within the application's context, bypassing standard app store review processes.
    *   **Impact:**
        *   Complete application compromise.
        *   Data theft (credentials, user data, etc.).
        *   Malware installation.
        *   Reputational damage.
        *   Potential for device compromise (if native modules are also compromised via the injected JS).
    *   **React Native Component Affected:**  OTA update mechanism (e.g., CodePush client, custom update implementation). Specifically, the code responsible for downloading, verifying the digital signature, and applying the update.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Mandatory Code Signing:**  Implement *strict* code signing for *all* OTA updates. The application *must* verify the signature of the downloaded bundle against a trusted, securely stored public key *before* applying the update.  Reject any unsigned or invalidly signed updates.
        *   **HTTPS with Certificate Pinning:**  Use HTTPS for all communication with the update server. Implement certificate pinning to prevent MITM attacks even if the attacker compromises a Certificate Authority.
        *   **End-to-End Encryption (E2EE):**  Consider E2EE for the update bundle itself. The bundle is encrypted on the server and decrypted only by the application using a securely stored key (separate from the code signing key).
        *   **Integrity Checks (Hashing):**  Calculate a cryptographic hash (e.g., SHA-256) of the downloaded bundle *after* signature verification. Compare this hash to a known good hash obtained through a *separate, secure channel* (not the update channel itself). This adds an extra layer of defense.
        *   **Rollback Mechanism:** Implement a robust mechanism to roll back to a previous, known-good version of the application if an update fails verification or causes unexpected behavior.

## Threat: [Deep Link Hijacking](./threats/deep_link_hijacking.md)

*   **Description:** An attacker creates a malicious application that registers the same deep link scheme (URL scheme) as the legitimate React Native application. When a user clicks a link intended for the legitimate app, the operating system might launch the malicious app instead. The attacker can then phish for credentials, steal data passed in the deep link, or redirect the user. This exploits how React Native apps handle external URLs.
    *   **Impact:**
        *   Credential theft (phishing).
        *   Data leakage (if sensitive data is passed insecurely in the deep link).
        *   User redirection to malicious sites.
        *   Impersonation of the legitimate application, leading to further attacks.
    *   **React Native Component Affected:**  Deep linking configuration (AndroidManifest.xml on Android, Info.plist on iOS), and the JavaScript code that handles incoming deep links (e.g., using `Linking.addEventListener` and associated event handlers).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Android App Links (Android):**  *Must* use Android App Links. This requires verifying website ownership, preventing other apps from claiming the same deep links.  This is the primary defense on Android.
        *   **Universal Links (iOS):**  *Must* use Universal Links. This also requires website association and is significantly more secure than custom URL schemes on iOS.
        *   **Strict Input Validation:**  Treat *all* data received via deep links as *completely untrusted*. Implement rigorous input validation and sanitization on *every* parameter received.
        *   **Confirmation Prompts (for sensitive actions):**  For *any* sensitive action triggered by a deep link (e.g., login, password reset, financial transactions), display a clear, unambiguous confirmation prompt to the user *before* proceeding. This gives the user a chance to verify the correct application is handling the request.
        *   **Avoid Sensitive Data in Deep Links:**  *Never* pass sensitive data (session tokens, passwords, PII) directly in deep link parameters. Use a secure, indirect method, such as a one-time token that is exchanged for a session token *after* the application is launched and verified.

## Threat: [Insecure Native Bridge Communication](./threats/insecure_native_bridge_communication.md)

*   **Description:** The React Native bridge facilitates communication between JavaScript and native code. If sensitive data is transmitted across the bridge without encryption or integrity checks, an attacker with access to the device (especially rooted/jailbroken) or a compromised native module could intercept, modify, or replay this data. This is a unique attack surface of React Native.
    *   **Impact:**
        *   Data leakage (credentials, API keys, user data, internal application state).
        *   Manipulation of data passed between JavaScript and native code, leading to unexpected behavior.
        *   Potential for privilege escalation (if the attacker can trigger native functions with elevated privileges).
    *   **React Native Component Affected:**  The React Native bridge itself, and any custom native modules that interact with the bridge. Specifically, the methods used to send and receive messages (e.g., `NativeModules`, `DeviceEventEmitter`, custom event emitters).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Minimize Bridge Traffic:**  Reduce the amount of sensitive data passed over the bridge. Perform sensitive operations entirely on the native side or, preferably, on a secure backend server.
        *   **Data Encryption:**  Encrypt *all* sensitive data *before* sending it over the bridge. Use a strong, well-vetted encryption algorithm (e.g., AES-256 with a secure key exchange mechanism) and securely manage the encryption keys. Do *not* hardcode keys.
        *   **Strict Input Validation (both sides):**  Implement rigorous input validation and sanitization on *both* sides of the bridge (JavaScript and native). Treat data from the other side as *completely untrusted*.
        *   **Authentication and Authorization (for native functions):**  If native functions are exposed via the bridge, implement strong authentication and authorization checks to ensure that only authorized JavaScript code can invoke them.  Consider using a token-based approach.
        *   **Message Integrity (MAC/Signatures):**  Use a message authentication code (MAC) or digital signatures to ensure the integrity of messages passed over the bridge. This prevents attackers from tampering with the data in transit and ensures the message originated from the expected source.

## Threat: [Native Module Permission Escalation](./threats/native_module_permission_escalation.md)

* **Description:** A malicious or unintentionally vulnerable native module (either a third-party library or a custom-built module) requests excessive or unnecessary permissions. If exploited, an attacker could gain unauthorized access to sensitive device features (camera, microphone, contacts, location, etc.) or data, exceeding the application's legitimate needs. This leverages the native capabilities accessed through React Native.
    * **Impact:**
        * Unauthorized access to sensitive device features and data.
        * Data theft.
        * Potential for complete device compromise.
        * Privacy violations.
    * **React Native Component Affected:** Native modules (Java/Kotlin on Android, Objective-C/Swift on iOS) and their permission requests (AndroidManifest.xml on Android, Info.plist on iOS). The bridge interface connecting to these modules.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Principle of Least Privilege:**  *Strictly* adhere to the principle of least privilege. Request only the *absolute minimum* necessary permissions for each native module.
        * **Thorough Permission Auditing:**  Carefully review and audit the permissions requested by *all* native modules, including those from third-party libraries. Question any excessive or seemingly unnecessary permissions.
        * **Runtime Permission Handling (Android 6.0+):**  Implement proper runtime permission handling, especially on Android. Request permissions only when they are *actually needed* at runtime, and gracefully handle cases where the user denies permission. Provide clear explanations to the user about why each permission is required.
        * **Code Review (Custom Modules):**  Conduct thorough code reviews of any custom native modules, focusing on security best practices and ensuring they are not requesting unnecessary permissions or performing unauthorized actions.
        * **Sandboxing (where possible):** Explore sandboxing techniques to limit the capabilities of native modules, even if they have been granted permissions.

