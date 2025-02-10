# Threat Model Analysis for bitwarden/mobile

## Threat: [Clipboard Data Sniffing](./threats/clipboard_data_sniffing.md)

*   **Threat:** Clipboard Data Sniffing

    *   **Description:** A malicious application installed on the device uses the operating system's clipboard access permissions to monitor and steal data copied from the Bitwarden application. The attacker could be waiting for the user to copy a password or 2FA code and then immediately capture it.
    *   **Impact:**  Compromise of user credentials, 2FA codes, or other sensitive data stored in Bitwarden, leading to unauthorized access to accounts.
    *   **Affected Component:**  `ClipboardService` (or equivalent platform-specific clipboard interaction module), any UI component that allows copying data (e.g., password display fields, 2FA code display).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   Implement a short timeout (e.g., 30 seconds) after which the clipboard is automatically cleared by the Bitwarden app. Use platform-specific APIs (e.g., `ClipboardManager.clearPrimaryClip()` on Android).
            *   Minimize the use of the clipboard; prioritize autofill functionality.
            *   If clipboard use is necessary, consider a "one-time copy" feature that clears the clipboard immediately after the first paste.
            *   Provide a user-configurable option to disable clipboard access entirely.
        *   **User:**
            *   Use autofill whenever possible instead of copy/paste.
            *   Be aware of installed applications and their permissions.
            *   Manually clear the clipboard after copying sensitive data.

## Threat: [Screen Capture/Recording by Malicious App](./threats/screen_capturerecording_by_malicious_app.md)

*   **Threat:** Screen Capture/Recording by Malicious App

    *   **Description:** A malicious app with screen recording permissions (or exploiting an OS vulnerability) captures screenshots or records the screen while the user is interacting with Bitwarden, revealing sensitive information like passwords or vault contents.
    *   **Impact:**  Exposure of user credentials, notes, and other sensitive data, leading to account compromise.
    *   **Affected Component:**  All UI components displaying sensitive data (e.g., `PasswordDisplayActivity`, `VaultItemDetailsFragment`, `LoginView`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   Use platform-specific APIs to prevent screenshots and screen recording when sensitive data is visible.  On Android, use `getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE)`. On iOS, detect screen recording using `UIScreen.main.isCaptured` and obscure sensitive views.
            *   Implement a "privacy screen" feature that blurs or obscures sensitive data by default, requiring an explicit user action (e.g., tap-to-reveal) to show it.
        *   **User:**
            *   Be cautious about granting screen recording permissions to apps.
            *   Regularly review installed apps and their permissions.

## Threat: [Autofill Injection into Malicious App](./threats/autofill_injection_into_malicious_app.md)

*   **Threat:** Autofill Injection into Malicious App

    *   **Description:** A malicious app mimics the UI of a legitimate app (e.g., a banking app) and tricks the Bitwarden autofill service into filling credentials into the wrong application. The attacker could create a fake login screen that looks identical to the real one.
    *   **Impact:**  Leakage of user credentials to the attacker, leading to account takeover.
    *   **Affected Component:**  `AutofillService` (or equivalent platform-specific autofill implementation), integration with OS autofill framework.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   **Strict Application Verification:** Before filling credentials, rigorously verify the requesting application's identity. Use strong application signing and package name verification. On Android, use `AutofillService.onFillRequest()` and check `FillRequest.getClientState()`. On iOS, use `ASAuthorizationController` and verify the requesting app's bundle identifier.
            *   **Contextual Autofill:**  Consider the context of the autofill request. For example, if the user is on a website, verify the domain name before filling credentials.
            *   **User Confirmation:**  Implement a confirmation dialog before autofilling sensitive credentials, showing the target application's name and icon.
            *   **Biometric Prompt:**  Require biometric authentication (if available) before autofilling highly sensitive credentials.
        *   **User:**
            *   Pay close attention to the autofill prompts and ensure they are filling credentials into the correct application.
            *   Enable biometric authentication for autofill if available.

## Threat: [Keylogging of Master Password](./threats/keylogging_of_master_password.md)

*   **Threat:** Keylogging of Master Password

    *   **Description:** A malicious app or a compromised custom keyboard captures keystrokes entered by the user, including the Bitwarden master password. The keylogger could be running in the background with elevated privileges.
    *   **Impact:**  Complete compromise of the user's Bitwarden vault, granting the attacker access to all stored credentials and data.
    *   **Affected Component:**  `MasterPasswordEntryActivity` (or equivalent), any component handling master password input.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   **Secure In-App Keyboard:**  Implement a custom, in-app keyboard for master password entry that bypasses the system keyboard. This keyboard should be designed to resist common keylogging techniques. This is a *significant* mitigation, but not a perfect solution against highly sophisticated, OS-level keyloggers.
            *   **Biometric Authentication:**  Encourage and prioritize the use of biometric authentication (fingerprint, face recognition) as an alternative to typing the master password.
            *   **Two-Factor Authentication (2FA):**  Strongly encourage the use of 2FA, which adds an extra layer of security even if the master password is compromised.
        *   **User:**
            *   Use a strong, unique master password.
            *   Enable biometric authentication if available.
            *   Enable 2FA for their Bitwarden account.
            *   Be cautious about installing custom keyboards from untrusted sources.

## Threat: [Data at Rest Encryption Bypass (Device Compromise)](./threats/data_at_rest_encryption_bypass__device_compromise_.md)

*   **Threat:** Data at Rest Encryption Bypass (Device Compromise)

    *   **Description:** An attacker gains physical access to the device (lost or stolen) and bypasses the device's lock screen or extracts data from the device's storage.  This could involve exploiting vulnerabilities in the device's operating system or using specialized forensic tools.
    *   **Impact:**  Exposure of all data stored in the Bitwarden vault, even if the app is locked.
    *   **Affected Component:**  `DataStorage` module (responsible for encrypting and storing data locally), interaction with platform-specific secure storage (Keychain/Keystore).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   **Strong Encryption:** Use strong, industry-standard encryption algorithms (e.g., AES-256) to encrypt data at rest.
            *   **Platform-Specific Secure Storage:**  Leverage the platform's secure storage mechanisms (Keychain on iOS, Keystore on Android) to protect encryption keys. Ensure keys are tied to the device's lock screen and biometric authentication.
            *   **Key Derivation:** Use a strong key derivation function (e.g., PBKDF2, Argon2) to derive encryption keys from the user's master password.
            *   **Secure Enclave/TEE:** If available, utilize the device's Secure Enclave (iOS) or Trusted Execution Environment (TEE) to perform sensitive cryptographic operations and store encryption keys.
        *   **User:**
            *   Use a strong device passcode/PIN.
            *   Enable biometric authentication (fingerprint, face recognition) for device unlock.
            *   Enable full-disk encryption on the device (usually enabled by default on modern devices).
            *   Enable remote wipe capabilities (e.g., Find My iPhone, Find My Device).

## Threat: [Biometric Spoofing](./threats/biometric_spoofing.md)

* **Threat:** Biometric Spoofing

    * **Description:** An attacker uses a fake fingerprint, photograph, or other method to bypass the biometric authentication (fingerprint or face recognition) used to unlock the Bitwarden app.
    * **Impact:** Unauthorized access to the user's Bitwarden vault.
    * **Affected Component:** `BiometricAuthenticationManager` (or equivalent), integration with platform-specific biometric APIs.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   **Developer:**
            *   **Liveness Detection:** Use platform-provided liveness detection features (if available) to help distinguish between a real biometric and a spoof.
            *   **Strong Biometric APIs:** Utilize the latest and most secure biometric APIs provided by the operating system.
            *   **Fallback Authentication:** Always provide a strong fallback authentication method (e.g., PIN, password) in case biometric authentication fails or is compromised.
            *   **Regular Updates:** Keep the biometric authentication components updated to address any known vulnerabilities.
        *   **User:**
            *   Be aware of the limitations of biometric authentication and the possibility of spoofing.
            *   Use a strong fallback authentication method.
            *   Keep their device's operating system and the Bitwarden app updated.

## Threat: [Application Tampering (Repackaging)](./threats/application_tampering__repackaging_.md)

*   **Threat:** Application Tampering (Repackaging)
    *   **Description:** An attacker downloads the Bitwarden application, modifies its code (e.g., to disable security checks or inject malicious code), and then redistributes the tampered application through unofficial channels (e.g., third-party app stores). This is a mobile-specific distribution vector.
    *   **Impact:**  Users who install the tampered application could have their credentials stolen, data modified, or other malicious actions performed.
    *   **Affected Component:**  Entire application package (APK/IPA).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   **Code Signing:**  Digitally sign the application package to ensure its integrity and authenticity.
            *   **Integrity Checks:** Implement runtime integrity checks to detect if the application has been modified. This can involve checking checksums of critical code sections or using platform-specific APIs.
            *   **Obfuscation:** Use code obfuscation techniques to make it more difficult to reverse engineer and modify the application.
            *   **Anti-Tampering Libraries:** Consider using third-party anti-tampering libraries that provide additional protection against modification.
        *   **User:**
            *   Only download the Bitwarden application from official sources (Google Play Store, Apple App Store).
            *   Avoid installing applications from untrusted websites or third-party app stores.

