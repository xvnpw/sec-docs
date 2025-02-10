# Attack Surface Analysis for bitwarden/mobile

## Attack Surface: [Data at Rest (Device Compromise/Loss/Theft)](./attack_surfaces/data_at_rest__device_compromiselosstheft_.md)

*Description:* Unauthorized access to sensitive data stored on the mobile device. This includes the encrypted vault, master password hash, session tokens, and any temporary files.
*How Mobile Contributes:* Mobile devices are inherently more susceptible to loss, theft, and physical compromise than desktop computers. Users may also install malicious apps or have less secure device configurations, increasing the risk of unauthorized access to the device's file system.
*Example:* An attacker steals a user's unlocked phone and uses a file explorer to access the Bitwarden data directory, attempting to decrypt the vault. Or, malware on the device reads data directly from Bitwarden's storage.
*Impact:* Complete compromise of the user's Bitwarden vault, leading to exposure of all stored passwords, notes, and other sensitive information.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **(Developer):** Utilize platform-specific secure storage (Android Keystore, iOS Keychain). Employ strong encryption (AES-256-GCM or better) with robust key derivation (PBKDF2, Argon2). Implement secure deletion of temporary files. Enforce a strong master password policy. Offer and strongly encourage two-factor authentication (2FA). Implement a "zero-knowledge" architecture.
    *   **(User):** Use a strong, unique master password. Enable 2FA for their Bitwarden account. Enable full-disk encryption on their mobile device. Set a strong device passcode/PIN/pattern. Keep the device OS and Bitwarden app updated. Avoid installing apps from untrusted sources. Be cautious of phishing attempts. Consider using a biometric lock for the Bitwarden app. Enable remote wipe capabilities for the device.

## Attack Surface: [Clipboard Exposure](./attack_surfaces/clipboard_exposure.md)

*Description:* Sensitive data (passwords, 2FA codes) copied to the system clipboard can be accessed by other applications.
*How Mobile Contributes:* Mobile users frequently copy and paste passwords between apps, a behavior more common on mobile than desktop due to the smaller screen and input methods. Mobile operating systems often have less restrictive clipboard access controls compared to desktop OSes, making this a higher risk.
*Example:* A user copies a password from Bitwarden to paste into a website login form. A malicious app running in the background reads the clipboard contents, stealing the password.
*Impact:* Exposure of individual passwords or 2FA codes, potentially leading to account compromise.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **(Developer):** Minimize clipboard usage for sensitive data. Implement a short clipboard timeout (e.g., 30 seconds) after which the clipboard is cleared. Provide a user-configurable option for clipboard clearing. Consider an in-app clipboard. Warn users about the risks.
    *   **(User):** Be mindful of what is copied to the clipboard. Manually clear the clipboard after pasting sensitive data. Use a clipboard manager that automatically clears the clipboard. Avoid copying sensitive data on public Wi-Fi.

## Attack Surface: [Screen Capture/Recording (Malware/Compromised Device)](./attack_surfaces/screen_capturerecording__malwarecompromised_device_.md)

*Description:* Malware or a compromised device OS can capture screenshots or record the screen, revealing sensitive information displayed by Bitwarden.
*How Mobile Contributes:* Mobile devices are more susceptible to malware infections than well-maintained desktop systems, and users may inadvertently grant excessive permissions to apps, increasing the likelihood of screen capture malware.
*Example:* A user opens Bitwarden to view a password. Malware running in the background takes a screenshot, capturing the displayed password.
*Impact:* Exposure of passwords, notes, and other sensitive information displayed on the screen.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **(Developer):** Use platform-specific APIs to prevent screenshots and screen recording when sensitive data is displayed (e.g., `FLAG_SECURE` on Android). Obfuscate sensitive UI elements.
    *   **(User):** Keep the device OS and apps updated. Avoid installing apps from untrusted sources. Be cautious of granting unnecessary permissions to apps. Use a reputable mobile security solution.

## Attack Surface: [Insecure Inter-Process Communication (IPC)](./attack_surfaces/insecure_inter-process_communication__ipc_.md)

*Description:* Vulnerabilities in how the Bitwarden app communicates with other apps or components on the device.
*How Mobile Contributes:* Mobile operating systems rely heavily on IPC mechanisms (e.g., Intents on Android, URL schemes). Improperly configured or secured IPC can be exploited by malicious apps, a risk that is more prevalent on mobile due to the app-centric nature of the platform.
*Example:* A malicious app registers to handle a custom URL scheme used by Bitwarden. When the user clicks a malicious link, the malicious app intercepts the data intended for Bitwarden.
*Impact:* Data leakage, injection of malicious data, or hijacking of Bitwarden's functionality.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **(Developer):** Use secure IPC mechanisms provided by the platform. Validate *all* data received from other apps or components. Implement proper access controls and permissions. Use signed Intents (Android) where appropriate. Avoid exporting components unnecessarily. Use explicit Intents (Android).

## Attack Surface: [Biometric Authentication Bypass](./attack_surfaces/biometric_authentication_bypass.md)

*Description:* Circumventing the biometric authentication mechanism (fingerprint, face recognition) used to unlock the Bitwarden app.
*How Mobile Contributes:* Mobile devices are the *primary* platform for biometric authentication. Vulnerabilities in the device's biometric hardware or software, or the use of weak biometric methods, can be exploited. This is a mobile-centric risk.
*Example:* An attacker uses a spoofed fingerprint (e.g., a gummy finger) or a high-resolution photo to bypass the fingerprint or face recognition lock on the Bitwarden app.
*Impact:* Unauthorized access to the Bitwarden vault.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **(Developer):** Use platform-provided biometric APIs and follow best practices. Implement a strong fallback authentication mechanism (e.g., PIN, password). Regularly test against known spoofing techniques. Use liveness detection where available. *Never* store raw biometric data; use secure enclaves.
    *   **(User):** Use a strong fallback authentication method. Keep the device OS and Bitwarden app updated. Be aware of the limitations of biometric authentication.

## Attack Surface: [Network Attacks (MitM) on Untrusted Networks](./attack_surfaces/network_attacks__mitm__on_untrusted_networks.md)

*Description:* Interception or modification of network traffic between the Bitwarden app and the Bitwarden servers, specifically when connected to untrusted networks.
*How Mobile Contributes:* Mobile devices frequently connect to untrusted networks (e.g., public Wi-Fi, cellular networks in unfamiliar locations), significantly increasing the risk of Man-in-the-Middle (MitM) attacks compared to desktop computers that primarily use trusted home or office networks.
*Example:* An attacker on the same public Wi-Fi network uses a tool to intercept the communication between the Bitwarden app and the server, capturing the user's session token or modifying data.
*Impact:* Exposure of sensitive data, account compromise, or injection of malicious data.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **(Developer):** Use HTTPS with strong TLS configurations (TLS 1.3, strong cipher suites). Implement certificate pinning. Validate the entire certificate chain. Use HSTS. Regularly update networking libraries.
    *   **(User):** Avoid using public Wi-Fi networks for sensitive operations. Use a VPN when connecting to untrusted networks. Ensure that the Bitwarden app is configured to use HTTPS.

