# Threat Model Analysis for bitwarden/mobile

## Threat: [Malware on the Device (Credential Stealing)](./threats/malware_on_the_device__credential_stealing_.md)

**Description:** Malicious software on the user's device exploits vulnerabilities within the Bitwarden mobile application's input handling or memory management to capture the user's master password as it's entered. This could involve techniques like monitoring the input field or accessing sensitive data in memory.

**Impact:** Complete compromise of the user's Bitwarden vault and all stored credentials.

**Affected Component:**
*   Master Password Input Field (within the UI module)
*   Memory Management (how the application handles sensitive data in memory)

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Developers:**
    *   Implement robust input field protection techniques to prevent eavesdropping and injection.
    *   Employ memory protection mechanisms to hinder malware from accessing sensitive data in memory.
    *   Regularly audit and update dependencies to patch known vulnerabilities that malware could exploit.

## Threat: [Insecure Local Storage Exploitation](./threats/insecure_local_storage_exploitation.md)

**Description:** Attackers leverage weaknesses in the Bitwarden mobile application's local data storage implementation. This could involve vulnerabilities in the encryption algorithms used, the key management process, or insecure file permissions, allowing an attacker with local device access (potentially through other vulnerabilities) to decrypt and access the stored vault data.

**Impact:** Compromise of the encrypted vault and its contents, exposing all stored credentials.

**Affected Component:**
*   Local Vault Storage Module (responsible for storing and retrieving the encrypted vault)
*   Encryption Implementation (the specific algorithms and methods used for encryption and decryption)
*   Key Management (how encryption keys are generated, stored, and accessed)

**Risk Severity:** High

**Mitigation Strategies:**
*   **Developers:**
    *   Utilize strong, industry-standard, and well-vetted encryption algorithms for local vault storage.
    *   Implement secure key management practices, ensuring keys are not stored insecurely on the device.
    *   Adhere to platform-specific best practices for secure data storage and file permissions.
    *   Regularly review and audit the local storage implementation for potential vulnerabilities.

## Threat: [Screen Overlay Attack (Master Password Capture)](./threats/screen_overlay_attack__master_password_capture_.md)

**Description:** A malicious application displays a deceptive overlay on top of the Bitwarden mobile application's login screen. This overlay mimics the legitimate login interface, tricking the user into entering their master password, which is then captured by the malicious application due to the Bitwarden app not effectively preventing such overlays from capturing input.

**Impact:** Complete compromise of the user's Bitwarden vault and all stored credentials.

**Affected Component:**
*   Master Password Input Field (within the UI module)
*   Application Login Screen UI (the visual elements of the login screen)
*   UI Rendering Logic (how the application draws its interface and handles input events)

**Risk Severity:** High

**Mitigation Strategies:**
*   **Developers:**
    *   Implement measures to detect and prevent screen overlay attacks by utilizing platform APIs designed for this purpose.
    *   Employ techniques to make the login screen more resistant to overlay attacks (e.g., using system-drawn elements where possible).
    *   Educate users within the application about the risks of screen overlay attacks and how to identify them.

