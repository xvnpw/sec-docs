# Attack Surface Analysis for square/leakcanary

## Attack Surface: [Information Disclosure via Heap Dumps](./attack_surfaces/information_disclosure_via_heap_dumps.md)

**Description:** Unauthorized access and extraction of sensitive information from heap dump files generated by LeakCanary.
*   **LeakCanary Contribution:** LeakCanary automatically creates `.hprof` heap dump files when memory leaks are detected and stores them on the device's file system. These files contain a snapshot of the application's memory, potentially including sensitive data.
*   **Example:** An attacker gains adb access to a debug build of the application (e.g., through a compromised development machine or insecure debug build distribution). They use `adb pull` to download `.hprof` files from the device's storage. Analyzing these heap dumps reveals user credentials, API keys, or personal data stored in memory by the application.
*   **Impact:** Critical confidentiality breach, leading to exposure of highly sensitive user data, application secrets, and potential intellectual property. This can enable further attacks like account takeover, data breaches, and service disruption.
*   **Risk Severity:** **High** (in debug builds if accessible).
*   **Mitigation Strategies:**
    *   **Disable LeakCanary in Release Builds:**  **Crucially**, ensure LeakCanary dependencies are configured to be included *only* in debug build variants using build configuration (e.g., `debugImplementation`). This prevents heap dump generation in production environments.
    *   **Secure Debug Builds & Development Environments:**  Restrict access to debug builds and development environments. Avoid distributing debug builds outside of trusted development teams. Implement strong access controls and security practices for development machines to prevent unauthorized adb access.
    *   **Limit adb Access:** Secure adb access during development. Use strong device passwords and restrict physical access to development devices. Disable adb over network if not strictly necessary.
    *   **Data Minimization & Sanitization (Application Level):**  Reduce the amount of sensitive data held in memory, especially in plain text. Implement secure coding practices to minimize the risk of sensitive information ending up in heap dumps. Consider using encryption or secure storage mechanisms for sensitive data within the application itself.

