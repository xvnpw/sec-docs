# Attack Surface Analysis for square/leakcanary

## Attack Surface: [Unsecured Heap Dumps](./attack_surfaces/unsecured_heap_dumps.md)

**Description:** LeakCanary generates `.hprof` files (heap dumps) when it detects memory leaks. These files contain a snapshot of the application's memory at a specific point in time.

**How LeakCanary Contributes:** LeakCanary's core functionality involves creating these heap dumps to analyze memory leaks. The library itself is responsible for generating and often storing these files.

**Example:** A malicious application with broad storage permissions could access the LeakCanary-generated `.hprof` files from the device's storage. These files might contain sensitive user data, API keys, or internal application secrets held in memory at the time of the dump.

**Impact:** Confidentiality breach, exposure of sensitive user data, potential compromise of API keys leading to unauthorized access to backend services, exposure of internal application secrets aiding further attacks.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Developers:**
    *   Ensure heap dump files are stored with appropriate permissions (e.g., `MODE_PRIVATE`) and are not world-readable or accessible to other applications.
    *   Consider storing heap dumps in application-specific private storage directories.
    *   Implement secure deletion of heap dump files after analysis or after a reasonable timeframe.
    *   Avoid logging or storing sensitive data in memory unnecessarily.
    *   If possible, encrypt heap dump files at rest.
*   **Users:**
    *   Be cautious about granting excessive storage permissions to applications.
    *   Regularly review application permissions on your device.

