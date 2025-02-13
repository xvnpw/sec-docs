# Threat Model Analysis for square/leakcanary

## Threat: [Threat 1: Production Release Exposure](./threats/threat_1_production_release_exposure.md)

*   **Description:** An attacker gains access to a publicly released version of the application that inadvertently includes the full LeakCanary library (not the `no-op` version). The attacker can then use standard Android reverse engineering tools (like `apktool`, `dex2jar`, `JD-GUI`) to inspect the APK, confirm LeakCanary's presence, and then run the application on a device or emulator. They can interact with the application normally, triggering various features and workflows. LeakCanary will automatically generate heap dumps and analyze them, storing the results locally. The attacker can then access these heap dumps (typically stored in the app's private storage) using `adb` (Android Debug Bridge) or by rooting the device.
    *   **Impact:**
        *   Exposure of sensitive data present in the heap dumps, including user data, API keys, session tokens, and internal application state.
        *   Significant performance degradation for all users of the production application.
        *   Potential application crashes due to excessive memory usage and analysis overhead.
        *   Reputational damage to the application developer.
    *   **Affected LeakCanary Component:** Entire library (`leakcanary-android`), specifically the heap dumping (`HeapDumper`), analysis (`HeapAnalyzerService`), and reporting (`DisplayLeakActivity`, notification system) components.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use the `leakcanary-android-no-op` artifact for all release builds. This replaces the full LeakCanary implementation with empty stubs, preventing any functionality from executing.
        *   Implement automated build checks (e.g., in CI/CD pipelines) to verify that only the `no-op` artifact is included in release builds.  These checks should fail the build if the full LeakCanary library is detected.
        *   Conduct code reviews to ensure that LeakCanary initialization is conditional and only occurs within debug build configurations.
        *   Use ProGuard/R8 to obfuscate and shrink the code, making it *slightly* harder to reverse engineer, but this is *not* a primary mitigation.

## Threat: [Threat 2: Debug Build Exploitation](./threats/threat_2_debug_build_exploitation.md)

*   **Description:** An attacker obtains a debug build of the application (e.g., through a leaked APK, a compromised developer device, or social engineering). They install the debug build on their own device or emulator. They then interact with the application, triggering various features and potentially manipulating the application's state to induce specific memory leaks.  They can use `adb` to monitor LeakCanary's output (logcat) and access the generated heap dumps from the app's private storage.  They can then analyze these heap dumps using tools like Eclipse Memory Analyzer (MAT) or Android Studio's profiler to extract sensitive information.
    *   **Impact:**
        *   Exposure of sensitive data present in the heap dumps, similar to Threat 1, but limited to the data present during the attacker's interaction with the debug build.
        *   Potential for the attacker to gain a deeper understanding of the application's internal workings by analyzing the memory leaks and object relationships.
    *   **Affected LeakCanary Component:** Entire library (`leakcanary-android`), specifically the heap dumping (`HeapDumper`), analysis (`HeapAnalyzerService`), and reporting (`DisplayLeakActivity`, notification system) components.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Strictly control access to debug builds.  Limit distribution to authorized developers only.
        *   Enforce strong security measures on developer devices (passwords, biometrics, full disk encryption).
        *   Use code signing for debug builds to prevent unauthorized modifications.
        *   Consider implementing emulator detection to prevent the debug build from running on unauthorized emulators.
        *   Minimize the amount of sensitive data stored in memory, even in debug builds. Use secure storage mechanisms (e.g., Android Keystore) whenever possible.

