# Mitigation Strategies Analysis for square/leakcanary

## Mitigation Strategy: [Disable LeakCanary in Production](./mitigation_strategies/disable_leakcanary_in_production.md)

**1. Mitigation Strategy: Disable LeakCanary in Production**

*   **Description:**
    1.  **Identify Build Variants:** Ensure your project uses Gradle build variants (typically `debug` and `release`).
    2.  **Conditional Dependency:** Modify your app's `build.gradle` file. Use `debugImplementation` for the full LeakCanary library and `releaseImplementation` for the no-op artifact:

        ```gradle
        dependencies {
            debugImplementation 'com.squareup.leakcanary:leakcanary-android:2.12' // Use the latest version
            releaseImplementation 'com.squareup.leakcanary:leakcanary-android-no-op:2.12' // Use the same version
        }
        ```
    3.  **Build Release APK/AAB:** When building for release (e.g., `gradlew assembleRelease`), the no-op artifact will be included, effectively disabling LeakCanary.
    4.  **Verification:** After building a release version, confirm LeakCanary classes are *not* present in the APK/AAB.

*   **List of Threats Mitigated:**
    *   **Sensitive Data Exposure in Heap Dumps (Severity: Critical):** Prevents heap dumps on user devices.
    *   **Denial of Service (DoS) due to Heap Analysis (Severity: High):** Eliminates heap analysis in production.
    *   **Information Disclosure via Notifications/Logs (Severity: Medium):** Prevents LeakCanary output in production.
    *   **Code Injection (related to LeakCanary manipulation) (Severity: Low):** Removes a potential manipulation target.

*   **Impact:**
    *   **Sensitive Data Exposure:** Risk reduced to near zero.
    *   **Denial of Service:** Risk reduced to near zero.
    *   **Information Disclosure:** Risk reduced to near zero.
    *   **Code Injection (related):** Minor reduction in attack surface.

*   **Currently Implemented:**
    *   **Yes/No:** (Specify).
    *   **Location:** `app/build.gradle` (Specify the exact file path).

*   **Missing Implementation:**
    *   If **No**: The `build.gradle` file needs modification; release builds include the full library.
    *   If **Yes**: None.

## Mitigation Strategy: [Custom Display and Logging (Development/Testing)](./mitigation_strategies/custom_display_and_logging__developmenttesting_.md)

**2. Mitigation Strategy: Custom Display and Logging (Development/Testing)**

*   **Description:**
    1.  **Custom `DisplayLeakService`:** Create a custom class extending `leakcanary.DisplayLeakService`.
    2.  **Override `onLeakDetected`:** Override the `onLeakDetected` method.
    3.  **Control Output:** Within the overridden method:
        *   Send information to a secure logging system.
        *   Filter/redact sensitive information before logging.
        *   Suppress on-screen notifications.
        *   Implement custom alerting.
    4.  **Register the Service:** Register your custom `DisplayLeakService` in your application's manifest:

        ```xml
        <service
            android:name=".MyCustomDisplayLeakService"
            android:enabled="true"
            android:exported="false" />
        ```
    5.  **Conditional Enablement:** Ensure the service is only enabled in debug builds.

*   **List of Threats Mitigated:**
    *   **Information Disclosure via Notifications/Logs (Severity: Medium):** Controls how leak information is displayed/logged.

*   **Impact:**
    *   **Information Disclosure:** Reduces risk; effectiveness depends on implementation.

*   **Currently Implemented:**
    *   **Yes/No:** (Specify).
    *   **Location:** (Specify the custom `DisplayLeakService` class name and location).

*   **Missing Implementation:**
    *   If **No**: A custom `DisplayLeakService` needs creation; default notifications/logs are used.
    *   If **Yes**: Review implementation for adequate filtering/redaction.

## Mitigation Strategy: [Heap Dump Filtering (Advanced/Custom - Discouraged)](./mitigation_strategies/heap_dump_filtering__advancedcustom_-_discouraged_.md)

**3. Mitigation Strategy:  Heap Dump Filtering (Advanced/Custom - Discouraged)**

*   **Description:**
    1.  **Custom `OnHeapAnalyzedListener`:**  Create a custom class that implements `leakcanary.OnHeapAnalyzedListener`.
    2.  **Intercept Heap Dump:**  In the `onHeapAnalyzed` method, you receive the `HeapAnalysis` object, which contains information about the heap dump *before* it's saved.
    3.  **Filtering/Redaction (Extremely Complex):**  You would need to:
        *   Understand the internal structure of the `HeapAnalysis` object and the underlying heap dump format (HPROF).
        *   Develop logic to identify and remove or redact sensitive data within the heap dump representation.  This is *highly* error-prone and requires deep expertise.
        *   Modify the `HeapAnalysis` object (if possible) or create a new, filtered version.
    4.  **Proceed with Analysis (or Not):**  You can then decide whether to proceed with the default LeakCanary analysis using the modified data or to abort the analysis.
    5. **Register Listener:** Use `LeakCanary.config = LeakCanary.config.copy(onHeapAnalyzedListener = MyCustomOnHeapAnalyzedListener())` to register your custom listener.  Do this early in your application's lifecycle (e.g., in your `Application` class).  Ensure this is only done in debug builds.

*   **List of Threats Mitigated:**
    *   **Sensitive Data Exposure in Heap Dumps (Severity: High - during development/testing):** *Potentially* reduces the risk by attempting to remove sensitive data from heap dumps *before* they are written to storage.  However, this is a very fragile mitigation.

*   **Impact:**
    *   **Sensitive Data Exposure:**  *Potentially* reduces risk, but with a *high* chance of failure or accidental data leakage.  This is *not* a reliable mitigation.

*   **Currently Implemented:**
    *   **Yes/No:** (Specify).  It's highly likely this is **No**.
    *   **Location:** (If implemented, specify the class name of the custom `OnHeapAnalyzedListener` and its location).

*   **Missing Implementation:**
    *   If **No**:  This complex and risky mitigation is not implemented.  This is the recommended state.
    *   If **Yes**:  Thoroughly review the implementation for correctness and security.  Consider removing this mitigation in favor of the simpler and more reliable approach of disabling LeakCanary in production and securely handling heap dumps during development.

**Important Note:**  The "Heap Dump Filtering" strategy is strongly discouraged due to its complexity and high risk of error.  The other two strategies (disabling in production and custom display/logging) are the recommended and much safer approaches. This third strategy is included for completeness, but with a strong warning against its use.

