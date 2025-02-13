# Attack Surface Analysis for jetbrains/compose-multiplatform

## Attack Surface: [Shared Code Vulnerabilities (Amplified Impact)](./attack_surfaces/shared_code_vulnerabilities__amplified_impact_.md)

*   **Description:**  Flaws in the code shared across all platforms (`commonMain`).  The *amplified impact* is the key Compose Multiplatform-specific aspect.
*   **Compose Multiplatform Contribution:**  Code sharing is the core of Compose Multiplatform.  A single vulnerability affects *all* target platforms (Android, iOS, Desktop, Web), making this a significantly higher risk than platform-specific vulnerabilities.
*   **Example:**  A flawed authentication bypass in the shared logic would allow unauthorized access on *all* platforms.  A data validation error could lead to data corruption across *all* platforms.
*   **Impact:**  Compromise of application data, functionality, and user accounts across *all* platforms.  Data breaches, unauthorized access, denial of service.
*   **Risk Severity:**  Critical (if affecting authentication, authorization, or critical data) / High (for most other shared logic flaws).
*   **Mitigation Strategies:**
    *   **Rigorous Code Review (Multiplatform Focus):**  Multiple reviewers, each with expertise in different platform security, must review the shared code.
    *   **Centralized, Robust Input Validation:**  Assume *all* input is malicious.  Implement strong input validation and output encoding in the shared code.
    *   **Secure Dependency Management (Shared Dependencies):**  Use dependency scanning tools (e.g., OWASP Dependency-Check, Snyk) and regularly audit shared dependencies.
    *   **Static Analysis (Multiplatform Configuration):**  Configure static analysis tools to specifically target Kotlin Multiplatform code and common vulnerabilities.
    *   **Fuzz Testing (Shared Code):**  Apply fuzzing to the shared code to uncover edge cases and unexpected vulnerabilities.
    *   **Comprehensive Unit/Integration Tests (Security-Focused):**  Include security-specific test cases in the shared code's test suite.

## Attack Surface: [Inconsistent `expect`/`actual` Implementations](./attack_surfaces/inconsistent__expect__actual__implementations.md)

*   **Description:**  Security-relevant differences in behavior between platform-specific implementations (`actual`) of a shared interface (`expect`).
*   **Compose Multiplatform Contribution:**  The `expect`/`actual` mechanism is *fundamental* to Compose Multiplatform's platform abstraction.  Inconsistencies create *platform-specific* vulnerabilities that bypass the shared code's intended security.
*   **Example:**  An `expect` function for secure storage might have an `actual` implementation on Android that uses encrypted SharedPreferences, but the iOS `actual` implementation might mistakenly use unencrypted UserDefaults, leading to data leakage on iOS.
*   **Impact:**  Platform-specific vulnerabilities that circumvent the shared code's security controls.  Privilege escalation, data leaks, or other platform-specific exploits.
*   **Risk Severity:**  High (potential for significant platform-specific compromise, bypassing shared security).
*   **Mitigation Strategies:**
    *   **Precise `expect` Interface Definition:**  The `expect` declaration must *explicitly* define all security requirements and expected behavior.
    *   **Cross-Platform Code Review:**  Reviewers must compare `actual` implementations side-by-side, looking for *any* behavioral differences, not just functional ones.
    *   **Platform-Specific Security Tests:**  Create *separate* test suites for *each* `actual` implementation, verifying its security behavior against the `expect` definition.
    *   **Documentation of Security Assumptions:** Clearly document all security-related assumptions and requirements for each `actual` implementation.

## Attack Surface: [Unsafe Native Interoperability (Through Shared or `actual` Code)](./attack_surfaces/unsafe_native_interoperability__through_shared_or__actual__code_.md)

*   **Description:**  Vulnerabilities arising from interactions between Kotlin code (either shared or in `actual` implementations) and native code (C/C++, Objective-C, Swift, etc.).
*   **Compose Multiplatform Contribution:**  Compose Multiplatform uses Kotlin/Native for interoperability with platform-specific APIs and libraries.  This *necessitates* native interop, introducing the inherent risks.
*   **Example:**  A shared Kotlin function uses Kotlin/Native to call a C library for cryptographic operations.  If the C library has a vulnerability (e.g., a buffer overflow), it can be triggered through the shared Kotlin code, affecting *all* platforms.  Alternatively, an `actual` implementation might use a vulnerable native library specific to that platform.
*   **Impact:**  Memory corruption, arbitrary code execution, denial of service, and other classic native code vulnerabilities.  Potential for complete system compromise.
*   **Risk Severity:**  Critical / High (depending on the nature and extent of the native interaction).
*   **Mitigation Strategies:**
    *   **Minimize Native Interop:**  Prefer platform-specific Kotlin APIs whenever possible to *reduce* the reliance on native code.
    *   **Memory Safety (Kotlin/Native):**  Use Kotlin's memory management features meticulously when interacting with native code.  Avoid manual memory management in Kotlin/Native if at all possible.
    *   **Secure Coding Practices (Native Code):**  If writing native code, adhere strictly to secure coding guidelines for the chosen language (e.g., C/C++).  Consider memory-safe languages (e.g., Rust) where feasible.
    *   **Auditing of Native Libraries:**  Thoroughly vet *all* third-party native libraries used (both shared and platform-specific) for security vulnerabilities.
    *   **Input Validation (Before Native Calls):**  Rigorously validate *all* data passed to native code from Kotlin.
    * **Sandboxing**: If possible, sandbox native code.

## Attack Surface: [Compose Runtime Exploits](./attack_surfaces/compose_runtime_exploits.md)

*   **Description:** Vulnerabilities within the Compose runtime library itself.
*   **Compose Multiplatform Contribution:** Compose Multiplatform uses a custom runtime, which is a direct attack vector.
*   **Example:** A hypothetical vulnerability in state management could allow UI manipulation or data leaks. A DoS could be triggered by forcing excessive recomposition.
*   **Impact:** UI manipulation, data leaks, DoS, potentially arbitrary code execution (in severe, unlikely cases).
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Keep Compose Updated:** This is the *primary* mitigation. Regularly update to the latest Compose Multiplatform version to get security patches.
    *   **Monitor Security Advisories:** Subscribe to JetBrains' security advisories for Compose.
    *   **Avoid Excessive Complexity:** While not a complete solution, limiting extremely complex UI interactions can reduce the attack surface within the runtime.

## Attack Surface: [Deserialization issues in shared code](./attack_surfaces/deserialization_issues_in_shared_code.md)

*   **Description:** Vulnerabilities arising from deserialization of untrusted data in shared code.
*   **Compose Multiplatform Contribution:** If shared code is using kotlinx.serialization, there is a risk of Deserialization vulnerabilities.
*   **Example:** Application is using kotlinx.serialization to deserialize data from untrusted source. Attacker can send malicious data that will be deserialized and executed.
*   **Impact:** Arbitrary code execution.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Avoid deserialization of untrusted data:** If possible, avoid deserialization of untrusted data.
    *   **Use allow lists:** If deserialization of untrusted data is necessary, use allow lists to restrict which classes can be deserialized.
    *   **Validate data after deserialization:** Validate data after deserialization to ensure that it is valid.
    *   **Use secure deserialization libraries:** Use secure deserialization libraries that are not vulnerable to deserialization attacks.

