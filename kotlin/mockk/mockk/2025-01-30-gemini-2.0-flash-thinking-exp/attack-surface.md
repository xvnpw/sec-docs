# Attack Surface Analysis for mockk/mockk

## Attack Surface: [1. Accidental Inclusion of Test Code in Production](./attack_surfaces/1__accidental_inclusion_of_test_code_in_production.md)

*   **Description:** Test code, including Mockk usage, inadvertently included in production builds can introduce unexpected behavior and security flaws.
*   **Mockk Contribution:** Mockk is a testing library. Its presence in production code is a strong indicator of accidental inclusion of test-related artifacts.  The functionality of Mockk itself (like intercepting calls, defining mocks) is not intended for production and can lead to unpredictable behavior if active.
*   **Example:** Test code using Mockk to bypass authentication checks for testing purposes is accidentally included in production. This could allow unauthorized access to protected resources in the production environment because the Mockk-defined mock authentication behavior is active in production.
*   **Impact:** Security bypasses, data leaks, incorrect application behavior, and potential instability in production.
*   **Risk Severity:** High to Critical (if security bypasses are introduced).
*   **Mitigation Strategies:**
    *   **Strict Build Process:** Implement a robust build process that clearly separates test and production code.
    *   **Source Set Management:** Utilize build tools (like Gradle or Maven) to define and enforce source sets, ensuring only production source sets are included in production builds.
    *   **Static Analysis:** Employ static analysis tools to detect and flag test-specific annotations or code patterns (including Mockk usage) in production code.
    *   **Code Reviews:** Conduct code reviews to identify and prevent accidental inclusion of test code in production.

## Attack Surface: [2. Over-Permissive Mocking in Security-Sensitive Contexts](./attack_surfaces/2__over-permissive_mocking_in_security-sensitive_contexts.md)

*   **Description:** Mocking security-critical components too permissively during testing can lead to inadequate security testing and masked vulnerabilities.
*   **Mockk Contribution:** Mockk provides the mechanism to create mocks for any component, including security-related ones.  The ease of use of Mockk can inadvertently lead developers to create overly simplistic or permissive mocks for security checks, hindering effective security testing.
*   **Example:** Mocking an authorization service with Mockk to always return "success" in tests. This might mask vulnerabilities in the actual authorization logic, as tests will always pass regardless of the real authorization implementation flaws.  Developers might incorrectly assume the system is secure based on these passing tests.
*   **Impact:**  False sense of security, undetected vulnerabilities in security mechanisms, potential security breaches in production when real security measures are bypassed due to flaws not caught by testing.
*   **Risk Severity:** High to Critical (depending on the criticality of the mocked security component).
*   **Mitigation Strategies:**
    *   **Realistic Mocks:** Design mocks for security components to accurately reflect real-world security constraints and behaviors, including failure scenarios and edge cases.
    *   **Negative Security Tests:** Use mocks to explicitly test negative security scenarios (e.g., authentication failures, authorization denials) to ensure security mechanisms are robust.
    *   **Integration Tests:** Prioritize integration tests with real security components for critical security paths to complement unit tests with mocks and validate end-to-end security.
    *   **Security Code Reviews:** Specifically review mocking strategies for security-sensitive components during code reviews to ensure they are comprehensive and not overly permissive.

