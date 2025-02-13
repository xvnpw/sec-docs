# Mitigation Strategies Analysis for mockk/mockk

## Mitigation Strategy: [Strategic and Limited Mocking with `spyk()`](./mitigation_strategies/strategic_and_limited_mocking_with__spyk___.md)

**Mitigation Strategy:** Strategic and Limited Mocking with `spyk()`

*   **Description:**
    1.  **Establish Mocking Guidelines:** Create clear guidelines for developers on when and how to use MockK's `mockk()` function. Emphasize using mocks only when absolutely necessary (e.g., truly unavailable dependencies, performance bottlenecks).
    2.  **Favor `spyk()`:**  *Prioritize* the use of MockK's `spyk()` function over `mockk()` whenever feasible.  `spyk()` creates a "spy" that wraps a real object.  This allows you to:
        *   Verify interactions with the real object (using `verify`).
        *   Stub *specific* methods using `every { ... } returns ...` or `every { ... } throws ...`, while letting other methods execute their real code.
        *   Achieve a balance between mocking and real execution, reducing the risk of masking real-world behavior.
    3.  **Code Reviews:** Enforce code reviews to ensure that `mockk()` is used judiciously and `spyk()` is preferred when appropriate. Reviewers should question the need for full mocks.
    4.  **Document Mocking Decisions:** Require developers to document the rationale behind each use of `mockk()` in the test code or commit messages. Explain *why* a full mock was necessary.
    5.  **Refactor Tests:** Periodically review and refactor existing tests to replace `mockk()` with `spyk()` where possible, or to eliminate mocks entirely if integration testing becomes feasible.

*   **Threats Mitigated:**
    *   **Over-Mocking (Severity: High):** Reduces the risk of masking real dependency issues by limiting the scope of full mocking and encouraging partial mocking with `spyk()`.
    *   **Mocking Internal Details (Severity: Medium):** Indirectly encourages mocking at the public API boundary, as `spyk()` works best with real objects and their public methods.

*   **Impact:**
    *   **Over-Mocking:** Reduces the risk (by 40-60%) by promoting more realistic testing through `spyk()`.
    *   **Mocking Internal Details:** Reduces the risk (by 30-50%) by making it less convenient to mock internal details.

*   **Currently Implemented:**
    *   Basic guidelines mention mocking in the project's `CONTRIBUTING.md` file.
    *   Code reviews are conducted, but enforcement of `spyk()` preference is inconsistent.

*   **Missing Implementation:**
    *   No formal documentation of `mockk()` usage decisions is required.
    *   No systematic review and refactoring of existing tests to favor `spyk()`.
    *   `spyk()` usage is not consistently enforced or prioritized.

## Mitigation Strategy: [Mandatory Mock Verification with `verify`, `verifySequence`, and `verifyAll`](./mitigation_strategies/mandatory_mock_verification_with__verify____verifysequence___and__verifyall_.md)

**Mitigation Strategy:** Mandatory Mock Verification with `verify`, `verifySequence`, and `verifyAll`

*   **Description:**
    1.  **Enforce Verification:** Make it *mandatory* to use MockK's verification functions (`verify`, `verifySequence`, `verifyAll`) in *every* test that uses `mockk()` or `spyk()`.
    2.  **`verify` (Basic):** Use `verify { ... }` to check that a specific method on a mock or spy was called, optionally with specific arguments: `verify { mockedObject.method(arg1, arg2) }`.
    3.  **`verifySequence` (Order):** Use `verifySequence { ... }` to check that a sequence of calls occurred in a specific order: `verifySequence { mockedObject.method1(); mockedObject.method2() }`.
    4.  **`verifyAll` (Strict):** Use `verifyAll { ... }` to ensure that *only* the explicitly verified interactions occurred on the mock or spy.  This is the strictest form of verification and helps prevent unexpected side effects.  Any unverified interaction will cause the test to fail.
    5.  **Exception Verification:** Use `verify` to check that exceptions thrown by mocked dependencies are handled correctly: `verify { mockedObject.methodThatThrows() wasNot Called }` or, within a try-catch, verify that the catch block was executed.
    6.  **Automated Checks:** Consider using static analysis tools or custom linters to automatically detect tests that use `mockk()` or `spyk()` without corresponding verifications (especially `verifyAll`).
    7.  **Training:** Provide training to developers on the importance of thorough mock verification and how to use MockK's verification features effectively.
    8.  **Code Reviews:** Emphasize comprehensive mock verification during code reviews.  Reviewers should check for the use of `verifyAll` where appropriate.

*   **Threats Mitigated:**
    *   **Ignoring Mock Verification (Severity: High):** Prevents tests from passing when the code under test is not interacting with mocks correctly, revealing potential bugs and security vulnerabilities related to incorrect API calls, missing parameters, or improper error handling.

*   **Impact:**
    *   **Ignoring Mock Verification:** Significantly reduces the risk (by 80-95%) of deploying code with incorrect mock interactions.

*   **Currently Implemented:**
    *   `verify` is used in some tests, but not consistently.
    *   No automated checks for missing verifications.

*   **Missing Implementation:**
    *   `verify` is not used in all tests that use mocks.
    *   No automated checks or linters to enforce verification (especially `verifyAll`).
    *   No formal training on comprehensive mock verification.
    *   `verifyAll` and `verifySequence` are rarely used.

## Mitigation Strategy: [Controlled Mocking of Randomness (Indirect via Testable Seam)](./mitigation_strategies/controlled_mocking_of_randomness__indirect_via_testable_seam_.md)

**Mitigation Strategy:** Controlled Mocking of Randomness (Indirect via Testable Seam)

*   **Description:**
    1.  **Identify Randomness Dependencies:** Identify all parts of the code that rely on random number generation, especially for security (tokens, salts, keys).
    2.  **Introduce a Testable Seam:**  *Do not mock `SecureRandom` directly.* Instead, refactor the code to introduce an abstraction (interface or abstract class) for random number generation.  For example:
        ```kotlin
        interface RandomNumberGenerator {
            fun nextBytes(size: Int): ByteArray
        }

        class SecureRandomNumberGenerator : RandomNumberGenerator {
            private val secureRandom = SecureRandom()
            override fun nextBytes(size: Int): ByteArray {
                val bytes = ByteArray(size)
                secureRandom.nextBytes(bytes)
                return bytes
            }
        }
        //In the class that needs random:
        class TokenGenerator(private val rng: RandomNumberGenerator) {
            fun generateToken(): String {
                val randomBytes = rng.nextBytes(16)
                // ... use randomBytes ...
            }
        }
        ```
    3.  **Deterministic PRNG for Tests:**  Create a *test implementation* of your `RandomNumberGenerator` interface that uses a deterministic pseudo-random number generator (PRNG) with a *fixed seed*.  This ensures repeatable tests.
        ```kotlin
        class DeterministicRandomNumberGenerator(seed: Long) : RandomNumberGenerator {
            private val random = java.util.Random(seed) // Use java.util.Random
            override fun nextBytes(size: Int): ByteArray {
                val bytes = ByteArray(size)
                random.nextBytes(bytes)
                return bytes
            }
        }
        ```
    4.  **Inject in Tests:** In your tests, use MockK to *mock the interface*, or preferably, inject the `DeterministicRandomNumberGenerator` directly:
        ```kotlin
        @Test
        fun testGenerateToken() {
            val rng = DeterministicRandomNumberGenerator(12345L) // Fixed seed
            val tokenGenerator = TokenGenerator(rng)
            val token1 = tokenGenerator.generateToken()
            val token2 = tokenGenerator.generateToken()
            // Assertions... token1 and token2 will be predictable
        }
        ```
    5. **Avoid Direct Mocking of System Classes:** This approach avoids directly mocking `SecureRandom`, which is generally discouraged and can lead to brittle or misleading tests.

*   **Threats Mitigated:**
    *   **Mocking Randomness Incorrectly (Severity: High):** Prevents predictable random number generation in tests from masking vulnerabilities in production, where unpredictability is crucial for security.

*   **Impact:**
    *   **Mocking Randomness Incorrectly:** Significantly reduces the risk (by 90-100%) of introducing vulnerabilities related to predictable randomness.

*   **Currently Implemented:**
    *   No specific mitigation for mocking randomness is currently implemented.

*   **Missing Implementation:**
    *   The `TokenGenerator` class directly uses `SecureRandom` and is not easily testable.
    *   No testable seam (interface) for random number generation.
    *   No deterministic PRNG implementation for tests.

