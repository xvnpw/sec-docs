# Mitigation Strategies Analysis for facebook/folly

## Mitigation Strategy: [Runtime Folly Version Checks](./mitigation_strategies/runtime_folly_version_checks.md)

*   **Description:**
    1.  **Include Folly Version Headers:** Ensure that the necessary Folly headers providing version information are included (e.g., `#include <folly/lang/Version.h>`).
    2.  **Define Expected Version:**  Define constants or variables representing the expected major, minor, and patch version of Folly (matching the pinned version in your build system).
    3.  **Check Version at Startup:**  In your application's initialization code (e.g., `main()` function or a dedicated initialization module), add code to retrieve the runtime Folly version using the provided macros (e.g., `FOLLY_VERSION_MAJOR`, `FOLLY_VERSION_MINOR`, `FOLLY_VERSION_PATCH`).
    4.  **Compare Versions:** Compare the retrieved runtime version components with the expected version components.
    5.  **Handle Mismatches:** If any of the version components do not match, log a critical error message (including both the expected and actual versions).  Depending on the application's requirements, either:
        *   Terminate the application gracefully.
        *   Enter a restricted, safe mode of operation.
        *   Attempt to load a specific, known-good version of Folly (advanced, and potentially complex).

*   **Threats Mitigated:**
    *   **ABI Incompatibility (Severity: Medium):** Prevents the application from running with an incompatible Folly version, even if dynamic linking somehow loads the wrong version.  This is *specific* to Folly because Folly's ABI can change between versions.
    *   **Unexpected Behavior due to Version Mismatch (Severity: Medium):**  Catches situations where a different Folly version is loaded than expected, which could lead to subtle bugs or vulnerabilities *specific to Folly's implementation*.

*   **Impact:**
    *   **ABI Incompatibility:** Risk significantly reduced. The application will not proceed if an incompatible version is detected.
    *   **Unexpected Behavior:** Risk reduced.  Version mismatches are detected early, preventing potential issues.

*   **Currently Implemented:**
    *   Not implemented.

*   **Missing Implementation:**
    *   Version check logic needs to be added to the application's initialization code.
    *   Appropriate error handling (logging and graceful termination/safe mode) needs to be implemented.

## Mitigation Strategy: [Concurrency Safety with Thread Sanitizer and Code Reviews (Folly-Specific Focus)](./mitigation_strategies/concurrency_safety_with_thread_sanitizer_and_code_reviews__folly-specific_focus_.md)

*   **Description:**
    1.  **Enable Thread Sanitizer (TSan):** Configure your build system to enable Thread Sanitizer during testing.
    2.  **Run Tests with TSan (Folly Focus):**  Run tests, *specifically focusing on code that uses Folly's concurrency primitives* (e.g., `folly::futures`, `folly::Executor`, `folly::ThreadLocal`, `folly::MPMCQueue`, etc.).
    3.  **Address TSan Reports:**  Investigate and fix any data races or other threading errors reported by TSan.
    4.  **Concurrency-Focused Code Reviews (Folly Focus):**  Code reviews should *explicitly examine the correct usage of Folly's concurrency APIs*. This includes:
        *   Understanding the threading model of `folly::futures` and continuations (which thread a continuation runs on).
        *   Checking for proper synchronization when using shared resources with Folly's executors.
        *   Verifying the correct use of `folly::ThreadLocal` to avoid unintended data sharing.
        *   Ensuring thread-safe use of Folly's concurrent data structures (e.g., `MPMCQueue`).
    5.  **Minimize Shared Mutable State (with Folly in Mind):** Design your code to minimize shared mutable state, *especially when interacting with Folly's concurrency features*.
    6.  **Use Higher-Level Folly Abstractions:**  Prefer Folly's higher-level concurrency abstractions (e.g., `folly::collect`, `folly::via`) over manual thread management or lower-level Folly primitives.
    7. **Avoid blocking operations in folly thread pools:** If you are using folly thread pools, avoid blocking operations, as they can lead to thread starvation.

*   **Threats Mitigated:**
    *   **Data Races (in Folly-based code) (Severity: High):** TSan directly detects data races, which are common pitfalls when using Folly's concurrency features incorrectly.
    *   **Deadlocks (involving Folly components) (Severity: High):** Code reviews and careful design, specifically considering Folly's threading model, can help prevent deadlocks.
    *   **Folly-Specific Concurrency Bugs (Severity: Medium to High):**  Incorrect use of Folly's concurrency APIs can lead to subtle bugs that are specific to Folly's implementation.

*   **Impact:**
    *   **Data Races:** Risk significantly reduced due to TSan.
    *   **Deadlocks:** Risk reduced through careful design and code reviews.
    *   **Folly-Specific Concurrency Bugs:** Risk reduced through focused code reviews and adherence to Folly's documentation.

*   **Currently Implemented:**
    *   TSan is enabled for unit tests.
    *   Basic code reviews are performed.

*   **Missing Implementation:**
    *   Formalized concurrency-focused code review process *specifically targeting Folly usage*.
    *   Training for developers on safe concurrency practices *with Folly*.

## Mitigation Strategy: [Memory Safety with `StringPiece` and `IOBuf` Best Practices](./mitigation_strategies/memory_safety_with__stringpiece__and__iobuf__best_practices.md)

*   **Description:**
    1.  **`StringPiece` Lifetime Management:**
        *   **Explicitly Document Lifetimes:**  Clearly document the lifetime of the data underlying any `folly::StringPiece`.
        *   **Avoid Long-Lived `StringPiece`:**  Minimize the scope and lifetime of `StringPiece` instances.
        *   **Prefer Owning Types:**  Use `std::string` or `folly::fbstring` when ownership is required. This is crucial because `StringPiece` is *non-owning*.
    2.  **`IOBuf` Chain Management:**
        *   **Use `IOBuf::takeOwnership()` and `IOBuf::release()`:**  Explicitly manage the ownership of `IOBuf` chains to prevent memory leaks or double-frees. This is *specific to the `IOBuf` API*.
        *   **Avoid Manual Chain Manipulation:**  Use Folly's provided methods for manipulating `IOBuf` chains.
        *   **Clear Chains After Use:** Ensure `IOBuf` chains are properly released.
    3. **Fuzz Testing (Folly Focus):** Develop fuzz tests specifically targeting code that uses `folly::StringPiece`, `folly::IOBuf`, and other Folly memory management utilities.

*   **Threats Mitigated:**
    *   **Dangling Pointers (due to `StringPiece` misuse) (Severity: High):**  Incorrect `StringPiece` usage is a common source of dangling pointers.
    *   **Memory Leaks/Double-Frees (due to `IOBuf` misuse) (Severity: High):**  Improper `IOBuf` chain management can lead to memory corruption.
    *   **Folly-Specific Memory Errors (Severity: High):**  Bugs in Folly's memory management utilities (though rare) could be exposed through fuzz testing.

*   **Impact:**
    *   **Dangling Pointers, Memory Leaks/Double-Frees:** Risk reduced through careful coding practices and adherence to Folly's guidelines.
    *   **Folly-Specific Memory Errors:** Risk reduced through fuzz testing.

*   **Currently Implemented:**
    *   Some basic guidelines for `StringPiece` usage are documented.

*   **Missing Implementation:**
    *   Comprehensive fuzz testing of code using `StringPiece` and `IOBuf`.
    *   More rigorous enforcement of `StringPiece` and `IOBuf` best practices during code reviews.
    *   Refactoring of some existing code to improve `StringPiece` lifetime management.

## Mitigation Strategy: [Secure Handling of `folly::dynamic`](./mitigation_strategies/secure_handling_of__follydynamic_.md)

*   **Description:**
    1.  **Schema Validation (for External Data):**
        *   **Define Schema:**  Create a formal schema (e.g., JSON Schema) for external data processed using `folly::dynamic`.
        *   **Validate Input:**  Use a schema validation library to verify that data conforms to the schema *before* using it with `folly::dynamic`.
    2.  **Type Checking (within `folly::dynamic`):**
        *   **Always Check Types:**  Before accessing any value within a `folly::dynamic` object, use `isString()`, `isInt()`, `isObject()`, etc. This is *crucial* when working with `folly::dynamic` because it's dynamically typed.
        *   **Handle Type Mismatches:**  Handle cases where the data is not of the expected type gracefully.
    3.  **Limit Use with Untrusted Data:**  Restrict the use of `folly::dynamic` with untrusted data as much as possible.
    4. **Avoid Deep Nesting:** Keep the structure of dynamic objects as flat as possible. If deep nesting is unavoidable, ensure that validation is performed at each level.

*   **Threats Mitigated:**
    *   **Type Confusion Vulnerabilities (in `folly::dynamic` usage) (Severity: High):**  Strict type checking and schema validation are essential to prevent type confusion when using `folly::dynamic`.
    *   **Unexpected Input Handling (with `folly::dynamic`) (Severity: Medium):** Schema validation ensures that the application only processes data in the expected format when using `folly::dynamic`.

*   **Impact:**
    *   **Type Confusion Vulnerabilities:** Risk significantly reduced.
    *   **Unexpected Input Handling:** Risk reduced.

*   **Currently Implemented:**
    *   Basic type checking is performed.

*   **Missing Implementation:**
    *   Formal schema validation.
    *   More comprehensive error handling for type mismatches.

## Mitigation Strategy: [Robust Exception Handling (Folly-Specific Considerations)](./mitigation_strategies/robust_exception_handling__folly-specific_considerations_.md)

*   **Description:**
    1.  **Identify Folly Usage:** Identify all code that directly or indirectly uses Folly.
    2.  **Specific Folly Exception Handling:** Catch specific Folly exception types (e.g., `folly::AsyncSocketException`, `folly::FutureException`, exceptions from `folly::dynamic`). This is important because Folly throws its own exception types.
    3.  **General Exception Handling:** Include a `catch (...)` block.
    4.  **Logging:** Log all caught exceptions.
    5.  **Graceful Degradation/Termination:** Handle exceptions appropriately.
    6.  **Consider `folly::Try`:** Explore using `folly::Try` as an alternative to exceptions, *especially in code interacting with Folly's asynchronous operations*. This is a Folly-specific alternative to exception handling.
    7. **Review exception safety:** Ensure that resources are properly released and data structures are left in a consistent state when exceptions are thrown.

*   **Threats Mitigated:**
    *   **Unhandled Folly Exceptions (Severity: High):** Prevents crashes due to unhandled exceptions *thrown by Folly*.
    *   **Unexpected Behavior (due to Folly exceptions) (Severity: Medium):**  Ensures predictable behavior even when Folly code throws exceptions.

*   **Impact:**
    *   **Unhandled Folly Exceptions:** Risk significantly reduced.
    *   **Unexpected Behavior:** Risk reduced.

*   **Currently Implemented:**
    *   Some basic exception handling is in place.
    *   Logging of exceptions is inconsistent.

*   **Missing Implementation:**
    *   A thorough review of all code that uses Folly.
    *   Consistent logging of all caught exceptions.
    *   Consideration of `folly::Try` in specific areas.

