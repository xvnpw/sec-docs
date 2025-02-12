# Mitigation Strategies Analysis for google/guava

## Mitigation Strategy: [Secure Hashing Practices (Guava `Hashing`)](./mitigation_strategies/secure_hashing_practices__guava__hashing__.md)

**Description:**
1.  **Algorithm Policy:** Establish a clear policy *prohibiting* the use of MD5 and SHA-1 within Guava's `Hashing` utilities. Document this policy.
2.  **Approved Algorithms:** Specify approved hashing algorithms for use with `Hashing` (e.g., SHA-256, SHA-512).  *Explicitly forbid* using `Hashing` for password storage; mandate a separate, dedicated password hashing library.
3.  **Code Review Checklist:** Include checks in code reviews to verify:
    *   No prohibited algorithms are used with `Hashing`.
    *   `Hashing` is *not* used for password storage.
    *   Justification is provided for any use of `Hashing`.
4.  **Static Analysis (Optional):** Configure static analysis to flag prohibited algorithms within calls to `Hashing`.

**Threats Mitigated:**
*   **Weak Hash Collisions:** (Severity: High) - Using weak algorithms (MD5, SHA-1) in `Hashing` makes collision attacks easier.
*   **Password Cracking:** (Severity: Critical) - Using `Hashing` *directly* for passwords (without proper techniques) makes them vulnerable.
*   **Data Integrity Compromise:** (Severity: High) - Weak hashes used for integrity checks via `Hashing` allow data modification.

**Impact:**
*   **Weak Hash Collisions:** Risk reduction: High (eliminates weak algorithm use within `Hashing`).
*   **Password Cracking:** Risk reduction: Critical (prevents misuse of `Hashing` for passwords).
*   **Data Integrity Compromise:** Risk reduction: High (stronger algorithms for integrity checks via `Hashing`).

**Currently Implemented:**
*   Coding standards document prohibits MD5 and SHA-1.
*   Code review checklist includes checks for hashing algorithm usage.

**Missing Implementation:**
*   Static analysis rules to flag weak hashing algorithms within `Hashing` calls are not configured.
*   Explicit policy and code examples for using a dedicated password hashing library (separate from Guava) are needed.

## Mitigation Strategy: [Input Validation for `InternetDomainName`](./mitigation_strategies/input_validation_for__internetdomainname_.md)

**Description:**
1.  **Input Validation *Before* Guava:** Implement input validation *before* calling `InternetDomainName.from()`.
2.  **Regular Expressions:** Use a robust regular expression to validate the domain name format *before* passing it to Guava.  This regex should be carefully crafted and tested.  Example (Java - simplified, needs refinement):
    ```java
    String domain = ...; // Input
    String domainRegex = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$";
    if (domain.matches(domainRegex)) {
        InternetDomainName parsedDomain = InternetDomainName.from(domain);
        // ... proceed ...
    } else {
        // Handle invalid input
    }
    ```
3.  **Length Limits:** Enforce reasonable length limits on the input string *before* passing it to Guava.

**Threats Mitigated:**
*   **Injection Attacks (into `InternetDomainName`):** (Severity: High) - Prevents malicious input exploiting vulnerabilities in Guava's parsing.
*   **Denial of Service (DoS) against `InternetDomainName`:** (Severity: Medium to High) - Limits impact of excessively long/complex inputs.
*   **Logic Errors due to `InternetDomainName`:** (Severity: Medium) - Reduces unexpected behavior from invalid input to Guava.

**Impact:**
*   **Injection Attacks:** Risk reduction: High (prevents injection attacks targeting `InternetDomainName`).
*   **Denial of Service (DoS):** Risk reduction: Medium (mitigates some DoS vectors against `InternetDomainName`).
*   **Logic Errors:** Risk reduction: Medium (improves robustness).

**Currently Implemented:**
*   Basic length checks are performed on some inputs.

**Missing Implementation:**
*   Robust regular expressions for `InternetDomainName` input are not consistently used.
*   Validation is not consistently applied *before* all calls to `InternetDomainName.from()`.

## Mitigation Strategy: [Proper `Optional` Handling](./mitigation_strategies/proper__optional__handling.md)

**Description:**
1.  **Coding Standards:** Enforce standards requiring correct `Optional` handling:
    *   *Never* call `.get()` without `.isPresent()`.
    *   Use `.orElse()`, `.orElseGet()`, `.orElseThrow()`.
    *   Use `.ifPresent()`.
2.  **Code Reviews:** Reviews *must* check for correct `Optional` usage, flagging `.get()` without `.isPresent()`.
3.  **Static Analysis:** Configure tools (SpotBugs, SonarQube) to detect `Optional` misuse (specifically, `.get()` without `.isPresent()`).

**Threats Mitigated:**
*   **`NoSuchElementException` from `Optional.get()`:** (Severity: Medium) - Prevents runtime exceptions.
*   **Denial of Service (DoS) due to `Optional` misuse:** (Severity: Low to Medium) - Unhandled exceptions can lead to DoS.
*   **Information Disclosure via `Optional` exceptions:** (Severity: Low) - Exception stack traces might reveal information.

**Impact:**
*   **`NoSuchElementException`:** Risk reduction: High (eliminates this specific exception).
*   **Denial of Service (DoS):** Risk reduction: Low (mitigates some DoS vectors).
*   **Information Disclosure:** Risk reduction: Low (reduces risk of exposing information).

**Currently Implemented:**
*   Some developers are aware of proper `Optional` handling.

**Missing Implementation:**
*   Explicit coding standards for `Optional` are not fully documented.
*   Code review checklists do not consistently check for `Optional` misuse.
*   Static analysis rules for `Optional` are not configured.

## Mitigation Strategy: [Secure `CacheBuilder` Configuration](./mitigation_strategies/secure__cachebuilder__configuration.md)

**Description:**
1.  **`maximumSize()` or `maximumWeight()`:** *Always* set a maximum size for any `CacheBuilder` instance. Choose a size appropriate for the application.
2.  **Expiration Policies:** Configure `expireAfterWrite()` or `expireAfterAccess()` to remove stale entries.
3.  **`Weigher` (If Applicable):** If entries have varying sizes, use a `Weigher` with `maximumWeight()`.
4.  **`RemovalListener` (Optional):** Implement a `RemovalListener` to monitor evictions and potentially detect attacks. Log relevant information.
5. **Documentation:** Document the cache configuration, including the rationale for chosen settings.

**Threats Mitigated:**
*   **Denial of Service (DoS) against `CacheBuilder`:** (Severity: High) - Prevents memory exhaustion by flooding the cache.
*   **Resource Exhaustion due to `CacheBuilder`:** (Severity: Medium) - Prevents excessive resource consumption.

**Impact:**
*   **Denial of Service (DoS):** Risk reduction: High (significantly reduces DoS risk).
*   **Resource Exhaustion:** Risk reduction: High (prevents excessive resource use).

**Currently Implemented:**
*   None.

**Missing Implementation:**
*   All aspects are missing. We need to:
    *   Identify all `CacheBuilder` uses.
    *   Implement `maximumSize()`/`maximumWeight()`.
    *   Configure expiration policies.
    *   Consider `Weigher` and `RemovalListener`.
    *   Document configurations.

