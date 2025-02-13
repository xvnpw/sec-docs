# Threat Model Analysis for sqldelight/sqldelight

## Threat: [Raw String SQL Injection](./threats/raw_string_sql_injection.md)

*   **Threat:** Raw String SQL Injection
    *   **Description:** An attacker crafts malicious input that, when concatenated directly into a SQL query string *within SQLDelight's context* (bypassing SQLDelight's parameterization), alters the query's logic. This occurs when developers mistakenly use string interpolation or concatenation *instead of* SQLDelight's parameterized query mechanisms within `.sq` files or when programmatically building queries. The attacker aims to read, modify, or delete data, or potentially execute commands on the database server.
    *   **Impact:** Data breach (reading sensitive data), data modification/corruption, data deletion, denial of service, potential remote code execution (depending on database configuration and privileges).
    *   **Affected Component:**  `.sq` files where queries are defined; Kotlin/Java/Swift code that dynamically constructs SQL queries using string operations *instead of* SQLDelight's API. Specifically, misuse of raw string handling within functions intended for parameterized queries.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strictly Enforce Parameterized Queries:**  Mandatory use of `?` placeholders in `.sq` files and the corresponding API methods (e.g., `executeAsOne`, `executeAsList`, `bindString`, `bindLong`, etc.) to bind values.
        *   **Code Reviews:** Mandatory code reviews with a specific focus on identifying *any* instance of string concatenation or interpolation used for SQL query construction within the SQLDelight context.
        *   **Static Analysis:** Employ static analysis tools configured to detect string concatenation within SQL contexts, specifically targeting `.sq` files and code interacting with the SQLDelight API. Linters should be customized to flag this as a critical error.
        *   **Developer Training:** Comprehensive developer training on secure SQLDelight usage, emphasizing the *absolute necessity* of parameterized queries and the severe risks of raw string manipulation.
        *   **Prohibit/Restrict Raw String Functions:**  Consider completely forbidding or severely restricting the use of any SQLDelight functions that accept raw SQL strings. If such functions *must* be used, they should be subject to extreme scrutiny and justification.

## Threat: [Custom Dialect SQL Injection](./threats/custom_dialect_sql_injection.md)

*   **Threat:** Custom Dialect SQL Injection
    *   **Description:** An attacker exploits a vulnerability in a *custom* SQLDelight dialect (one not officially supported by the SQLDelight project). The custom dialect likely has flaws in how it handles parameters or generates SQL, allowing for SQL injection *even when the developer believes they are using parameterized queries*. The attacker crafts input specifically designed to exploit the dialect's weaknesses. This is a direct threat to SQLDelight because the vulnerability exists within a component extending SQLDelight's core functionality.
    *   **Impact:** Data breach, data modification/corruption, data deletion, denial of service, potential remote code execution (similar to raw string injection, but through a vulnerability in the dialect).
    *   **Affected Component:** The *custom* SQLDelight dialect implementation. Specifically, the code responsible for generating SQL from the SQLDelight query representation and handling parameter binding within that custom dialect.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid Custom Dialects:** Strongly prefer officially supported and thoroughly vetted SQLDelight dialects.
        *   **Extreme Vetting:** If a custom dialect is *absolutely unavoidable*, subject it to the highest level of scrutiny.  Examine the source code meticulously for secure parameter handling and SQL generation, paying particular attention to how user-provided input is incorporated.
        *   **Rigorous Security Testing:** Perform extensive security testing on the custom dialect, including fuzzing and penetration testing, specifically focusing on potential SQL injection vulnerabilities.
        *   **Independent Security Audit:**  Have the custom dialect reviewed and audited by an independent security expert with experience in database security and SQL injection.
        *   **Continuous Monitoring and Updates:** Continuously monitor the custom dialect's codebase for any reported vulnerabilities or security issues, and apply updates immediately.

## Threat: [SQLDelight Dependency Vulnerability](./threats/sqldelight_dependency_vulnerability.md)

*   **Threat:** SQLDelight Dependency Vulnerability
    *   **Description:** A security vulnerability is discovered *within the SQLDelight library itself* (core components, code generator, or runtime). An attacker could exploit this vulnerability to compromise applications that use SQLDelight, potentially gaining access to the database or causing other application-level issues. This is a direct threat because the vulnerability resides within SQLDelight's own code.
    *   **Impact:** Varies depending on the specific vulnerability, but could range from data breaches (reading, modifying, deleting data) to denial of service or, in severe cases, potentially remote code execution (if the vulnerability allows for arbitrary code execution).
    *   **Affected Component:** The SQLDelight library itself (any of its modules).
    *   **Risk Severity:** Variable (depends on the vulnerability), potentially Critical or High.
    *   **Mitigation Strategies:**
        *   **Stay Updated:**  Maintain SQLDelight at the *latest released version*.  Actively monitor for security advisories and patches published by the SQLDelight maintainers.
        *   **Dependency Management:** Utilize a dependency management system (e.g., Gradle, Maven, CocoaPods) to automatically check for and apply updates to SQLDelight. Configure the system to alert on new releases.
        *   **Vulnerability Scanning:** Employ vulnerability scanning tools that specifically target dependencies, including SQLDelight, to identify known vulnerabilities. Integrate these tools into the CI/CD pipeline.

