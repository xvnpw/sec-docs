# Threat Model Analysis for ccgus/fmdb

## Threat: [SQL Injection](./threats/sql_injection.md)

**Description:** An attacker exploits vulnerabilities in how the application uses FMDB to execute SQL queries. By injecting malicious SQL code through user-supplied input that is not properly sanitized or parameterized, the attacker can manipulate the executed query. This allows them to perform unauthorized actions against the database, such as reading sensitive data, modifying or deleting data, or even executing arbitrary SQL commands.

**Impact:** Confidentiality breach (accessing unauthorized data), integrity violation (modifying or deleting data), potential denial of service (through resource exhaustion or data corruption).

**Affected FMDB Component:** `FMDatabase` methods for executing raw SQL queries (e.g., `executeQuery:`, `executeUpdate:`) when used with unsanitized input, and the lack of use of parameterized query methods (`executeQuery:withArgumentsInArray:`, `executeUpdate:withArgumentsInArray:`).

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Crucially, always use parameterized queries (prepared statements) with FMDB's `executeQuery:withArgumentsInArray:` or `executeUpdate:withArgumentsInArray:`.**
*   Avoid string concatenation to build SQL queries using any form of external input.

## Threat: [Database File Exposure](./threats/database_file_exposure.md)

**Description:**  The FMDB library interacts directly with the SQLite database file. If this file is stored in a location with insecure permissions or is otherwise accessible to an attacker, they can directly access and manipulate the database, bypassing any application-level security measures enforced through FMDB. This direct access allows them to read all data, modify it, or even delete the entire database file.

**Impact:** Complete confidentiality breach of all data within the database, potential integrity violation through direct modification, availability issues if the database is deleted or corrupted.

**Affected FMDB Component:** The underlying file system interaction initiated by `FMDatabase` when opening the database file using methods like `databaseWithPath:`.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   Store the database file in a protected location with restricted file system permissions, ensuring only the application process has the necessary read and write access.
*   Consider encrypting the database file at rest, which would mitigate the impact even if the file is accessed.

## Threat: [Path Traversal in Database File Path](./threats/path_traversal_in_database_file_path.md)

**Description:** If the application uses user-provided input to construct the file path passed to FMDB's database opening methods, an attacker could manipulate this input to specify a path outside the intended directory. This could allow them to access or potentially overwrite other files on the system that the application process has access to, by tricking FMDB into operating on a different file.

**Impact:** Potential confidentiality breach (accessing other files), integrity violation (modifying other files), potential for denial of service or even arbitrary code execution depending on the files accessed or modified.

**Affected FMDB Component:** `FMDatabase`'s initialization methods that take a file path as an argument (e.g., `databaseWithPath:`).

**Risk Severity:** High

**Mitigation Strategies:**
*   **Never directly use user-provided input to construct the full path to the database file passed to FMDB.**
*   Use a fixed or application-controlled base directory for the database and only allow specifying the database filename, combining it securely with the base path within the application.
*   Implement strict input validation on any user-provided filename components if absolutely necessary.

## Threat: [Vulnerabilities in FMDB Library](./threats/vulnerabilities_in_fmdb_library.md)

**Description:**  The FMDB library itself might contain undiscovered security vulnerabilities. An attacker could exploit these vulnerabilities to compromise the application or the data managed through FMDB. The impact would depend on the nature of the specific vulnerability.

**Impact:** Varies depending on the vulnerability, potentially leading to arbitrary code execution, data breaches, denial of service, or other unexpected behavior within the application's database interaction layer.

**Affected FMDB Component:** Any part of the FMDB library code.

**Risk Severity:** Varies (can be High or Critical depending on the specific vulnerability)

**Mitigation Strategies:**
*   **Keep the FMDB library updated to the latest version.** This ensures that known vulnerabilities are patched.
*   Monitor the FMDB repository and security advisories for any reported vulnerabilities.
*   Consider using static analysis tools that can scan third-party libraries for known vulnerabilities.

