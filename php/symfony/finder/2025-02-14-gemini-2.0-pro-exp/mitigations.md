# Mitigation Strategies Analysis for symfony/finder

## Mitigation Strategy: [Strict Directory Whitelisting (`in()` Method)](./mitigation_strategies/strict_directory_whitelisting___in____method_.md)

*   **Description:**
    1.  **Identify Allowed Directories:** Determine the *absolute minimum* set of directories that the application needs to access via Symfony Finder.
    2.  **Create a Mapping:** Create a hardcoded associative array (or a configuration file *not* editable by users) that maps user-friendly keys to the *absolute* paths of these allowed directories.  Example:
        ```php
        $allowedDirectories = [
            'user_uploads' => '/var/www/app/data/uploads/',
            'product_images' => '/var/www/app/public/images/products/',
            'temp_files' => '/tmp/app_temp/', // Outside webroot
        ];
        ```
    3.  **User Input as Key:** If users select a directory, *only* allow them to select from the *keys* of this mapping (e.g., 'user_uploads').  *Never* accept a raw path.
    4.  **Validate User Input:** Verify that the user-provided key exists in the `$allowedDirectories` array.
    5.  **Use the Mapped Path:** If the key is valid, use the corresponding value (the absolute path) from the `$allowedDirectories` array in the `Finder->in()` method.
    6.  **Handle Invalid Input:** If the key is *not* valid, handle the error. Do *not* use a default path that might be broader. Display a generic error message and log the attempt.

*   **Threats Mitigated:**
    *   **Arbitrary File Read (High Severity):** Prevents attackers from specifying arbitrary paths to read sensitive files.
    *   **Information Disclosure (Medium Severity):** Limits the attacker's ability to probe the filesystem.
    *   **Denial of Service (DoS) (Medium Severity):** Reduces risk of DoS by specifying a very large directory.
    *   **Trigger Unexpected Behavior (High Severity):** Prevents access to files that could lead to code execution.

*   **Impact:**
    *   **Arbitrary File Read:** Risk significantly reduced (almost eliminated).
    *   **Information Disclosure:** Risk significantly reduced.
    *   **Denial of Service (DoS):** Risk reduced.
    *   **Trigger Unexpected Behavior:** Risk significantly reduced.

*   **Currently Implemented:**
    *   `src/Controller/ImageController.php`: Whitelist for image directories.
    *   `src/Service/ReportGenerator.php`: Whitelist for temp file directories.

*   **Missing Implementation:**
    *   `src/Controller/LegacyDataController.php`: Uses user-provided paths directly in `Finder->in()`.
    *   `src/Command/CleanupCommand.php`: Uses a config file path that is not validated.

## Mitigation Strategy: [Safe Pattern Construction and Validation (`name()`, `path()`, `contains()`, `filter()`, etc.)](./mitigation_strategies/safe_pattern_construction_and_validation___name______path______contains______filter_____etc__.md)

*   **Description:**
    1.  **Avoid Direct User Input in Patterns:** *Never* allow users to directly input regular expressions or wildcard patterns for `Finder` methods.
    2.  **Predefined Patterns:** Use only predefined, hardcoded patterns that you have thoroughly tested.
    3.  **Indirect Input with Sanitization:** If you *must* use user input to construct a pattern:
        *   **Character Whitelisting:** Restrict allowed characters to the *absolute minimum*. Use `preg_replace()` to remove disallowed characters.
        *   **Escaping Special Characters:** Escape characters with special meaning in regular expressions. Use `preg_quote()`.
        *   **Length Limits:** Enforce strict length limits on user input.
        *   **Pattern Construction:** Construct the final pattern *programmatically*, incorporating the sanitized input into a predefined structure. Example:
            ```php
            $sanitizedInput = preg_replace('/[^a-zA-Z0-9_-]/', '', $userInput);
            $escapedInput = preg_quote($sanitizedInput, '/');
            $pattern = '*' . $escapedInput . '*'; // Files *containing* input
            $finder->name($pattern);
            ```
    4.  **`fnmatch()` for Simple Wildcards:** If you only need simple wildcard matching (e.g., `*.txt`), use `fnmatch()` within a `filter()` instead of regular expressions.
    5.  **Regex Timeouts (Advanced):** Implement timeouts on regular expression execution. Use `symfony/process` to run regex matching in a separate process with a timeout.

*   **Threats Mitigated:**
    *   **Regular Expression Denial of Service (ReDoS) (High Severity):** Prevents crafted regex causing excessive CPU usage.
    *   **Arbitrary File Read (High Severity):** Reduces risk of using patterns to match unintended files.
    *   **Information Disclosure (Medium Severity):** Limits using patterns to infer filesystem information.
    *   **Trigger Unexpected Behavior (High Severity):** Prevents access to files that could lead to code execution.

*   **Impact:**
    *   **ReDoS:** Risk significantly reduced (especially with timeouts).
    *   **Arbitrary File Read:** Risk reduced (relies on sanitization).
    *   **Information Disclosure:** Risk reduced.
    *   **Trigger Unexpected Behavior:** Risk significantly reduced.

*   **Currently Implemented:**
    *   `src/Controller/SearchController.php`: Sanitization and escaping for search terms.
    *   `src/Service/FileIndexer.php`: Uses `fnmatch()` for wildcards.

*   **Missing Implementation:**
    *   `src/Controller/ReportController.php`: Regex based on user input, no sanitization/timeouts.
    *   No global regex timeout mechanism.

## Mitigation Strategy: [Careful Use of `exclude()`](./mitigation_strategies/careful_use_of__exclude___.md)

*   **Description:**
    1.  **Prioritize `in()` Restrictions:** Focus primarily on tightly controlling the `in()` path (using whitelisting).
    2.  **`exclude()` for Convenience, Not Primary Security:** Use `exclude()` to simplify code by excluding files/directories *within* the already-securely-defined `in()` path.  Do *not* rely on it as the primary access control.
    3. **Avoid User Input:** Do not allow user to control what is excluded.

*   **Threats Mitigated:**
    *   **Arbitrary File Read (Low Severity):** Provides a *minor* additional layer of defense *if* `in()` is already well-controlled.  It does *not* reliably prevent access if `in()` is vulnerable.

*   **Impact:**
    *   **Arbitrary File Read:** Minimal impact on its own.  Only useful as a secondary measure.

*   **Currently Implemented:**
    *    `src/Service/BackupService.php` uses `exclude()` to omit temporary files during backups.

*   **Missing Implementation:**
    *   None. The existing usage is appropriate; the key is *not* to rely on `exclude()` for primary security.

