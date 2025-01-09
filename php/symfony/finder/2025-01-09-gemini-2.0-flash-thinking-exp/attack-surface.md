# Attack Surface Analysis for symfony/finder

## Attack Surface: [Path Traversal via User-Controlled Paths](./attack_surfaces/path_traversal_via_user-controlled_paths.md)

*   **Description:** An attacker can manipulate user-provided input to access files or directories outside the intended scope by exploiting insufficient validation of paths passed to the `Finder`.
    *   **How Finder Contributes to the Attack Surface:** The `Finder::in()` method and other path-related methods directly operate on the provided paths. If these paths are derived from user input without proper sanitization, the Finder will attempt to access those potentially malicious locations.
    *   **Example:** An application allows users to specify a directory to search within. An attacker provides `../../../../etc/passwd` as the directory, and the application uses `Finder::create()->in($_GET['path'])`.
    *   **Impact:** Unauthorized access to sensitive files, configuration files, or even system binaries. Potential for information disclosure or further exploitation.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Strict Input Validation:** Sanitize and validate all user-provided path inputs. Use whitelisting of allowed paths or regular expressions to enforce expected formats.
        *   **Canonicalization:**  Resolve symbolic links and relative paths to their canonical form to prevent traversal using techniques like `..`.
        *   **Principle of Least Privilege:** Ensure the application runs with the minimum necessary file system permissions. Limit the directories the Finder operates within.
        *   **Avoid Direct User Input:**  Avoid directly using user input to construct file paths. Instead, use predefined allowed paths and map user selections to these safe paths.

## Attack Surface: [Regular Expression Injection in Matching Methods](./attack_surfaces/regular_expression_injection_in_matching_methods.md)

*   **Description:** An attacker can inject malicious regular expressions into methods like `name()`, `contains()`, `notName()`, and `notContains()` if user input is used without proper escaping or sanitization. This can lead to Denial of Service (ReDoS).
    *   **How Finder Contributes to the Attack Surface:** These methods directly interpret the provided strings as regular expressions. If unsanitized user input is used, malicious regexes can be injected.
    *   **Example:** An application allows users to filter files by name. An attacker provides a specially crafted regex like `^(a+)+$` which can cause excessive backtracking and CPU consumption when used in `Finder::create()->in('/tmp')->name($_GET['filter'])`.
    *   **Impact:** Denial of Service (DoS) due to excessive CPU consumption, potentially making the application unresponsive.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Input Sanitization:**  Escape special regular expression characters in user-provided input before using it in Finder's matching methods.
        *   **Consider Alternatives:** If possible, use simpler string matching functions or predefined patterns instead of relying on user-provided regexes.
        *   **Timeouts:** Implement timeouts for regular expression matching to prevent long-running regexes from consuming excessive resources.
        *   **Regex Analysis:**  Analyze user-provided regexes for potential performance issues before execution (though this can be complex).

