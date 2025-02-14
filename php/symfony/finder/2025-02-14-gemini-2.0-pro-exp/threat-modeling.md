# Threat Model Analysis for symfony/finder

## Threat: [Path Traversal via `in()` and `path()`](./threats/path_traversal_via__in____and__path___.md)

*   **Threat:** Path Traversal via `in()` and `path()`

    *   **Description:** An attacker crafts a malicious input string containing directory traversal sequences (e.g., "../", "..\\") to be used with the `in()` or `path()` methods. The attacker aims to escape the intended base directory and access files or directories outside the allowed scope.  For example, if the application expects a subdirectory name, the attacker might provide "../../etc" to try and access system files.
    *   **Impact:**
        *   Unauthorized access to sensitive files (configuration files, source code, etc.).
        *   Potential for code execution if the attacker can access and execute scripts.
        *   System compromise.
    *   **Affected Component:** `in()` method, `path()` method. These methods define the search scope and are directly vulnerable to path manipulation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Input Validation:** Validate user input *before* passing it to `in()` or `path()`. Use whitelisting (allow only known-good characters) rather than blacklisting. Reject any input containing "/", "\", "..", or other suspicious characters.
        *   **Base Path Restriction:** Always use absolute paths.  Construct the final path by appending user input to a known-safe, absolute base path.  *Never* allow the user to provide the entire path.
        *   **Avoid User-Controlled Paths:** If possible, avoid using user input directly in file paths. Use database IDs or other indirect methods to map user requests to files.

## Threat: [Symbolic Link Attack via `followLinks()` and `realpath()`](./threats/symbolic_link_attack_via__followlinks____and__realpath___.md)

*   **Threat:** Symbolic Link Attack via `followLinks()` and `realpath()`

    *   **Description:** An attacker creates a symbolic link on the filesystem that points to a sensitive file or directory.  If the application uses `followLinks()` (which is the default), Finder will traverse the link and access the target. Even without `followLinks()`, using `realpath()` to canonicalize paths will *still* resolve symbolic links, potentially exposing the target.
    *   **Impact:**
        *   Unauthorized access to sensitive files or directories that are the targets of the symbolic links.
        *   Potential for bypassing intended access controls.
    *   **Affected Component:** `followLinks()` method (and its default behavior), `realpath()` function (used internally or by the developer).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Disable `followLinks()`:** If symbolic link traversal is not *absolutely* necessary, disable it explicitly: `$finder->followLinks(false);`. 
        *   **`realpath()` Caution:** Be extremely cautious when using `realpath()`. Understand that it *will* resolve symbolic links. If you don't need symlink resolution, consider alternatives or carefully validate the output of `realpath()` to ensure it's within the expected directory.
        *   **Filesystem Permissions:** Enforce strict filesystem permissions. The web server process should have the *minimum* necessary access rights.

## Threat: [Denial of Service (DoS) via Large Directory Traversal](./threats/denial_of_service__dos__via_large_directory_traversal.md)

*   **Threat:** Denial of Service (DoS) via Large Directory Traversal

    *   **Description:** An attacker provides input that causes Finder to search an extremely large directory tree (e.g., the root directory or a directory with a massive number of files). This can consume excessive CPU, memory, or disk I/O, making the application unresponsive.
    *   **Impact:**
        *   Application unavailability.
        *   Potential for server instability.
    *   **Affected Component:** All Finder methods that perform directory traversal (e.g., `in()`, `files()`, `directories()`). The larger the search scope, the greater the risk.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Limit Search Scope:** Strictly limit the directories that can be searched. Avoid allowing searches in the root directory or other large, potentially uncontrolled areas. Use specific, well-defined directories.
        *   **Depth Limits:** Use the `depth()` method to limit the depth of directory traversal. For example, `$finder->depth('< 3');` would limit the search to a maximum depth of 3 levels.
        *   **Timeouts:** Implement timeouts for Finder operations to prevent them from running indefinitely.

## Threat: [Denial of Service (DoS) via Complex Regular Expressions (ReDoS)](./threats/denial_of_service__dos__via_complex_regular_expressions__redos_.md)

*   **Threat:** Denial of Service (DoS) via Complex Regular Expressions (ReDoS)

    *   **Description:** An attacker provides a crafted regular expression as input to methods like `name()` or `contains()` that use regex matching. The malicious regex is designed to cause excessive backtracking, consuming significant CPU resources and potentially leading to a denial-of-service.
    *   **Impact:**
        *   Application unavailability.
        *   Server resource exhaustion.
    *   **Affected Component:** `name()` method (when used with regex), `contains()` method (when used with regex), `filter()` method (if custom filters use regex).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid User-Supplied Regex:** If possible, *do not* allow users to provide their own regular expressions. Use predefined, safe patterns.
        *   **Regex Validation and Sanitization:** If user-supplied regex is unavoidable, *strictly* validate and sanitize it. Use a regex testing tool to check for potential backtracking issues (e.g., catastrophic backtracking).
        *   **Regex Timeouts:** Implement timeouts for regular expression matching.

