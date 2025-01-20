# Attack Surface Analysis for symfony/finder

## Attack Surface: [Path Traversal via User-Controlled `in()` Method](./attack_surfaces/path_traversal_via_user-controlled__in____method.md)

**Description:** Attackers can manipulate user-provided input to specify directory paths outside the intended scope, potentially accessing sensitive files or directories.

**Finder Contribution:** The `in()` method directly uses the provided path to initiate the file search. If this path is influenced by unsanitized user input, Finder will operate within the attacker-controlled location.

**Example:** An application uses `$finder->in($_GET['target_dir']);`. An attacker could set `target_dir` to `../../../../etc/passwd` to attempt to access the system's password file.

**Impact:** Unauthorized access to sensitive files, potential for information disclosure, and in some cases, the ability to manipulate or delete critical system files.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Strict Input Validation:** Whitelist allowed directory paths or use a predefined set of safe directories.
* **Path Canonicalization:** Resolve symbolic links and relative paths to their absolute canonical form and validate against allowed paths.
* **Avoid Direct User Input:**  Do not directly use user input to define the root directory for the Finder. Use predefined, safe paths.

## Attack Surface: [Regular Expression Denial of Service (ReDoS) via User-Controlled `path()` or `name()` Methods](./attack_surfaces/regular_expression_denial_of_service__redos__via_user-controlled__path____or__name____methods.md)

**Description:** Attackers can provide crafted regular expressions to the `path()` or `name()` methods that cause excessive backtracking, leading to high CPU usage and potential denial of service.

**Finder Contribution:** The `path()` and `name()` methods use regular expressions for filtering files. If these expressions are derived from unsanitized user input, malicious patterns can be injected.

**Example:** An application uses `$finder->name($_GET['filename_pattern']);`. An attacker could set `filename_pattern` to `(a+)+.txt` which is a known ReDoS pattern.

**Impact:** Application slowdown, resource exhaustion, potential for complete denial of service.

**Risk Severity:** High

**Mitigation Strategies:**
* **Input Validation and Sanitization:**  Sanitize user input intended for regular expressions. Consider using a limited subset of regex features or escaping special characters.
* **Timeouts for Regex Matching:** Implement timeouts for the regular expression matching process to prevent indefinite execution.
* **Predefined Patterns:** If possible, use predefined and tested regular expression patterns instead of relying on user input.

## Attack Surface: [Information Disclosure via Unintended File Access (due to broad search scope or lack of `ignoreDotFiles()`)](./attack_surfaces/information_disclosure_via_unintended_file_access__due_to_broad_search_scope_or_lack_of__ignoredotfi_30edbc9b.md)

**Description:**  The Finder might inadvertently access and potentially expose sensitive files due to an overly broad search scope or by not ignoring dot files (configuration files, etc.).

**Finder Contribution:** The `in()` method defines the search scope, and the `ignoreDotFiles()` method controls whether hidden files are included. Misconfiguration can lead to unintended file access.

**Example:** An application uses `$finder->in('/var/www');` without proper filtering and doesn't call `$finder->ignoreDotFiles(true);`, potentially exposing `.env` files containing sensitive credentials.

**Impact:** Exposure of sensitive configuration data, credentials, or other confidential information.

**Risk Severity:** High

**Mitigation Strategies:**
* **Restrict Search Scope:**  Define the search scope as narrowly as possible to only include necessary directories.
* **Use `ignoreDotFiles(true)`:** Explicitly ignore dot files unless there's a specific and secure reason to include them.
* **Implement Strong Access Controls:** Ensure the application user has the least necessary privileges to access files.

