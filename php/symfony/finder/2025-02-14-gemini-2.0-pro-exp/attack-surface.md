# Attack Surface Analysis for symfony/finder

## Attack Surface: [Path Traversal (Directory Traversal)](./attack_surfaces/path_traversal__directory_traversal_.md)

**Description:** An attacker manipulates file paths provided to Finder to access files or directories outside the intended, restricted directory. This is the most significant vulnerability.

**How Finder Contributes:** Finder's `in()`, `path()`, and `name()` methods, when accepting unsanitized user-supplied data, become the direct mechanism for injecting path traversal sequences (e.g., `../`).  Improperly implemented `filter()` methods can also be exploited.

**Example:**
    *   Application code: `$finder->in('/uploads/' . $_GET['user_dir']);`
    *   Attacker provides: `?user_dir=../../etc`
    *   Finder accesses: `/path/to/uploads/../../etc` (likely resolving to `/etc`), potentially exposing system files.

**Impact:**
    *   **Information Disclosure:** Exposure of sensitive files (configuration, source code, data).
    *   **Potential Code Execution (Indirect):** Modification of server configuration files (e.g., `.htaccess`) could lead to RCE.
    *   **Data Tampering:** If write access is somehow obtained.

**Risk Severity:** Critical

**Mitigation Strategies:**
    *   **Never use user input directly in `in()`, `path()`, or `name()`:** Use a whitelist of allowed directories or a safe, application-generated base path.
    *   **Rigorous Input Validation and Sanitization:** If user input *must* be used, validate it strictly. Reject input with suspicious characters (`.`, `/`, `\`, null bytes). Use a regular expression for a strict format (e.g., alphanumeric and underscores only).
    *   **Path Normalization:** Normalize paths *before* using them with Finder (e.g., `realpath()`, but be aware of its limitations). *Crucially*, after normalization, verify the resulting path is *still* within the intended base directory (e.g., `strpos($normalizedPath, $basePath) === 0`).
    *   **Least Privilege:** Run the web server process with minimal file system permissions. It should *never* have read access to sensitive system directories.
    *   **Avoid user input in `filter()` closures:** Sanitize and validate any user input *before* it reaches the closure if it's used for file operations.

## Attack Surface: [Denial of Service (DoS) via Resource Exhaustion](./attack_surfaces/denial_of_service__dos__via_resource_exhaustion.md)

**Description:** An attacker crafts input to make Finder consume excessive server resources (CPU, memory, disk I/O), causing application unavailability.

**How Finder Contributes:** Finder's `in()` (with a large/deep directory), `path()`/`name()` (with overly broad wildcards or complex regex), or an inefficient `filter()` can be abused.

**Example:**
    *   Application code: `$finder->in('/')->name($_GET['pattern']);`
    *   Attacker provides: `?pattern=************************************************a` (a very long, complex pattern)
    *   Finder attempts to match this against every file in the root directory, potentially exhausting resources.  Alternatively, the attacker could provide a path to a directory known to contain a huge number of files.

**Impact:**
    *   Application unavailability.
    *   Potential server instability.

**Risk Severity:** High (can be Critical if it impacts other services)

**Mitigation Strategies:**
    *   **Limit Search Scope:** Restrict Finder's search to the smallest possible scope. Avoid searching from the root (`/`) or other large directories.
    *   **Input Validation (Pattern Complexity):** If user input influences the search pattern, limit its length and complexity. Reject overly long patterns or those with excessive wildcards. Consider a regular expression to enforce a maximum number of wildcards.
    *   **Resource Limits:** Configure PHP and the web server with appropriate resource limits (memory, execution time) to prevent a single request from consuming all resources.
    *   **Rate Limiting:** Implement rate limiting to prevent an attacker from making many requests that trigger resource-intensive Finder operations.
    *   **Depth Limiting:** Use Finder's `depth()` method to limit recursion depth when searching subdirectories (e.g., `$finder->depth('< 3')`).
    *   **File Count Limiting:** Use a counter (within a `filter()` or after results) to limit the total number of files processed. Stop and return an error if the limit is exceeded.

## Attack Surface: [Symbolic Link Attacks (Exploiting `followLinks()`)](./attack_surfaces/symbolic_link_attacks__exploiting__followlinks____.md)

**Description:** An attacker uses symbolic links to bypass access restrictions, leading Finder to access unintended files.

**How Finder Contributes:** If `followLinks()` is enabled (it's *off* by default), Finder will follow symbolic links. An attacker could create a symlink within an accessible directory pointing to a sensitive location.

**Example:**
    *   Application allows uploads to `/var/www/uploads/user1/`.
    *   Attacker creates: `ln -s /etc/passwd /var/www/uploads/user1/passwd_link`
    *   Application code: `$finder->in('/var/www/uploads/user1/')->followLinks();`
    *   Finder follows the link and accesses `/etc/passwd`.

**Impact:** Similar to path traversal: information disclosure, potential code execution, data tampering.

**Risk Severity:** High (if `followLinks()` is enabled and symlinks are possible)

**Mitigation Strategies:**
    *   **Disable `followLinks()`:** This is the *best* mitigation. Only enable it if absolutely necessary and you understand the risks.
    *   **Validate Target of Symbolic Links (if `followLinks()` is required):** Before accessing a file, use `is_link()` to check if it's a symlink. If so, use `readlink()` to get the target and *validate that the target is also within the allowed directory*. This is similar to path normalization for path traversal.
    *   **Restrict Symbolic Link Creation:** If possible, restrict the creation of symbolic links within user-accessible directories (defense-in-depth).

