# Threat Model Analysis for symfony/finder

## Threat: [Path Traversal](./threats/path_traversal.md)

**Description:** An attacker manipulates user-controlled input used in Finder's path methods (`in()`, `path()`) to traverse directories outside the intended scope. They might inject "../" sequences or absolute paths to access sensitive files or directories not meant to be accessible.
**Impact:** Unauthorized access to sensitive files, information disclosure (source code, configuration, user data), potential for further system compromise if sensitive files like configuration files with credentials are accessed. This can be **critical** if highly sensitive data is exposed or system compromise is facilitated.
**Affected Finder Component:** `Finder::in()` method, `Finder::path()` method when used with user-controlled input.
**Risk Severity:** Critical/High
**Mitigation Strategies:**
*   **Input Validation and Sanitization:** Sanitize and validate all user-provided input used in file paths.
*   **Restrict Search Scope:** Define a strict, absolute base directory for Finder searches and prevent user input from modifying or bypassing it.
*   **Principle of Least Privilege:** Run the application with minimal file system permissions.

## Threat: [Symbolic Link Following Exploitation](./threats/symbolic_link_following_exploitation.md)

**Description:**  Finder, by default, follows symbolic links. An attacker could create symbolic links within a searchable directory pointing to sensitive files or directories outside the intended scope. When Finder traverses these links, it could inadvertently access and potentially expose these sensitive resources, effectively bypassing intended path restrictions. This is a variation of path traversal.
**Impact:** Path traversal vulnerabilities, unauthorized access to files and directories outside the intended scope, information disclosure.
**Affected Finder Component:** `Finder::followLinks()` option (default is `true`).
**Risk Severity:** High
**Mitigation Strategies:**
*   **Disable Symbolic Link Following:** Use `Finder::followLinks(false)` if symbolic link following is not required.
*   **Restrict Search Scope:** Carefully control base directories to minimize exposure to attacker-controlled symlinks.
*   **Symbolic Link Resolution Validation:** If following symlinks is necessary, validate resolved paths to ensure they remain within the intended scope.

