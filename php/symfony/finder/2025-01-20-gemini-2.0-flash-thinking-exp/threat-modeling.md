# Threat Model Analysis for symfony/finder

## Threat: [Path Traversal via Input Manipulation](./threats/path_traversal_via_input_manipulation.md)

**Description:** An attacker manipulates the directory path provided to Finder, using sequences like `../` to navigate to directories outside the intended scope. This allows them to access files they shouldn't have access to.

**Impact:** Information disclosure of sensitive files, potential access to configuration files or even system files, leading to further compromise.

**Affected Component:** The `path` parameter used in methods like `in()` or `files()->in()`.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   Strictly validate and sanitize all user-provided input used as directory paths.
*   Use absolute paths instead of relative paths where possible.
*   Implement a whitelist of allowed directories.
*   Avoid directly using user input in file system operations.

## Threat: [Wildcard Exploitation for Information Disclosure](./threats/wildcard_exploitation_for_information_disclosure.md)

**Description:** An attacker provides overly broad or malicious wildcard patterns (e.g., `*`, `*.log`, `*.*`) to the Finder component, causing it to enumerate and potentially return a larger set of files than intended, revealing sensitive information through filenames or file contents.

**Impact:** Information disclosure of file names and potentially file contents, which could reveal sensitive data or application structure.

**Affected Component:** The `name()` or `path()` methods used with wildcard patterns.

**Risk Severity:** High

**Mitigation Strategies:**
*   Restrict the use of wildcards in user-provided patterns.
*   Implement server-side validation and sanitization of wildcard patterns.
*   Provide predefined, safe search options instead of allowing arbitrary patterns.
*   Carefully consider the permissions of the user running the application.

## Threat: [Following Symbolic Links to Unauthorized Locations](./threats/following_symbolic_links_to_unauthorized_locations.md)

**Description:** If the `followLinks` option is enabled, an attacker could create symbolic links pointing to sensitive files or directories outside the intended scope. Finder would then follow these links, granting access to the linked resources.

**Impact:** Information disclosure, potential access to sensitive system files or application data outside the intended boundaries.

**Affected Component:** The `followLinks()` option.

**Risk Severity:** High

**Mitigation Strategies:**
*   Avoid enabling the `followLinks` option unless absolutely necessary and the implications are fully understood.
*   If `followLinks` is required, carefully control the directories where Finder operates and ensure no malicious symbolic links can be created within those directories.

