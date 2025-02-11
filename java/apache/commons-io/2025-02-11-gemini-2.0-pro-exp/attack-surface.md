# Attack Surface Analysis for apache/commons-io

## Attack Surface: [Path Traversal](./attack_surfaces/path_traversal.md)

**Description:** Attackers manipulate file paths provided to Commons IO methods to access or modify files outside the intended directory, potentially gaining unauthorized access to sensitive data or system resources.

**Commons IO Contribution:** Provides numerous methods for file and directory manipulation (e.g., `FileUtils.getFile`, `FileUtils.copyFile`, `FileUtils.openInputStream`, `FileUtils.openOutputStream`, `FilenameUtils.normalize`) that are *directly* vulnerable if used with unsanitized user input.  `FilenameUtils.normalize` is *not* a complete security solution.

**Example:** An application uses `FileUtils.readFileToString("/var/www/app/uploads/" + userInput)` where `userInput` is controlled by the attacker.  If `userInput` is `../../etc/passwd`, the application might read the system's password file.

**Impact:**
    *   Disclosure of sensitive information (configuration files, source code, etc.).
    *   Modification or deletion of critical files.
    *   Potential for remote code execution (if the attacker can write to executable locations).

**Risk Severity:** Critical

**Mitigation Strategies:**
    *   **Input Validation (Whitelist):**  Strictly validate *all* user-supplied input used in file paths.  Use a whitelist approach, allowing only known-good characters and patterns. Reject any input containing "..", "/", "\", or other potentially dangerous characters.
    *   **Canonicalization:** After any normalization (e.g., using `FilenameUtils.normalize`), use `File.getCanonicalPath()` to obtain the absolute, unambiguous path.  *Then*, compare this canonical path to a known-good base directory to ensure it's within the allowed bounds.  This is a crucial step.
    *   **Least Privilege:** Run the application with the minimum necessary file system permissions.
    *   **Avoid User Input in Paths:** If possible, avoid using user-supplied data directly in file paths. Use unique identifiers (UUIDs) instead.

## Attack Surface: [Symbolic Link Attacks](./attack_surfaces/symbolic_link_attacks.md)

**Description:** Attackers create symbolic links (symlinks) that point to sensitive files or directories. Commons IO methods, by default, often follow these symlinks, leading to unintended operations on the linked targets.

**Commons IO Contribution:**  Many `FileUtils` methods follow symlinks by default.  While `FileUtils.isSymlink` exists for detection, developers must explicitly use it and handle the results correctly to prevent attacks. This is a *direct* contribution to the attack surface.

**Example:** An application uses `FileUtils.copyFile(userUploadedFile, destination)`.  If `userUploadedFile` is a symlink pointing to `/etc/shadow`, the application might inadvertently copy the system's shadow password file.

**Impact:**
    *   Similar to path traversal: unauthorized access, modification, or deletion of files.
    *   Potential for privilege escalation.

**Risk Severity:** High

**Mitigation Strategies:**
    *   **Symlink Detection:** Use `FileUtils.isSymlink()` to *always* detect symbolic links.
    *   **Policy Enforcement:**  If symlinks are not expected, reject them.  If they *are* expected, carefully validate the target of the symlink using canonicalization (as with path traversal) to ensure it's within the allowed bounds.
    *   **Operating System Controls:** Utilize OS-level features to restrict symlink creation or following, if available.

## Attack Surface: [Resource Exhaustion (DoS via Stream Handling)](./attack_surfaces/resource_exhaustion__dos_via_stream_handling_.md)

**Description:** Attackers provide excessively large inputs (files or streams) to Commons IO methods that read entire inputs into memory, causing the application to consume excessive resources and leading to a denial-of-service.

**Commons IO Contribution:** Methods like `IOUtils.toByteArray`, `FileUtils.readFileToByteArray`, and `IOUtils.toString` *directly* read entire streams or files into memory, making them inherently vulnerable to this type of attack if input size isn't externally limited.

**Example:** An application uses `FileUtils.readFileToByteArray(userUploadedFile)` to read an uploaded file.  An attacker uploads a multi-gigabyte file, causing the application to run out of memory.

**Impact:**
    *   Application unavailability.
    *   Potential for system instability.

**Risk Severity:** High

**Mitigation Strategies:**
    *   **Input Size Limits:** Enforce strict limits on the size of files and streams that the application will process *before* passing them to Commons IO methods.
    *   **Streaming Processing:** Whenever possible, process data in chunks (using `IOUtils.copy` with a limited buffer size) instead of loading entire files into memory using the vulnerable methods.
    *   **Timeouts:** Implement timeouts for stream operations to prevent indefinite hangs.

