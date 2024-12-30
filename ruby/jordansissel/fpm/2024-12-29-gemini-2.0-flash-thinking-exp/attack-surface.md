* **Command Injection via Input Parameters**
    * **Description:** Attackers can inject arbitrary commands into the system by manipulating input parameters provided to the `fpm` command-line interface.
    * **How fpm Contributes:** `fpm` uses these input parameters to construct commands that are executed on the underlying system during package creation. If these parameters are not properly sanitized, malicious commands can be injected.
    * **Example:**  `fpm -s dir -t deb -n "my-package; touch /tmp/pwned" -v 1.0 -f .`  Here, the attacker injects `touch /tmp/pwned` into the package name, which might be executed during package processing.
    * **Impact:** Full system compromise, data exfiltration, denial of service, privilege escalation, depending on the permissions of the user running `fpm`.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Parameterization/Escaping:**  When constructing `fpm` commands programmatically, use parameterized inputs or properly escape shell metacharacters in user-provided data before passing it to `fpm`.
        * **Input Validation:**  Strictly validate all input parameters provided to `fpm` against expected values and formats. Reject any input that doesn't conform.
        * **Principle of Least Privilege:** Run `fpm` with the minimum necessary privileges to perform its task. Avoid running it as root if possible.

* **Command Execution via Hooks**
    * **Description:** Attackers can inject and execute arbitrary commands by manipulating the content of hook scripts (e.g., `--before-install`, `--after-install`).
    * **How fpm Contributes:** `fpm` executes the scripts specified by these hook options during the package building process. If the content of these scripts is derived from untrusted sources or constructed without proper sanitization, it can lead to command injection.
    * **Example:** An attacker modifies a configuration file that populates the `--before-install` script with a malicious command like `rm -rf /`. When `fpm` builds the package, this command will be executed.
    * **Impact:** Full system compromise, data loss, denial of service, privilege escalation, depending on the permissions of the user running the installation process.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Secure Hook Management:**  Ensure that the content of hook scripts is strictly controlled and not derived from untrusted sources.
        * **Code Review:**  Thoroughly review all hook scripts for potential command injection vulnerabilities.
        * **Limited Hook Usage:**  Minimize the use of hooks if possible. If hooks are necessary, ensure they perform only the required actions and avoid executing external commands where possible.

* **Path Traversal via Input Files/Directories**
    * **Description:** Attackers can access or modify files outside the intended scope by manipulating file or directory paths provided as input to `fpm`.
    * **How fpm Contributes:** `fpm` uses the provided paths to include files and directories in the generated package. If these paths are not properly validated, attackers can use techniques like `../` to traverse the file system.
    * **Example:** `fpm -s dir -t deb -n my-package -v 1.0 -f ../../../etc/passwd=/etc/my-package-passwd .` This attempts to include the system's `passwd` file in the package.
    * **Impact:** Exposure of sensitive information, modification of critical system files, potential for arbitrary code execution if combined with other vulnerabilities.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Path Sanitization:**  Thoroughly sanitize all file and directory paths provided to `fpm`. Resolve symbolic links and canonicalize paths to prevent traversal.
        * **Restricted Input Paths:**  Limit the directories from which `fpm` can read input files.
        * **Chroot Environment:** Consider running `fpm` within a chroot environment to restrict its access to the file system.

* **Unsafe Handling of Archive Contents**
    * **Description:** When using archive-based input (e.g., tar), malicious archives can contain files with path traversal vulnerabilities that are exploited during extraction by `fpm`.
    * **How fpm Contributes:** `fpm` relies on external tools to extract archive contents. If these tools or `fpm` itself doesn't properly sanitize filenames within the archive, malicious entries can overwrite files outside the intended extraction directory.
    * **Example:** A malicious tar archive contains a file named `../../../etc/cron.d/malicious_job`. When `fpm` extracts this archive, it could overwrite the system's cron configuration.
    * **Impact:** Modification of critical system files, potential for arbitrary code execution via cron jobs or other system services.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Secure Archive Extraction:**  Ensure that the archive extraction process used by `fpm` (or the underlying tools) properly sanitizes filenames and prevents path traversal.
        * **Trusted Sources:** Only use input archives from trusted sources.
        * **Archive Inspection:**  Inspect the contents of archives before processing them with `fpm`.