# Attack Surface Analysis for sharkdp/fd

## Attack Surface: [Path Traversal via File Paths Passed to `fd`](./attack_surfaces/path_traversal_via_file_paths_passed_to__fd_.md)

* **Description:** Path Traversal via File Paths Passed to `fd`
    * **How `fd` Contributes:** `fd` directly operates on file paths provided to it. If an application constructs these paths based on untrusted input and passes them to `fd`, it can be tricked into accessing files outside the intended scope.
    * **Example:** An application allows users to search for files within a specified directory. If a user provides an input like `../../../../etc/passwd`, and the application naively constructs the path for `fd`, `fd` might attempt to access the system's password file.
    * **Impact:** Unauthorized access to sensitive files or directories, potentially leading to information disclosure, data breaches, or even system compromise depending on the accessed files.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Implement strict input validation and sanitization on any user-provided data used to construct file paths passed to `fd`.
        * Use canonicalization techniques to resolve symbolic links and ensure paths stay within the intended boundaries before passing them to `fd`.
        * Employ chroot jails or similar sandboxing techniques to restrict `fd`'s access to specific parts of the file system.

## Attack Surface: [Command Injection via `fd`'s `-x`/`--exec` or `-X`/`--exec-batch` Options](./attack_surfaces/command_injection_via__fd_'s__-x__--exec__or__-x__--exec-batch__options.md)

* **Description:** Command Injection via `fd`'s `-x`/`--exec` or `-X`/`--exec-batch` Options
    * **How `fd` Contributes:** The `-x` and `-X` options allow `fd` to execute arbitrary commands on the system. If the application constructs the command string based on untrusted input, an attacker can inject malicious commands.
    * **Example:** An application allows users to perform actions on found files. If the application constructs the command for `-x` like `fd ... -x mv {} user_provided_destination`, a malicious user could input `; rm -rf /` as `user_provided_destination`, leading to the execution of `rm -rf /`.
    * **Impact:** Full system compromise, data deletion, installation of malware, or any other action the application's user has permissions to perform.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Avoid using `-x` or `-X` with untrusted input if at all possible.**
        * If `-x` or `-X` is necessary, implement extremely strict input validation and sanitization. Whitelist allowed characters and patterns.
        * Prefer using safer alternatives to shell execution if the desired functionality can be achieved through other means.
        * If using `-x` or `-X`, consider using parameterized commands or escaping shell metacharacters carefully, although this is complex and error-prone.

