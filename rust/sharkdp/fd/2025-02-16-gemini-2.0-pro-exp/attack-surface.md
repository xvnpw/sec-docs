# Attack Surface Analysis for sharkdp/fd

## Attack Surface: [Symbolic Link Traversal](./attack_surfaces/symbolic_link_traversal.md)

*   **Description:** `fd` can follow symbolic links, potentially leading to unintended file access.
*   **How `fd` Contributes:** `fd`'s default behavior is to follow symbolic links.
*   **Example:** A malicious symlink points to `/etc/passwd`. `fd` lists the contents of `/etc/passwd` if run with sufficient privileges.
*   **Impact:** Information disclosure, potential privilege escalation (if `fd`'s output is used to modify files), denial of service (if circular links are encountered, though `fd` has built-in protection).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use the `--no-follow` option to disable symbolic link following.
    *   Run `fd` with the least necessary privileges.
    *   Carefully audit the environment where `fd` is used for malicious symlinks.
    *   If the output of `fd` is used to perform actions on files, validate the file type (e.g., check if it's a symlink) before acting.

## Attack Surface: [Command Injection via `--exec` / `-x`](./attack_surfaces/command_injection_via__--exec____-x_.md)

*   **Description:** Unsafe construction of commands using the `--exec` option can lead to arbitrary code execution.  This is a direct vulnerability *because* `fd` provides the mechanism for executing the potentially injected command.
*   **How `fd` Contributes:** The `--exec` option allows executing a command for each matched file, providing a direct mechanism for command injection if misused.
*   **Example:** `fd -e txt --exec "echo $(cat {})"` (if a file contains shell metacharacters, they will be executed).  A safer alternative is `fd -e txt --exec cat {}`. A *very* dangerous example: `fd -e txt --exec "rm -rf $UNTRUSTED_INPUT"` where `$UNTRUSTED_INPUT` comes from an external source.
*   **Impact:** Arbitrary code execution, complete system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid `--exec` with untrusted input:** Never construct the command string directly from user input or any other untrusted source.
    *   **Use placeholders correctly:** Use the `{}` placeholder *only* for the filename, and do not embed any other variable data within the command string.
    *   **Prefer safer alternatives:** Use `xargs` (with appropriate delimiters like `-0`) or a programming language's built-in file handling capabilities instead of shell commands whenever possible.  This provides much better control and avoids shell injection vulnerabilities.
    *   **Input sanitization (as a last resort):** If you *must* use external input, rigorously sanitize it to remove any potentially dangerous characters.  However, this is error-prone and should be avoided if at all possible.

