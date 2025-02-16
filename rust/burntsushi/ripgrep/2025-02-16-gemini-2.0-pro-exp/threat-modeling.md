# Threat Model Analysis for burntsushi/ripgrep

## Threat: [Command Injection via `--pre` option](./threats/command_injection_via__--pre__option.md)

*   **Description:** An attacker provides malicious input that is directly incorporated into the `--pre` option of the `ripgrep` command *as executed by the application*.  `ripgrep` then executes this attacker-controlled command as a preprocessor on files before searching them. This is a direct exploitation of `ripgrep`'s intended functionality, but in a malicious way due to improper input handling by the calling application.
*   **Impact:** Complete system compromise. The attacker gains the ability to execute arbitrary commands with the privileges of the user running the `ripgrep` process. This could lead to data theft, data modification, system takeover, and lateral movement.
*   **Ripgrep Component Affected:** `ripgrep`'s internal command-line argument parsing and the execution logic for the `--pre` option, specifically the code that spawns the preprocessor subprocess.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Disable `--pre`:** The most secure option is to completely disallow the use of the `--pre` option within the application.
    *   **Strict Whitelisting (if `--pre` is essential):** Implement a very strict whitelist of allowed preprocessor commands.  *Never* allow the user to directly specify the command.
    *   **Input Sanitization (secondary defense):** Sanitize any user input passed as arguments to the whitelisted preprocessor. Use a library for safe command-line argument construction.
    *   **Least Privilege:** Run `ripgrep` (and the preprocessor) with the lowest possible privileges.
    *   **Sandboxing/Containerization:** Run `ripgrep` (and the preprocessor) within a container or sandbox.

## Threat: [Command Injection via `--search-zip` option (Indirect, Exploiting Decompression Utility)](./threats/command_injection_via__--search-zip__option__indirect__exploiting_decompression_utility_.md)

*   **Description:** An attacker provides a malicious path to a crafted "zip" file. When `ripgrep` is invoked with the `--search-zip` option, it uses an external decompression utility.  The attacker exploits a vulnerability *in that external utility*, triggered by the malicious archive. This is indirect command injection; `ripgrep` is the vector, but the vulnerability is in another program.
*   **Impact:**  Potentially high, depending on the vulnerability in the decompression utility. Could range from denial of service to arbitrary code execution.
*   **Ripgrep Component Affected:** `ripgrep`'s code that handles the `--search-zip` option and invokes the external decompression utility. The vulnerability itself is *not* in `ripgrep`.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable `--search-zip`:** If searching within compressed archives is not essential, disable this option.
    *   **Controlled Input:** If `--search-zip` is needed, *strictly* control the paths that `ripgrep` can access. Do *not* allow arbitrary file paths from users.
    *   **Sandboxing/Containerization:** Isolate the `ripgrep` process (and the decompression utility).
    *   **Keep Decompression Utilities Updated:** Ensure that the system's decompression utilities are up-to-date with security patches.
    *   **Input Validation (Limited):** Validate the *path* to ensure it's within the allowed directory and has a whitelisted extension.

## Threat: [Denial of Service via Catastrophic Backtracking Regex](./threats/denial_of_service_via_catastrophic_backtracking_regex.md)

*   **Description:** An attacker provides a regular expression that, when processed by `ripgrep`'s regex engine (either PCRE2 or Rust's `regex` crate), causes excessive CPU and memory consumption due to catastrophic backtracking. This is a direct attack on `ripgrep`'s regex processing capabilities.
*   **Impact:** Denial of Service. `ripgrep` becomes unresponsive, consuming excessive resources and preventing legitimate searches.
*   **Ripgrep Component Affected:** The regex engine used by `ripgrep` (PCRE2 or Rust's `regex` crate).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Regex Complexity Limits:** Use a regex engine with built-in protections against catastrophic backtracking (Rust's `regex` crate has some). Consider using a regex complexity analyzer/limiter.
    *   **Input Length Limits:** Impose a reasonable limit on the length of user-provided regular expressions.
    *   **Timeouts:** Implement timeouts for `ripgrep` processes. Terminate searches that take too long.
    *   **Resource Quotas:** Use OS features or containerization to limit CPU and memory for the `ripgrep` process.

