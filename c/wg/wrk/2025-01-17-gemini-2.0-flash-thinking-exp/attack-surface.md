# Attack Surface Analysis for wg/wrk

## Attack Surface: [Maliciously Crafted Command-Line Arguments](./attack_surfaces/maliciously_crafted_command-line_arguments.md)

*   **Description:** An attacker manipulates the command-line arguments passed to the `wrk` command.
*   **How wrk Contributes:** `wrk` relies on command-line arguments to define its behavior, including the target URL, number of connections, threads, and duration. If these arguments are derived from untrusted sources or not properly sanitized, they can be exploited.
*   **Example:** A script dynamically generates the `wrk` command using user input for the number of connections (`-c`). An attacker could input a very large number, like `100000`, leading to a denial-of-service attack against the target application or the machine running `wrk`.
*   **Impact:** Denial of Service (DoS) against the target application or the system running `wrk`, resource exhaustion.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Avoid dynamic generation of `wrk` commands with untrusted input.
    *   Strictly validate and sanitize any input used to construct `wrk` arguments, setting maximum limits for parameters.
    *   Run `wrk` with the minimum necessary privileges.

## Attack Surface: [Execution of Malicious Lua Scripts](./attack_surfaces/execution_of_malicious_lua_scripts.md)

*   **Description:** An attacker provides a malicious Lua script to the `-s` option of `wrk`.
*   **How wrk Contributes:** `wrk` allows users to execute custom Lua scripts to generate requests, process responses, and perform other actions. This powerful feature becomes a vulnerability if untrusted or malicious scripts are executed.
*   **Example:** An attacker provides a Lua script that uses the `os.execute()` function to run arbitrary commands on the system running `wrk`, such as `os.execute("rm -rf /")`.
*   **Impact:** Arbitrary code execution on the system running `wrk`, data exfiltration from the `wrk` host, local denial of service, potential for further network attacks originating from the `wrk` host.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Restrict access to Lua script execution with `wrk`.
    *   Thoroughly review all Lua scripts for potential security vulnerabilities before execution.
    *   Avoid using untrusted Lua scripts.
    *   Consider alternatives to Lua scripting if possible.
    *   Securely store Lua scripts with appropriate access controls.

