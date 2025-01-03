# Attack Surface Analysis for wg/wrk

## Attack Surface: [Execution of Malicious `wrk` Scripts](./attack_surfaces/execution_of_malicious__wrk__scripts.md)

- **Description:**  The `-s <script>` option allows loading and executing Lua scripts within the `wrk` process. Malicious scripts can perform unintended actions.
- **How `wrk` Contributes:** `wrk` provides the mechanism to execute arbitrary Lua code, extending its functionality but also introducing a significant attack vector if the script source is untrusted.
- **Example:** A developer unknowingly runs `wrk -s malicious.lua` where `malicious.lua` contains code to exfiltrate environment variables or perform network scans on the internal network.
- **Impact:** Arbitrary code execution, information disclosure, lateral movement within the network, denial-of-service on the machine running `wrk`.
- **Risk Severity:** **Critical**
- **Mitigation Strategies:**
    - **Code Review:** Thoroughly review all `wrk` scripts before execution, especially those from external or untrusted sources.
    - **Restrict Script Sources:** Only allow loading scripts from trusted and controlled locations.
    - **Sandboxing (Limited):** While Lua has some sandboxing capabilities, it's not a foolproof security measure. Be cautious even with seemingly safe scripts.
    - **Principle of Least Privilege:** Run `wrk` with the minimum necessary privileges.

## Attack Surface: [Command-Line Argument Injection](./attack_surfaces/command-line_argument_injection.md)

- **Description:** If the execution of `wrk` commands is automated or relies on user-provided input, attackers might inject malicious arguments.
- **How `wrk` Contributes:** `wrk` relies on command-line arguments for configuration, including the target URL and script path, making it susceptible to injection if these are not properly sanitized.
- **Example:** A CI/CD pipeline takes a URL from an untrusted source and uses it directly in a `wrk` command: `wrk -t 1 -c 1 -d 10s $UNTRUSTED_URL`. An attacker could inject `evil.com -s malicious.lua` leading to `wrk -t 1 -c 1 -d 10s evil.com -s malicious.lua`.
- **Impact:** Targeting unintended systems, execution of malicious scripts, denial-of-service on the target or the `wrk` host.
- **Risk Severity:** **High**
- **Mitigation Strategies:**
    - **Input Sanitization:**  Strictly sanitize and validate any user-provided input used in `wrk` commands.
    - **Parameterization:** If possible, use methods to pass parameters to `wrk` execution that avoid direct command-line injection (though `wrk` primarily relies on command-line arguments).
    - **Secure Configuration Management:** Store and manage `wrk` configurations securely, preventing unauthorized modifications.

