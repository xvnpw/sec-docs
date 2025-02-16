# Attack Surface Analysis for dalance/procs

## Attack Surface: [1. Information Disclosure: Sensitive Process Data](./attack_surfaces/1__information_disclosure_sensitive_process_data.md)

*   **Description:**  Exposure of sensitive information about running processes, including command-line arguments, environment variables, user IDs, and process paths.
    *   **How `procs` Contributes:** `procs` is the *direct mechanism* used to access this sensitive process information. The library's functions provide the capability to query and retrieve these details.
    *   **Example:** An application uses `procs.NewProc(pid)` and then accesses `.Cmdline()` or `.Environ()` to display process details in a log file or web interface. An attacker gains access to this log or interface and obtains database credentials or API keys passed as command-line arguments or environment variables.
    *   **Impact:**  Leakage of credentials, API keys, internal network configurations, leading to unauthorized access, data breaches, and potential system compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Data Minimization:**  *Never* retrieve `Cmdline()` or `Environ()` unless absolutely necessary and with a strong, documented justification.  If you only need the process name, use a safer method.
        *   **Access Control:**  Strictly control access to any functionality that uses `procs` to retrieve process details.  Only authorized users or system components should have this access.
        *   **Output Sanitization:** If, and *only if*, displaying this information is unavoidable, *always* sanitize and redact sensitive data (passwords, keys) before display. Use appropriate escaping for the output context (HTML, shell, etc.).
        *   **Least Privilege:** The application using `procs` should run with the absolute minimum necessary privileges.  Never run as root unless there's no other option.
        *   **Auditing:** Log every instance where `procs` is used to access sensitive process data (especially `Cmdline()` and `Environ()`), including the user, timestamp, and the specific data accessed.

## Attack Surface: [2. Information Disclosure: System Reconnaissance](./attack_surfaces/2__information_disclosure_system_reconnaissance.md)

*   **Description:**  Discovery of running services, software versions, and user accounts, enabling attackers to identify vulnerabilities and plan further attacks.
    *   **How `procs` Contributes:** `procs` provides the direct means to enumerate running processes, giving attackers a snapshot of the system's software and user landscape.
    *   **Example:** An application uses `procs.Processes()` to display a list of all running processes. An attacker uses this feature to identify that an outdated version of a database server (visible in the process name or path) is running, which has a known, exploitable vulnerability.
    *   **Impact:**  Facilitates targeted attacks by revealing vulnerable software and services.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Restrict Process Listing:**  Do *not* provide a feature that allows listing *all* processes to unprivileged users.  Offer only filtered views or aggregated information, if necessary.
        *   **Access Control:**  Limit access to any functionality that uses `procs.Processes()` (or similar functions) to authorized users or administrators.
        *   **Harden System:** Keep all software up-to-date. This is a general security best practice, but it directly mitigates the risk of reconnaissance by reducing the number of known vulnerabilities.

## Attack Surface: [3. Privilege Escalation (Indirect - TOCTOU)](./attack_surfaces/3__privilege_escalation__indirect_-_toctou_.md)

*   **Description:** Exploitation of race condition. Application checks process information and acts on that information, but the process state changes between the check and the action.
    *   **How `procs` Contributes:** `procs` is used to get potentially outdated process information.
    *   **Example:**
        1.  Application uses `procs` to check if process named "X" is running as user "Y".
        2.  Application confirms.
        3.  Application sends signal to process "X", assuming it's still running as "Y".
        *   **Attack:** Between steps 1 and 3, attacker terminates "X" and starts *new* process with the same name ("X") but running as "root".
    *   **Impact:** Attacker gains elevated privileges.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid TOCTOU:** Do *not* make security decisions based on potentially stale process information. Use secure inter-process communication.
        *   **Secure IPC:** Use secure inter-process communication (IPC) mechanisms.
        *   **Capabilities:** Use capabilities (on Linux) to grant specific permissions to processes.
        *   **Verification:** Re-verify process identity *immediately* before interacting with it.
        * **Least Privilege:** Ensure that even if a process is compromised, it has limited privileges.

