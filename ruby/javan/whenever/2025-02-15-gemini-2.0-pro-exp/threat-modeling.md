# Threat Model Analysis for javan/whenever

## Threat: [Privilege Escalation via Root Execution](./threats/privilege_escalation_via_root_execution.md)

*   **Threat:** Jobs running as root.
*   **Description:** `Whenever` is configured to execute jobs as the `root` user.  If an attacker can influence the commands executed by these jobs (even indirectly, through a vulnerability in a script *called by* the `whenever` job), they gain full control of the system. The attacker doesn't necessarily need to modify `schedule.rb` directly; any vulnerability in code executed by a root-level cron job is a potential escalation path.
*   **Impact:** Complete system compromise. The attacker has full administrative access.
*   **Affected Component:** The `job_type` definitions and overall configuration within `schedule.rb` that determine the user context. Specifically, any job defined *without* an explicit `:user` option, or with `:user => 'root'`, is vulnerable. The `Whenever::CommandLine` class, which generates the crontab, is directly involved.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:** *Never* run jobs as root.  Create a dedicated, unprivileged user account and use the `:user` option in `whenever` for *all* job types.
    *   **Strict File Permissions:** Ensure `schedule.rb` and related scripts have restrictive permissions.
    *   **Code Review:** Mandatory code reviews for all changes to `schedule.rb`.

## Threat: [Command Injection in `schedule.rb`](./threats/command_injection_in__schedule_rb_.md)

*   **Threat:** Injection of malicious commands.
*   **Description:** An attacker gains the ability to modify the `schedule.rb` file. They inject arbitrary shell commands into the job definitions, which `whenever` then translates into crontab entries. These commands are executed by `cron` with the privileges of the configured user (which, if not properly mitigated, could be root).
*   **Impact:** Arbitrary command execution with the privileges of the user running the job. This could lead to data theft, system modification, or denial of service.
*   **Affected Component:** The `schedule.rb` file itself. Any `job_type` or custom job definition that uses string interpolation or concatenation without proper sanitization (within the `schedule.rb` file) is vulnerable. The `Whenever::CommandLine` class, which parses and processes `schedule.rb`, is directly involved in translating the (potentially malicious) definitions into cron commands.
*   **Risk Severity:** High (Critical if jobs run as root)
*   **Mitigation Strategies:**
    *   **Secure Code Repository:** Use a secure repository with strong access controls and MFA.
    *   **Code Reviews:** Mandatory code reviews, focusing on preventing command injection *within the `schedule.rb` file*.
    *   **File Integrity Monitoring (FIM):** Use FIM to detect unauthorized changes to `schedule.rb`.

## Threat: [Information Disclosure via Insecure Output Handling (If Cron Emails)](./threats/information_disclosure_via_insecure_output_handling__if_cron_emails_.md)

*   **Threat:** Exposure of sensitive data via cron's default email behavior.
*   **Description:** `Whenever` generates cron jobs. By default, cron sends the output (stdout and stderr) of *any* job that produces output to the user account that owns the crontab. If this output contains sensitive information (passwords, API keys, etc.), and the email configuration is not secure, this information is exposed. This is a direct consequence of how `whenever` interacts with cron.
*   **Impact:** Data breach. Sensitive information is exposed, potentially leading to further attacks.
*   **Affected Component:** The interaction between `whenever`-generated jobs and cron's default output handling (specifically, the emailing of output). The `Whenever::Job::Base` class and its subclasses, which could potentially handle output redirection, are relevant.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid Logging Sensitive Data:** The *best* mitigation is to ensure that jobs *never* output sensitive information.
    *   **Redirect Output:** Within `schedule.rb`, explicitly redirect standard output and standard error to `/dev/null` for jobs that don't require output to be monitored. Use `output: { error: '/dev/null', standard: '/dev/null' }` in your job definitions.
    *   **Disable Cron Email (System-Wide):** Configure the cron daemon itself *not* to send emails for job output. This is a system-level configuration, not directly within `whenever`, but it's a crucial mitigation for this `whenever`-related threat. This is often done by setting `MAILTO=""` in the crontab or system-wide cron configuration.
    *  **Secure Cron Email:** If email is absolutely required, configure cron to send emails securely (e.g., using a properly configured MTA with TLS) and only to a secure, monitored mailbox.

