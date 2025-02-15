# Attack Surface Analysis for javan/whenever

## Attack Surface: [Arbitrary Command Execution via `schedule.rb` Injection](./attack_surfaces/arbitrary_command_execution_via__schedule_rb__injection.md)

  *   **Description:** An attacker injects malicious commands into the `schedule.rb` file, which are then executed by the cron daemon. This is the most critical vulnerability *directly* related to `whenever`.
    *   **How `whenever` Contributes:** `whenever` *directly* translates the contents of `schedule.rb` into cron commands. It performs *no* sanitization or validation. This is its core function, and thus the core risk.
    *   **Example:**
        ```ruby
        # schedule.rb (Vulnerable)
        every 1.day do
          command "echo #{params[:unsafe]}"  # Unsanitized input directly into a command
        end
        ```
        An attacker controlling `params[:unsafe]` can execute arbitrary commands.
    *   **Impact:** Complete system compromise. The attacker gains the privileges of the user running the cron job.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Input Validation (Application-Level):** The application *must* rigorously validate and sanitize *any* input used within the `schedule.rb` file, especially if that input comes from external sources. This is the *primary* defense, even though it's application-level, because `whenever` provides *no* protection.
        *   **Avoid `command` Where Possible:** Prefer `runner` and `rake` over `command`. These are *slightly* less prone to shell injection (but *still* require input validation). This is a `whenever`-specific mitigation.
        *   **Code Review:** Thoroughly review `schedule.rb` for injection points.

## Attack Surface: [Privilege Escalation via Insecure `sudo` Usage (within `schedule.rb`)](./attack_surfaces/privilege_escalation_via_insecure__sudo__usage__within__schedule_rb__.md)

    *   **Description:** A scheduled task defined *within `schedule.rb`* uses `sudo` without proper restrictions, allowing an attacker to gain elevated privileges.
    *   **How `whenever` Contributes:** `whenever` allows the definition of tasks that use `sudo` *within the `schedule.rb` file*. The security depends on the `sudoers` configuration *and* how `whenever` is used to call `sudo`.
    *   **Example:**
        ```ruby
        # schedule.rb (Vulnerable)
        every 1.hour do
          command "sudo /usr/local/bin/my_script.sh" # sudoers allows this, but script is vulnerable
        end
        ```
    *   **Impact:** The attacker gains root privileges (or the privileges granted by the `sudoers` configuration).
    *   **Risk Severity:** **Critical** (if `sudo` grants root), **High** (if other elevated privileges)
    *   **Mitigation Strategies:**
        *   **Restrictive `sudoers`:** The `sudoers` file should *only* allow the *specific* commands needed, with *no* wildcards or user-supplied arguments. This is crucial when using `sudo` *within* a `whenever` task.
        *   **Principle of Least Privilege:** Avoid using `sudo` at all within `schedule.rb` if possible.
        * **Avoid command:** If possible use runner or rake.

