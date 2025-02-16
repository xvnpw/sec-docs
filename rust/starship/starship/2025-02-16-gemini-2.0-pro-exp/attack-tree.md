# Attack Tree Analysis for starship/starship

Objective: Execute Arbitrary Code OR Exfiltrate Sensitive Information via Starship

## Attack Tree Visualization

Goal: Execute Arbitrary Code OR Exfiltrate Sensitive Information via Starship

├── 1.  Exploit Vulnerabilities in Starship's Code
│   ├── 1.1  Vulnerability in Module Parsing/Execution
│   │   ├── 1.1.1  Crafted Input to a Specific Module (e.g., `custom` commands, `env_var`, `directory`)
│   │   │   ├── 1.1.1.1  Command Injection:  Module improperly sanitizes input, allowing execution of shell commands. [CRITICAL]
│   │   │   │   └── Action:  Provide malicious input designed to trigger command execution within the module's logic.  Example:  Setting a malicious `STARSHIP_CUSTOM_MYMODULE_COMMAND` environment variable.
│
└── 2.  Exploit Misconfigurations [HIGH RISK]
    ├── 2.1  Overly Permissive `custom` Commands [HIGH RISK]
    │   └── 2.1.1  Unsanitized User Input in `custom` Command: [CRITICAL]
    │       └── Action:  Set the relevant environment variable to a malicious payload (e.g., `"; rm -rf /; #"`).
    ├── 2.2  Insecure `env_var` Configuration [HIGH RISK]
    │   └── 2.2.1  Displaying Sensitive Environment Variables: [CRITICAL]
    │       └── Action:  Simply view the prompt to exfiltrate the sensitive information.  This is a data exfiltration attack, not code execution.

## Attack Tree Path: [Exploit Vulnerabilities in Starship's Code](./attack_tree_paths/exploit_vulnerabilities_in_starship's_code.md)

*   **1.1 Vulnerability in Module Parsing/Execution**
    *   **1.1.1 Crafted Input to a Specific Module**
        *   **1.1.1.1 Command Injection [CRITICAL]**
            *   **Description:** This attack exploits a vulnerability where a Starship module (especially `custom` commands, but potentially others handling environment variables or directory paths) fails to properly sanitize user-provided input before using it in a shell command. This allows an attacker to inject arbitrary shell commands, which are then executed by the user's shell.
            *   **Action:** The attacker crafts malicious input, often by setting an environment variable or manipulating a directory name, that contains shell metacharacters (e.g., `;`, `|`, `` ` ``, `$()`). When Starship processes this input and incorporates it into a shell command without proper escaping, the injected commands are executed.
            *   **Example:** If a `custom` command uses an environment variable `MY_VAR` without sanitization:
                *   Attacker sets: `MY_VAR="; rm -rf /; #"`
                *   Starship executes (effectively): `some_command "$MY_VAR"` which becomes `some_command "; rm -rf /; #"`, leading to the execution of `rm -rf /`.
            *   **Likelihood:** Low (Assuming reasonable coding practices in Rust, but higher if `unsafe` is used improperly or shell commands are built via string concatenation)
            *   **Impact:** High (Arbitrary code execution on the user's system)
            *   **Effort:** Medium (Requires finding a vulnerable module and crafting the exploit)
            *   **Skill Level:** Intermediate to Advanced (Understanding of shell scripting, command injection techniques, and the specific module's logic)
            *   **Detection Difficulty:** Medium to Hard (May be detected by security tools monitoring shell activity, but could be obfuscated)

## Attack Tree Path: [Exploit Misconfigurations](./attack_tree_paths/exploit_misconfigurations.md)

*   **2.1 Overly Permissive `custom` Commands [HIGH RISK]**
    *   **2.1.1 Unsanitized User Input in `custom` Command [CRITICAL]**
        *   **Description:** This is a specific, and very common, instance of command injection that occurs due to user misconfiguration.  The user defines a `custom` command in their `starship.toml` that uses unsanitized user input (typically from environment variables).
        *   **Action:** The attacker sets the environment variable used by the `custom` command to a malicious payload containing shell commands. When Starship renders the prompt, it executes the `custom` command, including the attacker's injected code.
        *   **Example:**
            *   `starship.toml`:
                ```toml
                [custom.my_command]
                command = "echo $MY_VAR"
                ```
            *   Attacker sets: `MY_VAR="; whoami"`
            *   When the prompt is rendered, `whoami` is executed.
        *   **Likelihood:** Medium to High (This is a common mistake, especially for users who are not security-conscious)
        *   **Impact:** High (Arbitrary code execution)
        *   **Effort:** Very Low (Simply set a malicious environment variable)
        *   **Skill Level:** Novice (Basic understanding of shell scripting)
        *   **Detection Difficulty:** Medium (May be detected by security tools monitoring shell activity, but could be obfuscated)

*   **2.2 Insecure `env_var` Configuration [HIGH RISK]**
    *   **2.2.1 Displaying Sensitive Environment Variables [CRITICAL]**
        *   **Description:** The user configures Starship to display sensitive environment variables (e.g., API keys, passwords, secret tokens) directly in the prompt. This exposes these secrets to anyone who can see the user's terminal.
        *   **Action:** The attacker simply views the user's terminal (either directly or through a screen sharing session, shoulder surfing, or a compromised terminal recording).  No code execution is required; this is purely an information disclosure vulnerability.
        *   **Example:**
            *   `starship.toml`:
                ```toml
                [env_var]
                variable = "MY_SECRET_API_KEY"
                ```
            *   The prompt will display the value of `MY_SECRET_API_KEY`.
        *   **Likelihood:** Medium (Users may not realize the security implications)
        *   **Impact:** Medium to High (Exposure of sensitive information)
        *   **Effort:** Very Low (Simply view the prompt)
        *   **Skill Level:** Novice
        *   **Detection Difficulty:** Very Easy (The sensitive information is displayed directly in the prompt)

