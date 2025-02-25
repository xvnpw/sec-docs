### Vulnerability List for Code Runner Extension

* Vulnerability Name: Arbitrary Command Execution via Executor Configuration and Filename

* Description:
    1. **Configuration Attack Vector:** The Code Runner extension allows users to customize executors for different programming languages and file types through settings like `code-runner.executorMap`, `code-runner.executorMapByGlob`, `code-runner.executorMapByFileExtension`, and `code-runner.customCommand`.
    2. A malicious actor can exploit this by tricking a user into configuring a malicious command within these settings. This could be achieved through social engineering, phishing, or by compromising the user's VS Code settings.
    3. When the user subsequently attempts to run code using the Code Runner extension for a language or file type associated with the malicious executor, or uses the custom command feature, the configured malicious command will be executed by the system instead of the intended code execution.
    4. **Filename Attack Vector:** The Code Runner extension uses configuration templates with substitution variables (e.g., `$dir`, `$fileName`, `$fileNameWithoutExt`) to build shell commands based on filenames.
    5. If an attacker can influence these variables, for example, by creating a file with a malicious name containing shell metacharacters (like `;`, `&&`, `|`, etc.), these characters are substituted into the command template without proper sanitization.
    6. When the user invokes the "Run Code" command on a file with a malicious name, the injected metacharacters break out of the intended command context, allowing the execution of arbitrary commands embedded within the filename. For example, a filename like `test.js; touch /tmp/pwned` could lead to the execution of `touch /tmp/pwned` alongside the intended code execution command.

* Impact:
    Exploiting this vulnerability can lead to arbitrary command execution on the host machine running the VS Code extension. This can result in a full system compromise, allowing an attacker to:
    - **Gain complete control of the user's system:** Execute any command with the privileges of the VS Code process.
    - **Steal sensitive data:** Access and exfiltrate files and information stored on the user's machine, including personal documents, credentials, and source code.
    - **Install malware:** Deploy viruses, trojans, ransomware, or other malicious software to further compromise the system or network.
    - **Disrupt system operations:** Modify or delete critical system files, leading to system instability, denial of service, or data corruption.
    - **Achieve persistent access:** Create new user accounts or modify existing ones to establish long-term access to the compromised system.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    None. Based on the provided information and documentation, the Code Runner extension lacks any input validation, sanitization, or security warnings related to user-configurable executor paths, custom commands, or filenames used in command construction. The extension directly uses user-provided strings and filenames as part of the commands executed by the system shell without any apparent security measures. The documentation only advises users to “take care of the back slash and the space in file path” when setting executor commands, but does not address the risks of command injection via shell metacharacters or malicious commands.

* Missing Mitigations:
    To effectively mitigate this vulnerability, the following measures are necessary:
    - **Input validation and sanitization:** Implement rigorous checks to validate and sanitize all user-provided inputs that are used in constructing shell commands. This includes:
        - **Whitelisting allowed characters:** Define a strict whitelist of allowed characters for filenames and executor paths, rejecting any input that contains characters outside of this whitelist.
        - **Blacklisting dangerous commands or patterns:** Identify and blacklist known dangerous commands or patterns in user-provided configurations.
        - **Escaping shell metacharacters:**  Properly escape shell metacharacters (e.g., `;`, `&`, `|`, `$`, `` ` ``, `\`, `!`, etc.) in filenames, executor paths, and custom commands before they are incorporated into shell commands. Use secure escaping mechanisms provided by the operating system or programming language.
    - **Secure command construction:** Instead of directly concatenating strings to build shell commands, utilize secure command building functions or APIs that prevent command injection. Consider using parameterized execution or libraries designed for safe command construction, if available in the extension's development environment.
    - **Principle of least privilege and sandboxing:** Explore options to execute code in a sandboxed environment or with reduced privileges to limit the potential impact of malicious commands. This could involve using containerization, virtualization technologies, or operating system-level security features to isolate the execution environment and restrict access to system resources.
    - **Security warnings and user education:** Display clear and prominent warning messages to the user when they are configuring custom executors or commands, explicitly highlighting the potential security risks associated with executing untrusted code or commands. Educate users about the dangers of command injection and best practices for secure configurations.

* Preconditions:
    - User must have the Code Runner extension installed in VS Code.
    - **Configuration Attack:** An attacker must be able to trick the user into modifying the Code Runner extension's settings to include a malicious command in one of the executor configuration options or custom command.
    - **Filename Attack:** An attacker must be able to introduce a file with a maliciously crafted filename into a workspace that the user opens in VS Code. This could be through:
        - Contributing to a publicly accessible repository.
        -  Shared project workspaces where file creation or renaming is possible by an attacker.
        -  Local file system access if the attacker has already compromised the user's machine to some extent.
    - The Code Runner extension's configuration must use filename parameters (like `$fileName`) in the executor command without proper sanitization for the filename attack. This is the default behavior as described in the documentation.
    - The user must execute code using the Code Runner extension, either by running a file with a malicious filename or by running code with a maliciously configured executor.

* Source Code Analysis:
    While direct source code access is unavailable, analysis based on the extension's documented functionality and configuration options reveals the likely code flow and vulnerability points:
    1. **Configuration Loading:** The extension reads executor map configurations from VS Code settings (e.g., `settings.json`).
    2. **Command Construction:** When the user executes code, the extension constructs the shell command based on:
        - The configured executor for the file's language or file type.
        - Substitution variables like `$dir`, `$fileName`, `$fileNameWithoutExt`, which are derived from the file system.
        - Potentially user-defined custom commands.
    3. **Unsafe Variable Substitution:** The extension likely performs simple string substitution or concatenation to insert these variables into the command template without any sanitization or escaping of shell-sensitive characters.
    4. **Shell Execution:** The constructed command string is then passed to a shell execution function (e.g., `child_process.exec` or `child_process.spawn` in Node.js, if the extension is JavaScript-based) for execution.

    The vulnerability stems from the **lack of input sanitization** at step 3. By directly embedding user-controlled input (executor configurations, filenames) into shell commands without proper escaping, the extension becomes vulnerable to command injection.

    **Visualization of Filename Attack Vector:**

    ```
    Malicious Filename --> Code Runner Extension --> Command Template with $fileName --> Unsafe String Interpolation --> Shell Execution (Interprets Malicious Filename Parts as Commands) --> System Compromise
    ```

    **Visualization of Configuration Attack Vector:**

    ```
    Malicious Configuration (Executor Map/Custom Command) --> Code Runner Extension --> Command Construction (Uses Malicious Configuration) --> Shell Execution (Executes Malicious Command from Configuration) --> System Compromise
    ```


* Security Test Case:
    **Test Case 1: Configuration Attack Vector**
    1. **Prepare Malicious Command:** Choose a command to verify execution, e.g., create a file named "pwned-config.txt" in the temporary directory with content "Vulnerable-Config":
        - On Linux/macOS: `bash -c "echo 'Vulnerable-Config' > /tmp/pwned-config.txt"`
        - On Windows: `cmd /c "echo 'Vulnerable-Config' > %TEMP%\pwned-config.txt"`
    2. **Configure Malicious Executor:** Open VS Code settings (JSON). Add or modify `code-runner.executorMap` to associate JavaScript with the malicious command. For Linux/macOS:
    ```json
    {
        "code-runner.executorMap": {
            "javascript": "bash -c \"echo 'Vulnerable-Config' > /tmp/pwned-config.txt\""
        }
    }
    ```
    3. **Create JavaScript File:** Create a new JavaScript file (e.g., `config_test.js`) with any code or an empty file.
    4. **Run JavaScript File:** Open `config_test.js` and execute it using Code Runner.
    5. **Verify Command Execution:** Check for "pwned-config.txt" in the temporary directory (`/tmp/` or `%TEMP%`) and verify it contains "Vulnerable-Config".

    **Test Case 2: Filename Attack Vector**
    1. **Set up Test Environment:** Install VS Code and Code Runner.
    2. **Create Malicious File:** Create a new directory, e.g., `test-filename-injection`. Inside, create a JavaScript file named `vuln.js; touch /tmp/pwned-filename.txt`. (Filename contains command injection).
    3. **Open Workspace:** Open the `test-filename-injection` directory as a VS Code workspace.
    4. **Configure Executor (if necessary):** Ensure Code Runner uses `$fileName` in the JavaScript executor. Default configurations often do, but verify or set in `settings.json`:
       ```json
       {
           "code-runner.executorMap": {
               "javascript": "node $fileName"
           }
       }
       ```
    5. **Execute Malicious File:** Open `vuln.js; touch /tmp/pwned-filename.txt` and run it using Code Runner.
    6. **Verify Command Execution:** Check if `/tmp/pwned-filename.txt` exists in the `/tmp` directory.
    7. **Expected Result (for both test cases):** If the "pwned" files are created with the expected content, it confirms arbitrary command execution, demonstrating the vulnerability via configuration and filename respectively.