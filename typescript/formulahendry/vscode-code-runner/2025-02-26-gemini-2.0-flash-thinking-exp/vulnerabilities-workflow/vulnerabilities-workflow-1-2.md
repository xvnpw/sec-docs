- **Vulnerability Name:** Arbitrary Command Execution via Unsanitized Shebang Parsing  
  **Description:**  
  When no explicit language is provided, the extension checks the first line of the file for a shebang line if the “respectShebang” setting is enabled (the default behavior). In the `getExecutor` method, if the first line matches the regex `/^#!(?!\[)/`, the extension simply strips off the “#!” and uses the rest as the executor command. An attacker can craft a file whose first line is a malicious shebang (for example, including shell metacharacters or dangerous commands) so that when a user opens the file and triggers the “Run Code” command, the extension will execute that unsanitized command using the system shell.  
  **Impact:**  
  Arbitrary command execution on the victim’s machine can be achieved. If an attacker’s file is executed, they may run arbitrary system commands, leading to full system compromise or data exfiltration.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  - The setting “respectShebang” is enabled by default to support legitimate shebang use.  
  - No additional sanitization or validation is performed on the shebang content.  
  **Missing Mitigations:**  
  - Validate and sanitize the contents of the shebang line before using it as an executor.  
  - Consider requiring explicit opt-in to execute shebang commands or implementing a whitelist of allowed commands.  
  **Preconditions:**  
  - The file to be run must have a first line beginning with `#!` that specifies a command.  
  - The user must run that file with the “Run Code” command without overriding the “respectShebang” setting.  
  **Source Code Analysis:**  
  - In `src/codeManager.ts`, the `getExecutor` method (around the lines checking `if (/^#!(?!\[)/.test(firstLineInFile))`) takes the unsanitized string following “#!” as the executor.  
  - This value is later passed into the helper function `getFinalCommandToRunCodeFile` and ultimately handed off to `child_process.spawn` with `shell: true`, without any verification.  
  **Security Test Case:**  
  1. Create a test file (e.g., `malicious.txt`) with a first line such as:  
     ```
     #!/bin/bash -c "echo 'Exploited: Arbitrary code execution' && <malicious command>"
     ```  
  2. Open this file in VS Code.  
  3. Trigger the “Run Code” command.  
  4. Observe that the command from the shebang is executed directly in the shell (for example, the output shows that the malicious payload ran).  
  5. Verify that proper warnings or lack of sanitization confirm the existence of the vulnerability.

- **Vulnerability Name:** Arbitrary Command Execution via Workspace Configuration Injection  
  **Description:**  
  The extension relies on executor commands defined in workspace/user settings (such as in `executorMap` or via the `customCommand` setting) without performing any sanitization of the command strings. An attacker who is able to supply or modify a project’s workspace settings (for example, by committing a malicious `.vscode/settings.json` to a repository) can inject a malicious command. When a user opens the project in VS Code and later triggers a run command (for example, “Run Custom Command”), the extension will use the malicious configuration value directly to construct and execute the shell command.  
  **Impact:**  
  This can lead to arbitrary command execution on the developer’s machine in a scenario where untrusted workspace settings are loaded. An attacker could thereby compromise the victim’s system or access sensitive information.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  - The extension reads configuration values (such as `customCommand` and entries in `executorMap`) directly from the workspace settings without any additional filtering or validation.  
  **Missing Mitigations:**  
  - Validate and sanitize all configuration-provided command strings before processing.  
  - Consider enforcing a whitelist of allowed executors or warning the user before executing commands imported from workspace settings.  
  **Preconditions:**  
  - The target project’s workspace (or repository) contains malicious or tampered configuration values for executor commands.  
  - The victim opens this workspace in VS Code and executes a command that relies on these settings.  
  **Source Code Analysis:**  
  - In the `getExecutor` method of `src/codeManager.ts`, the extension retrieves commands from settings without sanitization.  
  - Later, in `getFinalCommandToRunCodeFile`, these values are used for placeholder replacement and then passed to `child_process.spawn` with `shell: true`, making the overall execution flow vulnerable to injection.  
  **Security Test Case:**  
  1. Create a test workspace that includes a `.vscode/settings.json` with the following content:  
     ```json
     {
       "code-runner.customCommand": "echo harmless && echo 'Malicious code executed'"
     }
     ```  
  2. Open the workspace in VS Code.  
  3. Trigger the “Run Custom Command” command.  
  4. Observe that the command is executed exactly as injected (for example, look for both the “harmless” and the “Malicious code executed” outputs).  
  5. Confirm that the unsanitized configuration value leads directly to command injection.

- **Vulnerability Name:** Predictable Temporary File Race Condition  
  **Description:**  
  When running selected code snippets (as opposed to whole files), the extension creates a temporary file for execution. The filename is generated using a noncryptographic random string via `Math.random()` (via the helper function `rndName()`) or a custom configuration value (`temporaryFileName`). Because the randomness is low entropy and the file creation does not use secure methods, an attacker who has write access to the temporary directory (typically returned by `os.tmpdir()`) may be able to predict the temporary file name. The attacker might pre-create a symlink or file at that path so that when the extension writes the snippet’s contents (or later executes it), it overwrites or redirects to an unintended destination.  
  **Impact:**  
  An attacker exploiting this weakness could potentially overwrite sensitive files or redirect execution to an attacker-controlled file. In multi-user environments where the temp directory is shared, this can lead to local privilege escalation or unintended code execution.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - A random string is appended to the temporary file name, but it is derived directly from `Math.random()` and no atomic file-creation mechanism is used.  
  **Missing Mitigations:**  
  - Use a cryptographically secure random generator for temporary file naming.  
  - Employ a safe temporary file creation API that atomically creates a file (or fails if the file already exists) rather than simply constructing a predictable file name and writing to it.  
  **Preconditions:**  
  - The attacker must have write access to the temporary directory on the victim’s machine.  
  - The attacker must be able to predict or preempt the temporary file name (or configure a malicious value for `temporaryFileName` via workspace settings).  
  **Source Code Analysis:**  
  - In `src/codeManager.ts`, the method `createRandomFile` constructs a file name by using either the `temporaryFileName` configuration or concatenating `"temp"` with a value generated by `rndName()`.  
  - The function `rndName()` calls `Math.random().toString(36)` and formats the result, yielding a low-entropy, predictable string.  
  - The file is then written with `fs.writeFileSync` without any checks for preexistence or race conditions.  
  **Security Test Case:**  
  1. In an environment where you can write to the system’s temporary directory, determine the predictable pattern used by Code Runner (e.g. by observing several generated file names).  
  2. Pre-create a symbolic link (or a malicious file) in the temporary directory at a path matching the likely filename (using the default naming convention).  
  3. Run a code snippet that causes Code Runner to create its temporary file.  
  4. Verify whether the extension writes to the symlinked location and whether the malicious file is overwritten or executed instead of the intended temporary file.  
  5. Confirm that the filename can be predicted and exploited, demonstrating the race condition.