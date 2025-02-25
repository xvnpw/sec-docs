- **Vulnerability Name:** Command Injection via Unsanitized Variable Substitution in Executor Map

  - **Description:**
    The Code Runner extension uses configuration templates (provided in settings such as the “executorMap”) that include substitution variables (e.g. `$dir`, `$fileName`, `$fileNameWithoutExt`) to build shell commands. These command templates are defined in user configuration files and are executed as entered. If an attacker is able to influence these variables—by, for example, creating or renaming a file in a publicly accessible project workspace with malicious characters—the injected metacharacters (such as `;` or `&&`) may break out of the intended command context and cause additional commands to be executed. An adversary could then trigger arbitrary command execution by having a user invoke the “Run Code” command on such a file.

  - **Impact:**
    Exploiting this vulnerability can cause arbitrary commands to be executed on the host machine running the extension. This could lead to full system compromise, unauthorized data access or modification, and other forms of system abuse.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    The project documentation only advises users to “take care of the back slash and the space in file path” when setting executor commands. There is no mention of sanitizing or escaping shell metacharacters in the substituted variables. In the absence of evidence of secure command-building routines, the variable substitution appears to be unsanitized.

  - **Missing Mitigations:**
    The extension lacks proper sanitization and escaping for values injected into shell commands. Mitigations that need to be implemented include:
    - Validating and strictly filtering the characters allowed in filenames or directory paths.
    - Escaping shell metacharacters before substituting them into command templates.
    - Using secure command building functions or APIs instead of simple string substitution.

  - **Preconditions:**
    - An attacker must have a way to inject or influence file names (or other substituted variables) in the workspace. This may occur in publicly accessible repositories or in setups where contributions are allowed without stringent filtering on file names.
    - The user (or developer) must trigger the “Run Code” command for a file that has a maliciously crafted name.

  - **Source Code Analysis:**
    - The README examples show executor command templates such as:
      ```
      "java": "cd $dir && javac $fileName && java $fileNameWithoutExt"
      ```
      This indicates that the extension assembles the command by directly substituting variables from the file system.
    - Suppose a file is given a malicious name (e.g., `example; echo hacked`); the command after substitution would resemble:
      ```
      cd [directory] && javac example; echo hacked && java [fileNameWithoutExt]
      ```
      The shell would interpret the semicolon as a separator and execute `echo hacked` as a separate command.
    - Although the actual source code is not provided here, the documented behavior implies that there is no in‑depth sanitization step applied to the substituted variables. This makes the command string vulnerable to injection if the file name (or directory path) is attacker-controlled.

  - **Security Test Case:**
    1. In a controlled test environment, create a file in the workspace with a malicious name—for example:
       ```
       malicious; echo hacked > /tmp/hacked.txt
       ```
       (On Windows, you may adjust the injected command to a suitable payload.)
    2. Open the malicious file in VS Code.
    3. Trigger the “Run Code” command for a language whose executor command (from the README) uses the `$fileName` variable—for instance, the Java executor.
    4. Observe the behavior on the host system. Check whether the injected command causes the payload to execute (for example, verify that the file `/tmp/hacked.txt` is created or that “hacked” appears in the output).
    5. If the injected payload executes, this confirms that an attacker can leverage unsanitized variable substitution to execute arbitrary shell commands.