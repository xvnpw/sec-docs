# High-Risk Vulnerabilities in Live Server Extension

## Unsanitized Command Execution via Malicious Workspace Browser Settings

- **Description:**  
  When a user opens a workspace that comes with a manipulated .vscode/settings.json file, an attacker can supply malicious values for browser‐launch settings (for example, `liveServer.settings.AdvanceCustomBrowserCmdLine` or `liveServer.settings.CustomBrowser`). The extension reads these configuration values without validating or sanitizing them. Later, when the user invokes "Go Live", the extension's `openBrowser` method uses the unsanitized configuration to construct command‑line parameters that are handed over to the external "opn" library. Because these values are directly injected into the parameters for executing a browser client, an attacker can force the extension to execute arbitrary operating system commands on the user's machine.

- **Impact:**  
  Successful exploitation could result in remote code execution on the victim's system. An attacker, by providing a repository with a corrupted workspace settings file, could execute arbitrary commands (for example, installing malware, deleting files, or any system command) when the user activates the Live Server extension. This directly compromises the integrity and security of the victim's machine.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  - The extension reads configuration values via the VSCode API (using `workspace.getConfiguration('liveServer.settings')`), assuming that the user trusts the workspace settings.  
  - There is an implicit assumption that the workspace (or repository) is safe; no explicit validation or sanitization is performed on the values retrieved.

- **Missing Mitigations:**  
  - There is no input validation or sanitization for configuration values that control command‐line arguments.  
  - No whitelist or strict enumeration is enforced on allowed values for `AdvanceCustomBrowserCmdLine` or `CustomBrowser`.  
  - The extension does not verify that the parameters conform to a safe, predefined list before passing them to the external process spawning mechanism.

- **Preconditions:**  
  - The victim opens a repository whose workspace settings (typically in .vscode/settings.json) have been maliciously altered by an attacker.  
  - The malicious configuration sets a custom browser command line (using either `liveServer.settings.AdvanceCustomBrowserCmdLine` or `liveServer.settings.CustomBrowser`) to include additional arguments or commands.
  - The Live Server extension is activated (for example, when the user clicks "Go Live"), thereby using the manipulated configuration.

- **Source Code Analysis:**  
  - **Configuration Extraction:** In `Config.ts`, the extension retrieves settings with calls such as:  
    `public static get getAdvancedBrowserCmdline(): string { return Config.getSettings<string>('AdvanceCustomBrowserCmdLine'); }`  
    This value (originating from the workspace) is not validated.
  - **Parameter Construction:** In the `openBrowser` method (found in `appModel.ts`), the code first checks if an advanced custom command line is present:  
    ```typescript
    let advanceCustomBrowserCmd = Config.getAdvancedBrowserCmdline;
    if (advanceCustomBrowserCmd) {
        advanceCustomBrowserCmd.split('--').forEach((command, index) => {
            if (command) {
                if (index !== 0) command = '--' + command;
                params.push(command.trim());
            }
        });
    }
    ```  
    Here, the string from the settings is split on the token `"--"` and reassembled into an array (`params`). No sanitization is performed.
  - **Command Execution:** Later, the code calls the external library "opn" to open a URL with the provided app parameters:  
    ```typescript
    require('opn')(`${protocol}://${host}:${port}/${path}`, { app: params || [''] });
    ```  
    Since the parameters come directly from the unsanitized configuration value, an attacker–controlled string can constitute part of the command executed by the operating system.
  - **Conclusion:** By not validating or sanitizing the configuration values, the extension inadvertently allows an attacker to inject arbitrary parameters (and possibly force the execution of unintended commands) when the browser is launched.

- **Security Test Case:**  
  1. **Preparation:**  
     - Create a test repository that includes a `.vscode/settings.json` file containing a malicious Live Server setting. For example:
       ```json
       {
         "liveServer.settings.AdvanceCustomBrowserCmdLine": "chrome --incognito --execute \"echo MALICIOUS_EXECUTION > /tmp/malicious.txt\""
       }
       ```
       *(Note: In a safe test environment, replace the command with one that logs a harmless message or creates a marker file.)*
  2. **Deployment:**  
     - Open the malicious repository in VSCode so that the workspace settings are loaded by the Live Server extension.
  3. **Triggering the Vulnerability:**  
     - Use the command palette or click the "Go Live" button to start the Live Server.
     - The extension calls the `openBrowser` method, reads the malicious value, constructs the parameters array, and invokes the "opn" library with these parameters.
  4. **Observation:**  
     - Verify (in a controlled lab environment) whether the injected command is executed. For example, check the designated output (e.g. the creation of `/tmp/malicious.txt` or any other side effect).
     - Monitor system logs or console output for evidence that the malicious command was run.
  5. **Result:**  
     - A successful test will show that the manipulated configuration value was used to execute the injected command, demonstrating the remote code execution risk.
  6. **Cleanup:**  
     - Remove or undo any changes made during the test in order to restore a clean environment.