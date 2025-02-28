## Vulnerability Report: vscode-jest Extension

### Vulnerability List

- [Vulnerability 1: Arbitrary Code Execution via Malicious Workspace Configuration](#vulnerability-1-arbitrary-code-execution-via-malicious-workspace-configuration)
- [Vulnerability 2: Command Injection via Malicious Terminal Link](#vulnerability-2-command-injection-via-malicious-terminal-link)

### Vulnerability 1: Arbitrary Code Execution via Malicious Workspace Configuration

- Description:
A threat actor can craft a malicious workspace configuration that, when opened in VSCode with the vscode-jest extension installed, leads to arbitrary code execution on the user's machine. This vulnerability stems from the extension's reliance on user-provided settings, specifically the `jest.shell` setting, which allows specifying a custom shell executable. If a user is tricked into opening a workspace with a maliciously crafted `settings.json` that points `jest.shell` to a malicious executable, the extension will execute this malicious code when it attempts to run Jest.

- Impact:
Arbitrary code execution on the victim's machine. This can lead to complete compromise of the user's system, including data theft, malware installation, and further propagation of attacks.

- Vulnerability Rank: critical

- Currently Implemented Mitigations:
None. The extension relies on user-provided settings and does not perform validation on the `jest.shell` path.

- Missing Mitigations:
- Input validation: The extension should validate the `jest.shell` setting to ensure it points to a legitimate shell executable and not a potentially malicious file. This could include:
    - Path validation: Checking if the path is absolute or relative, and resolving relative paths to absolute paths within the workspace.
    - Executable validation: Checking if the file at the specified path is actually an executable.
    - Blocklisting: Maintaining a blocklist of known malicious or suspicious executables or paths.
- User warning: When a custom `jest.shell` is configured, especially if it's not a standard shell path, the extension should display a warning to the user, highlighting the security risks and advising caution.
- Principle of least privilege: Consider if running Jest commands in a custom shell is strictly necessary. If not, restrict the `jest.shell` setting to a predefined list of safe shell executables or remove the option entirely.

- Preconditions:
1. VSCode with vscode-jest extension is installed.
2. Threat actor can trick a user into opening a workspace (e.g., via a malicious GitHub repository or project).
3. The malicious workspace contains a `.vscode/settings.json` file with a crafted `jest.shell` setting pointing to a malicious executable.

- Source Code Analysis:
1. **Configuration Loading:** The extension reads the `jest.shell` setting from `.vscode/settings.json`.
   - File: `/code/README.md`
   - Content:  The `README.md` documents the `jest.shell` setting under "Customization - Settings - shell". It describes how users can configure a custom shell.
   - Vulnerable Code: The extension uses the value of `jest.shell` setting directly to spawn jest processes without validation.
   - Visualization:
   ```
   settings.json --> VSCode Configuration API --> vscode-jest --> Jest Process Spawning (using jest.shell)
   ```
2. **Jest Process Spawning:** The extension uses the configured shell to execute Jest commands.
   - File: `/code/Customization.md`
   - Content: The `Customization.md` explains how `jest.shell` can be customized.
   - Vulnerable Code: The extension's code uses the `jest.shell` value to execute commands, as seen in files related to process management and debugging.
   - Visualization:
   ```
   jest.shell (settings.json) --> Child Process API (VSCode Extension Host) --> Execution of Jest Command (potentially malicious)
   ```

- Security Test Case:
1. **Setup Malicious Workspace:**
   - Create a new directory named `malicious-jest-workspace`.
   - Inside `malicious-jest-workspace`, create a directory named `.vscode`.
   - Inside `.vscode`, create a file named `settings.json` with the following content (for Linux/macOS):
     ```json
     {
       "jest.shell": "/tmp/malicious_script.sh"
     }
     ```
     or for Windows:
     ```json
     {
       "jest.shell": "C:\\Windows\\Temp\\malicious_script.bat"
     }
     ```
   - In `/tmp/malicious_script.sh` (Linux/macOS) or `C:\\Windows\\Temp\\malicious_script.bat` (Windows), create a malicious script. For example, for Linux/macOS:
     ```bash
     #!/bin/bash
     # malicious_script.sh
     echo "Malicious script executed by vscode-jest!" >> /tmp/attack_log.txt
     # Add more malicious commands here, e.g., exfiltrate data
     ```
     For Windows `C:\\Windows\\Temp\\malicious_script.bat`:
     ```batch
     @echo off
     echo Malicious script executed by vscode-jest! >> C:\Windows\Temp\attack_log.txt
     REM Add more malicious commands here
     ```
     - Make sure the script is executable (`chmod +x /tmp/malicious_script.sh` on Linux/macOS).
   - Create a simple JavaScript file (e.g., `test.js`) in `malicious-jest-workspace` to trigger Jest execution:
     ```javascript
     test('vulnerable test', () => {
       expect(1).toBe(1);
     });
     ```
   - Initialize a npm project and install jest: `npm init -y && npm install jest` inside `malicious-jest-workspace`.
2. **Victim Opens Workspace:**
   - Trick a victim user into opening the `malicious-jest-workspace` in VSCode with the vscode-jest extension installed.
3. **Trigger Jest Execution:**
   - Once the workspace is opened, vscode-jest will attempt to start Jest, triggering the execution of the malicious script defined in `jest.shell`.  This can happen automatically based on the `runMode` setting or manually by triggering a test run.
4. **Verify Arbitrary Code Execution:**
   - Check for the presence of `/tmp/attack_log.txt` (Linux/macOS) or `C:\Windows\Temp\attack_log.txt` (Windows) file. If the file exists and contains the "Malicious script executed by vscode-jest!" message, the vulnerability is confirmed.

This test case demonstrates how an attacker can achieve arbitrary code execution by exploiting the lack of validation on the `jest.shell` setting.

### Vulnerability 2: Command Injection via Malicious Terminal Link

- Description:
The `ExecutableTerminalLinkProvider` in `terminal-link-provider.ts` registers a terminal link provider for the scheme `vscode-jest://`. The `handleTerminalLink` function parses the URI, decodes components like `folderName`, `command`, and `args`, and then executes a VSCode command using `vscode.commands.executeCommand`. A threat actor could craft a malicious `vscode-jest://` URI with a harmful command and arguments. If a user clicks on such a link within the terminal output, the extension will execute the command. Due to insufficient validation and encoding handling, a malicious command could be injected and executed, potentially leading to unintended actions within VSCode or even command execution in the user's shell depending on the executed command's functionality.

- Impact:
Command injection leading to potentially unintended actions within VSCode. Depending on the nature of the injected command and its arguments, the impact could range from benign actions to more serious consequences if the executed command interacts with sensitive VSCode APIs or triggers further vulnerabilities. While direct arbitrary code execution in the user's shell might be less likely through this vector compared to `jest.shell`, the risk of command injection within VSCode itself is significant and can have serious implications depending on the extension's command landscape.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
None. The extension directly uses `decodeURIComponent` and `JSON.parse` on the URI components without any sanitization or validation before executing the command.

- Missing Mitigations:
- Input validation and sanitization: The extension should validate and sanitize the decoded `command` and `args` from the URI.
    - Command validation: Implement a whitelist of allowed commands that can be executed via terminal links.
    - Arguments validation: Validate the structure and content of the `args` object to ensure it conforms to the expected format and does not contain malicious payloads.
    - Secure decoding: Review the usage of `decodeURIComponent` and `JSON.parse` for potential vulnerabilities related to malformed or unexpected input. Consider using safer parsing methods or implementing error handling and fallback mechanisms.
- User warning: Before executing any command from a terminal link, the extension should display a clear warning to the user, explaining the potential risks and asking for confirmation before proceeding.
- Principle of least privilege: Review the necessity of executing arbitrary VSCode commands from terminal links. If possible, restrict the functionality to a limited set of safe and necessary commands.

- Preconditions:
1. VSCode with vscode-jest extension is installed.
2. The vscode-jest extension's terminal link provider is active (it is registered during extension activation).
3. A user views terminal output containing a maliciously crafted `vscode-jest://` link.
4. The user clicks on the malicious terminal link.

- Source Code Analysis:
1. **Terminal Link Provider Registration:** The `ExecutableTerminalLinkProvider` is registered as a terminal link provider.
   - File: `/code/src/terminal-link-provider.ts`
   - Content: The `ExecutableTerminalLinkProvider` class and its `register` method are defined, registering it with `vscode.window.registerTerminalLinkProvider(this)`.
   - Vulnerable Code: The registration itself is not vulnerable, but it enables the vulnerable `handleTerminalLink` function to be called.
   - Visualization:
   ```
   vscode.window.registerTerminalLinkProvider(this) --> Activates ExecutableTerminalLinkProvider
   ```
2. **Malicious Link Handling:** The `handleTerminalLink` function parses and executes commands from the URI.
   - File: `/code/src/terminal-link-provider.ts`
   - Content: The `handleTerminalLink` function is defined within the `ExecutableTerminalLinkProvider` class.
   - Vulnerable Code:
     ```typescript
     async handleTerminalLink(link: ExecutableTerminalLink): Promise<void> {
       try {
         const uri = vscode.Uri.parse(link.data);
         const folderName = decodeURIComponent(uri.authority);
         const command = decodeURIComponent(uri.path).substring(1);
         const args = uri.query && JSON.parse(decodeURIComponent(uri.query));
         await vscode.commands.executeCommand(command, folderName, args); // Vulnerable line
       } catch (error) {
         vscode.window.showErrorMessage(`Failed to handle link "${link.data}": ${error}`);
       }
     }
     ```
   - Source Code Walkthrough:
     - The function `handleTerminalLink` takes a `ExecutableTerminalLink` as input, which contains the link data.
     - `vscode.Uri.parse(link.data)` parses the link data into a VSCode URI object.
     - `decodeURIComponent(uri.authority)` decodes the authority part of the URI, assigned to `folderName`.
     - `decodeURIComponent(uri.path).substring(1)` decodes the path part of the URI (excluding the leading '/'), assigned to `command`.
     - `uri.query && JSON.parse(decodeURIComponent(uri.query))` decodes the query part of the URI, parses it as JSON, and assigns it to `args`.
     - `vscode.commands.executeCommand(command, folderName, args)` executes the VSCode command specified in the URI with the decoded arguments. **This is the vulnerable line.**
     - Error handling is present, but it only catches parsing errors and displays a generic error message, not preventing the command injection.
   - Visualization:
   ```
   vscode-jest://... (Malicious Link) --> ExecutableTerminalLinkProvider.handleTerminalLink
   handleTerminalLink --> URI Parsing --> decodeURIComponent (folderName, command, args) --> JSON.parse (args)
   vscode.commands.executeCommand(command, folderName, args) --> Command Execution (Vulnerable)
   ```

- Security Test Case:
1. **Craft Malicious Link:**
   - Create a malicious `vscode-jest://` link. This link will attempt to execute a command to display an error message box.
     ```
     vscode-jest://test-workspace/evil-command?{"message":"Vulnerable to Command Injection!"}
     ```
     Here, `evil-command` is the injected command and `{"message":"Vulnerable to Command Injection!"}` are arguments for this command.
2. **Inject Link into Terminal Output:**
   -  Modify the vscode-jest extension (or a testing environment) to print this malicious link to the terminal output.  For example, within `ExecutableTerminalLinkProvider.provideTerminalLinks`:
     ```typescript
     provideTerminalLinks(
       context: vscode.TerminalLinkContext,
       _token: vscode.CancellationToken
     ): vscode.ProviderResult<ExecutableTerminalLink[]> {
       const maliciousLink = `vscode-jest://test-workspace/evil-command?${encodeURIComponent(JSON.stringify({"message":"Vulnerable to Command Injection!"}))}`;
       const lineWithLink = `This line contains a malicious link: ${maliciousLink}`;
       return [{
         startIndex: lineWithLink.indexOf(maliciousLink),
         length: maliciousLink.length,
         tooltip: 'execute malicious command',
         data: maliciousLink,
       }];
     }
     ```
3. **User Opens Terminal and Clicks Link:**
   - Start VSCode with the modified extension and open a terminal.
   - The malicious link should appear in the terminal output.
   - Click on the link.
4. **Verify Command Execution:**
   - Observe if the injected command is executed. In this test case, verify if an error message box with the text "Vulnerable to Command Injection!" is displayed by VSCode. If the message box appears, it confirms that the injected command was executed, proving the vulnerability.

This test case demonstrates that an attacker can inject and execute arbitrary VSCode commands by crafting a malicious `vscode-jest://` link and tricking a user into clicking it.