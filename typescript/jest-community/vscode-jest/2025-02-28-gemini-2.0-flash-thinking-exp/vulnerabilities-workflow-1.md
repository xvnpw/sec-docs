## Combined Vulnerability List

This document consolidates the vulnerabilities identified across multiple reports into a unified list, removing duplicates and providing detailed descriptions for each.

### 1. Arbitrary Code Execution via Malicious Workspace Configuration

- **Vulnerability Name:** Arbitrary Code Execution via Malicious Workspace Configuration

- **Description:** A threat actor can craft a malicious workspace configuration that, when opened in VSCode with the vscode-jest extension installed, leads to arbitrary code execution on the user's machine. This vulnerability arises from the extension's reliance on user-provided settings, specifically the `jest.shell` setting. By manipulating the `jest.shell` setting within a workspace's `.vscode/settings.json` file to point to a malicious executable, an attacker can execute arbitrary code on a victim's machine when the vscode-jest extension attempts to run Jest within that workspace.

- **Impact:** Arbitrary code execution on the victim's machine. This can lead to a complete compromise of the user's system, including sensitive data theft, malware installation, and further propagation of attacks. The vulnerability is considered critical due to the potential for full system takeover.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:** None. The extension directly uses the user-provided `jest.shell` setting without any validation or sanitization.

- **Missing Mitigations:**
    - **Input validation:** Implement robust validation for the `jest.shell` setting. This should include:
        - **Path validation:** Verify if the provided path is absolute or relative and resolve relative paths within the workspace to absolute paths.
        - **Executable validation:** Confirm that the file at the specified path is indeed an executable file.
        - **Blocklisting:** Maintain a blocklist of known malicious or suspicious executables or paths to prevent their usage.
    - **User warning:** Display a clear warning to the user when a custom `jest.shell` is configured, especially if it deviates from standard shell paths. This warning should highlight the potential security risks and advise caution.
    - **Principle of least privilege:** Evaluate the necessity of allowing users to configure a custom shell for Jest execution. If not strictly required, restrict the `jest.shell` setting to a predefined whitelist of safe shell executables or remove the customizability altogether to minimize risk.

- **Preconditions:**
    1. The user has VSCode installed with the vscode-jest extension enabled.
    2. An attacker can induce a user to open a workspace containing a malicious `.vscode/settings.json` file. This could be achieved through social engineering, malicious repositories, or compromised project files.
    3. The malicious workspace includes a `.vscode/settings.json` file that sets the `jest.shell` property to point to a malicious executable.

- **Source Code Analysis:**
    1. **Configuration Loading:** The vscode-jest extension reads configuration settings, including `jest.shell`, from the `.vscode/settings.json` file within the opened workspace. This is a standard VSCode feature for workspace-specific settings.
        ```
        settings.json --> VSCode Configuration API --> vscode-jest Extension
        ```
        The extension's code retrieves the value of the `jest.shell` setting via VSCode's API.
    2. **Jest Process Spawning:** The extension utilizes the configured `jest.shell` value directly when spawning child processes to execute Jest commands. The extension does not perform any validation or sanitization on the `jest.shell` path before using it in process execution.
        ```
        jest.shell (from settings.json) --> Child Process API (VSCode Extension Host) --> Execution of Jest Command (potentially malicious shell)
        ```
        This direct usage of the user-provided path without validation is the root cause of the vulnerability.

- **Security Test Case:**
    1. **Malicious Workspace Setup:**
        - Create a new directory named `malicious-jest-workspace`.
        - Inside `malicious-jest-workspace`, create a directory named `.vscode`.
        - Within `.vscode`, create a file named `settings.json`.
        - Populate `settings.json` with the following content, adapting to the operating system:
            - **Linux/macOS:**
              ```json
              {
                "jest.shell": "/tmp/malicious_script.sh"
              }
              ```
            - **Windows:**
              ```json
              {
                "jest.shell": "C:\\Windows\\Temp\\malicious_script.bat"
              }
              ```
        - Create the malicious script at the specified path (`/tmp/malicious_script.sh` or `C:\\Windows\\Temp\\malicious_script.bat`).
            - **Example malicious script (`/tmp/malicious_script.sh` - Linux/macOS):**
              ```bash
              #!/bin/bash
              echo "Malicious script executed by vscode-jest!" >> /tmp/attack_log.txt
              # Add further malicious commands here if desired
              ```
            - **Example malicious script (`C:\\Windows\\Temp\\malicious_script.bat` - Windows):**
              ```batch
              @echo off
              echo Malicious script executed by vscode-jest! >> C:\Windows\Temp\attack_log.txt
              REM Add further malicious commands here if desired
              ```
        - Ensure the script is executable (e.g., `chmod +x /tmp/malicious_script.sh` on Linux/macOS).
        - Create a simple JavaScript test file (e.g., `test.js`) within `malicious-jest-workspace`:
          ```javascript
          test('vulnerable test', () => {
            expect(1).toBe(1);
          });
          ```
        - Initialize an npm project and install Jest: `npm init -y && npm install jest` within `malicious-jest-workspace`.
    2. **Victim Workspace Opening:** Trick a user into opening the `malicious-jest-workspace` in VSCode with the vscode-jest extension installed and activated.
    3. **Jest Execution Trigger:**  Once the workspace is open, vscode-jest will attempt to start Jest. This may happen automatically depending on the extension's configuration or upon manually triggering a test run.
    4. **Verification of Code Execution:** Check for the existence of the log file created by the malicious script (`/tmp/attack_log.txt` or `C:\Windows\Temp\attack_log.txt`). If the file exists and contains the expected message ("Malicious script executed by vscode-jest!"), it confirms successful arbitrary code execution.

### 2. Command Injection via Malicious Terminal Link

- **Vulnerability Name:** Command Injection via Terminal Links

- **Description:** The `ExecutableTerminalLinkProvider` in `terminal-link-provider.ts` processes `vscode-jest://` URIs embedded in terminal output. When a user clicks on such a link, the extension parses the URI, extracts the `command` and `args` parameters, and executes a VSCode command using `vscode.commands.executeCommand`. An attacker can craft a malicious terminal output containing a specially crafted `vscode-jest://` URI to inject arbitrary VSCode commands. Due to insufficient validation and sanitization of the URI parameters, particularly `command` and `args`, a malicious actor can potentially execute unintended or harmful actions within VSCode by tricking a user into clicking on a malicious link in the terminal.

- **Impact:** Command injection within the VSCode environment. While not direct arbitrary code execution on the user's operating system in the same way as the `jest.shell` vulnerability, this can still lead to significant unintended actions within VSCode. Depending on the injected command and arguments, the impact can range from benign actions to more serious consequences if the executed command interacts with sensitive VSCode APIs or triggers further vulnerabilities within the extension or VSCode itself.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:** None. The extension uses `decodeURIComponent` and `JSON.parse` on the URI components directly without any validation or sanitization before passing them to `vscode.commands.executeCommand`.

- **Missing Mitigations:**
    - **Input validation and sanitization:** Implement thorough validation and sanitization of the `command` and `args` extracted from the URI.
        - **Command whitelist:** Establish a whitelist of allowed commands that can be executed via terminal links. Only commands explicitly included in this whitelist should be permitted.
        - **Arguments validation:** Validate the structure and content of the `args` object to ensure it conforms to the expected format and does not contain malicious payloads. Implement strict schema validation for the expected arguments of whitelisted commands.
        - **Secure decoding:** Review the usage of `decodeURIComponent` and `JSON.parse`. Consider potential vulnerabilities related to malformed or unexpected input during decoding and JSON parsing. Explore safer parsing methods or implement robust error handling and fallback mechanisms.
    - **User warning:** Before executing any command triggered by a terminal link, display a clear and informative warning to the user. This warning should explain the potential risks associated with executing commands from terminal links and require explicit user confirmation before proceeding.
    - **Principle of least privilege:** Re-evaluate the necessity of executing arbitrary VSCode commands from terminal links. If possible, restrict the functionality to a minimal and essential set of safe commands, minimizing the attack surface.

- **Preconditions:**
    1. VSCode with the vscode-jest extension is installed and activated.
    2. The `ExecutableTerminalLinkProvider` is registered and active within the extension.
    3. A user views terminal output that contains a maliciously crafted `vscode-jest://` link. This could originate from a test execution output or be maliciously injected into the terminal stream.
    4. The user clicks on the malicious `vscode-jest://` terminal link.

- **Source Code Analysis:**
    1. **Terminal Link Provider Registration:** The `ExecutableTerminalLinkProvider` is registered as a terminal link provider using `vscode.window.registerTerminalLinkProvider(this)` within the extension's activation phase. This registration makes the `provideTerminalLinks` and `handleTerminalLink` functions active for processing terminal links.
        ```
        vscode.window.registerTerminalLinkProvider(this) --> Activates ExecutableTerminalLinkProvider
        ```
    2. **Malicious Link Handling in `handleTerminalLink`:** When a user clicks on a terminal link, the `handleTerminalLink` function in `terminal-link-provider.ts` is invoked. This function performs the following steps:
        ```typescript
        async handleTerminalLink(link: ExecutableTerminalLink): Promise<void> {
          try {
            const uri = vscode.Uri.parse(link.data);
            const folderName = decodeURIComponent(uri.authority);
            const command = decodeURIComponent(uri.path).substring(1);
            const args = uri.query && JSON.parse(decodeURIComponent(uri.query));
            await vscode.commands.executeCommand(command, folderName, args); // Vulnerable Line
          } catch (error) {
            vscode.window.showErrorMessage(`Failed to handle link "${link.data}": ${error}`);
          }
        }
        ```
        - `vscode.Uri.parse(link.data)`: Parses the raw link data into a VSCode URI object.
        - `decodeURIComponent(uri.authority)`: Decodes the authority part of the URI, assigned to `folderName`.
        - `decodeURIComponent(uri.path).substring(1)`: Decodes the path part (excluding the leading '/'), assigned to `command`.
        - `uri.query && JSON.parse(decodeURIComponent(uri.query))`: Decodes the query part, parses it as JSON, and assigns it to `args`.
        - `vscode.commands.executeCommand(command, folderName, args)`: Executes the VSCode command specified in the `command` variable with the decoded `folderName` and `args`. **This line is vulnerable to command injection** because the `command` and `args` are derived from the URI without proper validation.

- **Security Test Case:**
    1. **Craft Malicious Link:** Create a malicious `vscode-jest://` URI designed to trigger a visible action in VSCode, such as displaying an error message. For instance, use a command like `evil-command` (which could be a placeholder for any VSCode command) and arguments to control the displayed message:
        ```
        vscode-jest://test-workspace/evil-command?{"message":"Vulnerable to Command Injection!"}
        ```
    2. **Inject Link into Terminal Output:** To simulate a scenario where this link might appear, modify the `provideTerminalLinks` function in `ExecutableTerminalLinkProvider.ts` to inject this malicious link into the terminal output.  For testing purposes, you can hardcode the link into a line of output:
        ```typescript
        provideTerminalLinks(
          context: vscode.TerminalLinkContext,
          _token: vscode.CancellationToken
        ): vscode.ProviderResult<ExecutableTerminalLink[]> {
          const maliciousLink = `vscode-jest://test-workspace/evil-command?${encodeURIComponent(JSON.stringify({"message":"Vulnerable to Command Injection!"}))}`;
          const lineWithLink = `This line contains a malicious link: ${maliciousLink}`;
          // ... (rest of the function, potentially returning links)
          return [{
            startIndex: lineWithLink.indexOf(maliciousLink),
            length: maliciousLink.length,
            tooltip: 'execute malicious command',
            data: maliciousLink,
          }];
        }
        ```
    3. **User Interaction:** Start VSCode with the modified extension and open a terminal. The terminal output should now contain the injected malicious link. Instruct a test user to click on this link.
    4. **Verify Command Execution:** Observe if the injected command is executed. In this test case, check if an error message box appears in VSCode with the message "Vulnerable to Command Injection!". If the message box is displayed, it confirms that the injected command was executed, demonstrating the command injection vulnerability through terminal links.