## Combined Vulnerability List

This document outlines identified vulnerabilities, combining information from provided vulnerability lists and removing duplicates.

### Vulnerability 1: Path Traversal via `mount` configuration

* Description:
    1. An attacker can exploit the `liveServer.settings.mount` configuration within VSCode Live Server.
    2. The attacker needs to induce a user to set a malicious `mount` configuration in their VSCode settings, potentially through social engineering or exploiting another vulnerability to inject configuration (though less likely in VSCode extension settings).
    3. The user unknowingly configures `liveServer.settings.mount` with a malicious URL path that includes path traversal sequences, such as `[["/../../../../", "/"]]`.
    4. When Live Server starts, this configuration is applied, mapping URL paths to file system directories as defined.
    5. Consequently, when an attacker requests a URL containing path traversal sequences (e.g., `http://localhost:<port>/../../../../etc/passwd`), the application, due to the insecure mount configuration, incorrectly resolves the path and serves files from outside the intended workspace directory.

* Impact:
    - High: Successful exploitation grants an attacker unauthorized access to sensitive files located within the user's workspace or potentially even system files, depending on the workspace's root directory. This information disclosure can expose source code, configuration files containing sensitive data, or system credentials.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None:  The codebase lacks input validation or sanitization measures for the URL paths provided in the `mount` configuration.

* Missing Mitigations:
    - Implement robust input validation and sanitization for `mountRule[0]` (the URL path) within the `generateParams` function in `Helper.ts`.
    - Specifically, the extension must ensure that the URL path in the `mount` configuration does not contain path traversal characters (like `..`). A restrictive approach would be to only allow alphanumeric characters and forward slashes `/`.
    - Alternatively, disallowing relative paths in `mountRule[0]` and enforcing that all paths must start from the root `/` and refer to locations within the workspace could mitigate this vulnerability.

* Preconditions:
    - A user must configure the `liveServer.settings.mount` setting in their VSCode settings.
    - An attacker needs to persuade or trick the user into setting a vulnerable configuration.
    - Live Server must be started after the malicious configuration has been set.

* Source Code Analysis:
    - File: `/code/src/Helper.ts`
    - Function: `generateParams`
    ```typescript
    public static generateParams(
        rootPath: string,
        workspacePath: string,
        onTagMissedCallback?: MethodDecorator
    ) {
        // ...
        const mount = Config.getMount;
        // In live-server mountPath is reslove by `path.resolve(process.cwd(), mountRule[1])`.
        // but in vscode `process.cwd()` is the vscode extensions path.
        // The correct path should be resolve by workspacePath.
        mount.forEach((mountRule: Array<any>) => {
            if (mountRule.length === 2 && mountRule[1]) {
                mountRule[1] = path.resolve(workspacePath, mountRule[1]);
            }
        });
        // ...
        return {
            // ...
            mount: mount
        };
    }
    ```
    - The `generateParams` function processes the `mount` configuration retrieved from `Config.getMount`.
    - For each `mountRule` in the configuration, the code resolves the second element (`mountRule[1]`, representing the file path) using `path.resolve(workspacePath, mountRule[1])`. This correctly resolves the file path relative to the workspace.
    - **Vulnerability:** Critically, the code directly uses `mountRule[0]` (the URL path) without any form of validation or sanitization. This unvalidated URL path is then passed to the underlying `live-server` library. This direct passthrough allows users to specify arbitrary URL paths, including those containing path traversal sequences like `..`. Consequently, a malicious `mount` configuration can trick the server into serving files from outside the intended workspace directory when a crafted URL with path traversal is requested.

* Security Test Case:
    1. Open VSCode with any workspace directory.
    2. Create a simple text file named `test.txt` in the root of your workspace and add the text "This is a test file" to it.
    3. Access VSCode settings (JSON format) and add the following configuration to `settings.json`:
       ```json
       "liveServer.settings.mount": [
           ["/../../../../", "/"]
       ]
    ```
    4. Start Live Server. You can do this by clicking the "Go Live" button in the VSCode status bar or using the context menu.
    5. Identify the port Live Server is running on. This is usually displayed in an information message or in the status bar. Let's assume the port is `<port>`.
    6. Open a web browser and enter the following URL, replacing `<port>` with the actual port number and `<absolute_path_to_workspace>` with the full absolute path to your workspace directory on your operating system (e.g., `/home/user/myproject` on Linux, `C:/Users/User/Documents/myproject` on Windows): `http://localhost:<port>/../../../../<absolute_path_to_workspace>/test.txt`.
    7. Examine the browser's response.
    8. **Expected Result (Vulnerable):** If the browser displays the content of `test.txt` ("This is a test file"), the path traversal vulnerability is confirmed. This demonstrates successful access to a file within your workspace using path traversal techniques through the `mount` configuration.
    9. **Further Test (Critical Vulnerability - System File Access):** To assess the severity further, attempt to access sensitive system files. On Linux, try navigating to `http://localhost:<port>/../../../../etc/passwd`. On Windows, try `http://localhost:<port>/../../../../Windows/win.ini`.
    10. **Expected Result (Critically Vulnerable):** If you can successfully retrieve the contents of system files like `/etc/passwd` or `win.ini`, it confirms a critical path traversal vulnerability, indicating the potential for unauthorized access to sensitive system information beyond the workspace.


### Vulnerability 2: Command Injection in `AdvanceCustomBrowserCmdLine` setting

* Description:
    The `AdvanceCustomBrowserCmdLine` setting in VSCode Live Server allows users to define custom command-line arguments to be passed to the browser when Live Server is launched. The value provided by the user for this setting is split by the delimiter `--` and directly passed to the `opn` library to open the browser. If an attacker can manipulate this setting, they can inject arbitrary commands that will be executed on the user's system at the time Live Server is started.

* Impact:
    - Critical: Successful command injection allows for arbitrary command execution on the user's machine with the privileges of the VSCode process. This can lead to severe consequences, including data theft, malware installation, creation of new user accounts, or complete system compromise, depending on the injected commands and system permissions.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None: There is no input sanitization or validation performed on the `AdvanceCustomBrowserCmdLine` setting before passing it to the `opn` library.

* Missing Mitigations:
    - Implement robust input sanitization and validation for the `AdvanceCustomBrowserCmdLine` setting. Sanitize or block potentially harmful characters and commands.
    - Avoid directly passing user-provided command-line arguments to the `opn` library or any shell execution function without strict validation. Consider alternative methods for customizing browser behavior that do not involve direct command-line argument injection. If command-line arguments are absolutely necessary, use a safe parsing and validation mechanism to prevent injection attacks.

* Preconditions:
    - A user must configure the `liveServer.settings.AdvanceCustomBrowserCmdLine` setting in their VSCode settings.
    - An attacker needs to convince or trick the user into setting a malicious value for `AdvanceCustomBrowserCmdLine` or find an alternative method to modify VSCode settings, such as through a malicious workspace configuration file.

* Source Code Analysis:
    - File: `/code/src/appModel.ts`
    - Function: `openBrowser`
    ```typescript
    private openBrowser(port: number, path: string) {
        // ...
        let params: string[] = [];
        let advanceCustomBrowserCmd = Config.getAdvancedBrowserCmdline; // [1] Get user provided command line arguments
        if (advanceCustomBrowserCmd) {
            advanceCustomBrowserCmd
                .split('--') // [2] Split arguments by '--'
                .forEach((command, index) => {
                    if (command) {
                        if (index !== 0) command = '--' + command;
                        params.push(command.trim()); // [3] Add arguments to params array
                    }
                });
        }
        // ...
        try {
            require('opn')(\`${protocol}://${host}:${port}/${path}\`, { app: params || [''] }); // [4] Execute command with user provided arguments
        } catch (error) {
            // ...
        }
    }
    ```
    - **Step 1**: The `openBrowser` function starts by retrieving the value of the `AdvanceCustomBrowserCmdLine` setting using `Config.getAdvancedBrowserCmdline`. This setting is intended to allow users to customize browser command-line arguments.
    - **Step 2**: The code then splits the string obtained from the setting by the `--` delimiter. This is intended to separate multiple command-line arguments provided by the user.
    - **Step 3**: Each segment resulting from the split is treated as a command-line argument and added to the `params` array. If a segment is not the first one, `--` is prepended back to it, assuming it was originally intended to be a separate argument.
    - **Step 4**: Finally, the code uses the `opn` library to open the browser. Critically, the `app` option of the `opn` function is directly set to the `params` array, which now contains the user-provided and unsanitized command-line arguments from `AdvanceCustomBrowserCmdLine`. The `opn` library then executes a command, incorporating these user-provided arguments. If a malicious command is injected into the `AdvanceCustomBrowserCmdLine` setting, it will be directly executed by `opn` on the user's system, leading to command injection.

* Security Test Case:
    1. Open VSCode on your operating system (Windows, macOS, or Linux).
    2. Open any HTML file within a workspace in VSCode.
    3. Navigate to VSCode settings (File -> Preferences -> Settings on Windows/Linux, or Code -> Settings -> Settings on macOS). Search for "liveServer.settings.AdvanceCustomBrowserCmdLine".
    4. Under "Live Server > Settings: Advance Custom Browser Cmdline", input one of the following values based on your operating system to demonstrate command execution. These commands are safe examples to launch the system's calculator application:
        - **For Windows:** `chrome --incognito --remote-debugging-port=9222 & calc.exe`
        - **For macOS:** `chrome --incognito --remote-debugging-port=9222 & open /Applications/Calculator.app`
        - **For Linux:** `chrome --incognito --remote-debugging-port=9222 & gnome-calculator` (or `xcalc` if `gnome-calculator` is not available).
       These commands are designed to open Google Chrome in incognito mode with remote debugging enabled (standard Live Server behavior) and concurrently launch the system calculator application using the `&` operator to run commands in the background.
    5. Start Live Server by clicking the "Go Live" button in the VSCode status bar or by right-clicking on the HTML file and selecting "Open with Live Server".
    6. Observe the system's response. Shortly after Live Server starts and the browser window opens, the calculator application (e.g., `calc.exe`, Calculator.app, or gnome-calculator) should also launch.
    7. The successful launch of the calculator application confirms that arbitrary commands can be injected and executed via the `AdvanceCustomBrowserCmdLine` setting. This demonstrates a command injection vulnerability, as user-controlled input is directly leading to command execution on the system.