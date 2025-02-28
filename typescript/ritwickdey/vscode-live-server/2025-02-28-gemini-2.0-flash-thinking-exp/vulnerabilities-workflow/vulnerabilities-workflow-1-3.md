### Vulnerability List

- Vulnerability Name: Command Injection in `AdvanceCustomBrowserCmdLine` setting
- Description: The `AdvanceCustomBrowserCmdLine` setting allows users to specify custom command-line arguments for the browser. This setting's value is split by `--` and directly passed to the `opn` library to open the browser. If a malicious user can control this setting, they can inject arbitrary commands that will be executed on the user's system when Live Server is started.
- Impact: Arbitrary command execution on the user's machine. This can lead to data theft, malware installation, or complete system compromise.
- Vulnerability Rank: Critical
- Currently implemented mitigations: None
- Missing mitigations: Input sanitization and validation for `AdvanceCustomBrowserCmdLine` setting. Avoid directly passing user-provided command-line arguments to `opn`.
- Preconditions:
    - User must configure `liveServer.settings.AdvanceCustomBrowserCmdLine` setting with a malicious command.
    - An attacker needs to convince a user to set a malicious `AdvanceCustomBrowserCmdLine` or find another way to modify the VSCode settings (e.g., via a malicious workspace configuration).
- Source Code Analysis:
    - Vulnerability can be found in `/code/src/appModel.ts` file, in `openBrowser` function.
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
    - **Step 1**: The code retrieves the value of `AdvanceCustomBrowserCmdLine` setting from VSCode configuration. This setting allows users to specify custom command-line arguments for the browser.
    - **Step 2**: The code splits the string value of `advanceCustomBrowserCmd` by `--` delimiter. This is intended to separate different command-line arguments.
    - **Step 3**: Each part obtained after splitting is considered as a command-line argument and added to the `params` array.
    - **Step 4**: The `opn` function is called to open the browser. The `app` option of `opn` is set to the `params` array. `opn` then executes the command specified in `params`, which now includes user-provided arguments from `AdvanceCustomBrowserCmdLine`. If a malicious command is injected into `AdvanceCustomBrowserCmdLine`, it will be executed by `opn`.

- Security Test Case:
    1. Open VSCode.
    2. Open any HTML file in a workspace.
    3. Go to VSCode settings (File -> Preferences -> Settings or Code -> Settings -> Settings on macOS) and search for "liveServer.settings.AdvanceCustomBrowserCmdLine".
    4. In the settings, under "Live Server > Settings: Advance Custom Browser Cmdline", set the value to:
        - For Windows:  `chrome --incognito --remote-debugging-port=9222 & calc.exe`
        - For macOS: `chrome --incognito --remote-debugging-port=9222 & open /Applications/Calculator.app`
        - For Linux: `chrome --incognito --remote-debugging-port=9222 & gnome-calculator` (or `xcalc` depending on your system)
       These commands will open Chrome in incognito mode and also launch the calculator application after the browser command. The calculator is used as a harmless example to demonstrate command execution.
    5. Start Live Server by clicking "Go Live" on the status bar, or by right-clicking on the HTML file and selecting "Open with Live Server".
    6. Observe that the calculator application (e.g., `calc.exe` on Windows, Calculator.app on macOS, or gnome-calculator on Linux) is launched shortly after Live Server starts and the browser opens.
    7. This confirms that arbitrary commands can be injected and executed via the `AdvanceCustomBrowserCmdLine` setting, demonstrating a command injection vulnerability.