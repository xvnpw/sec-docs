### Vulnerability List:

* Vulnerability Name: Command Injection via Filename in `opn`
* Description:
    1. The VSCode extension "Open in Browser" uses the `opn` library to open files in a browser.
    2. The `opn` library, when opening a file path, might pass the filename unsanitized to underlying system commands like `start`, `open`, or `xdg-open`.
    3. If an attacker can create a file with a malicious filename containing command injection payloads, and then open this file using the "Open in Browser" extension, they can execute arbitrary commands on the user's system.
    4. The extension does not sanitize the filename before passing it to `opn`.
* Impact:
    - Arbitrary command execution on the user's system with the privileges of the VSCode process.
    - This can lead to data theft, malware installation, or system compromise.
* Vulnerability Rank: high
* Currently implemented mitigations: None
* Missing mitigations:
    - Sanitize the `path` parameter before passing it to the `opn` function.
    - Consider using a safer way to open files in browsers, possibly using VSCode API if available, or carefully sanitizing input for `opn`.
* Preconditions:
    - Attacker needs to create a file with a malicious filename in a workspace that the victim opens in VSCode.
    - Victim needs to use the "Open in Browser" extension to open this malicious file using either "Open in Default Browser" or "Open in Specified Browser" commands.
* Source code analysis:
    1. In `/code/src/util.ts`, the `open` function is defined:
    ```typescript
    export const open = (path: string, browser: string = '') => {
      opn(path, { app: browser })
        .catch(_ => {
          vscode.window.showErrorMessage(`Open browser failed!! Please check if you have installed the browser ${browser} correctly!`);
        });
    };
    ```
    2. The `opn` function is called with the `path` argument directly without any sanitization.
    3. In `/code/src/index.ts`, the `openDefault` and `openBySpecify` functions call the `open` function from `util.ts`:
    ```typescript
    export const openDefault = (path: any): void => {
      let uri;
      if (path) {
        uri = path.fsPath;
      } else {
        const _path = currentPageUri();
        uri = _path && _path.fsPath;
      }
      const browser = standardizedBrowserName(defaultBrowser());
      open(uri, browser);
    };

    export const openBySpecify = (path: any): void => {
      vscode.window.showQuickPick(
        Config.browsers
      ).then(item => {
        if (!item) {
          return;
        }
        let uri;
        if (path) {
          uri = path.fsPath;
        } else {
          const _path = currentPageUri();
          uri = _path && _path.fsPath;
        }
        open(uri, item.standardName);
      });
    };
    ```
    4. In both `openDefault` and `openBySpecify`, the `path` variable is derived from `path.fsPath` or `currentPageUri().fsPath`. The `fsPath` property of a VSCode `Uri` object represents the file system path, which can include maliciously crafted filenames.
    5. No sanitization is performed on the `uri` or `uri.fsPath` before passing it to the `open` function in `util.ts`.
    6. This allows an attacker to inject commands through a malicious filename that will be executed by the `opn` library when opening the file in a browser.

* Security test case:
    1. Open VSCode.
    2. Create a new workspace or open an existing one.
    3. Create a new file in the workspace with the following filename:  `; touch command_injection_vulnerability.txt`.
        - On Windows, use filename: `; start notepad.exe`
    4. Open the file you just created in the VSCode editor.
    5. Execute the command "Open in Default Browser" (using `Alt + B` or `Shift + Alt + B` shortcut, or via command palette).
    6. Observe the system behavior:
        - On macOS/Linux: Check if a file named `command_injection_vulnerability.txt` has been created in the workspace directory. If yes, the command injection is successful.
        - On Windows: Check if the Notepad application is launched. If yes, the command injection is successful.
    7. If the expected system command (touch or notepad) is executed, it confirms the command injection vulnerability.