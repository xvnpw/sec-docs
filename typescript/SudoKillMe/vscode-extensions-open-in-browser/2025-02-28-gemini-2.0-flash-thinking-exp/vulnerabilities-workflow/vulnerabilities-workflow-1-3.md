### Vulnerability List:

* Vulnerability Name: Command Injection via Malicious File Path
* Description:
    1. An attacker crafts a workspace and includes a file with a malicious filename containing shell command injection sequences (e.g., using backticks, `$()`, or semicolons for command chaining).
    2. A user opens this attacker-crafted workspace in VSCode.
    3. The user opens the malicious file within the VSCode editor.
    4. The user triggers the "Open in Default Browser" or "Open in Specified Browser" command provided by the extension, either through the context menu, command palette, or keyboard shortcut.
    5. The extension retrieves the file path from the active editor, which includes the malicious filename.
    6. The extension utilizes the `opn` library to open this file path in a browser.
    7. The `opn` library, depending on the operating system, executes a system command (like `open` on macOS, `start` on Windows, or `xdg-open` on Linux) to open the file.
    8. Due to insufficient sanitization of the file path, the shell interprets the malicious command injection sequences embedded in the filename as commands and executes them, in addition to the intended file opening operation.
* Impact: Arbitrary command execution on the user's machine with the privileges of the VSCode process. This can allow an attacker to perform various malicious actions, such as:
    - Data exfiltration: Stealing sensitive files or environment variables.
    - Malware installation: Downloading and executing malware.
    - System compromise: Modifying system settings or creating new user accounts.
    - Denial of Service (indirect): While direct DoS is excluded, command injection could be used to execute resource-intensive commands, indirectly leading to performance degradation.
* Vulnerability Rank: High
* Currently Implemented Mitigations: None. The extension directly passes the file path obtained from VSCode's API to the `opn` library without any sanitization or validation.
* Missing Mitigations:
    - **Input Sanitization:** The extension should sanitize the file path before passing it to the `opn` library. This could involve:
        - Removing or escaping shell-sensitive characters (e.g., backticks, `$`, `()`, `;`, `&`, `|`, `<`, `>`, etc.) from the file path.
        - Validating the file path to ensure it only contains expected characters and does not include command injection patterns.
    - **Alternative API:** Explore if there are safer, cross-platform APIs for opening files in browsers that do not rely on shell command execution and are less susceptible to command injection vulnerabilities.
* Preconditions:
    1. The user must open a VSCode workspace that contains a file with a maliciously crafted name designed for command injection.
    2. The user must open this malicious file in the VSCode editor, making it the active text editor.
    3. The user must then trigger the "Open in Default Browser" or "Open in Specified Browser" command provided by the extension.
* Source Code Analysis:
    1. **`src/index.ts`**:
        ```typescript
        export const openDefault = (path: any): void => {
          let uri;
          if (path) {
            uri = path.fsPath; // [ vulnerable code ] Path from argument, potentially controllable via context menu
          } else {
            const _path = currentPageUri();
            uri = _path && _path.fsPath; // [ vulnerable code ] Path from current file, workspace-dependent, but filename can be malicious
          }
          const browser = standardizedBrowserName(defaultBrowser());
          open(uri, browser); // Calls util.open with the potentially unsafe path
        };

        export const openBySpecify = (path: any): void => {
          // ... similar path retrieval ...
          open(uri, item.standardName); // Calls util.open with the potentially unsafe path
        };
        ```
        - The `openDefault` and `openBySpecify` functions retrieve the file path using `uri.fsPath`. This path is then directly passed to the `open` function in `util.ts`. There is no sanitization of this path in `index.ts`.

    2. **`src/util.ts`**:
        ```typescript
        const opn = require('opn');

        export const open = (path: string, browser: string = '') => {
          opn(path, { app: browser }) // [ vulnerable code ] Calls opn directly with unsanitized path
            .catch(_ => {
              vscode.window.showErrorMessage(`Open browser failed!! Please check if you have installed the browser ${browser} correctly!`);
            });
        };
        ```
        - The `open` function in `util.ts` directly calls the `opn` library with the provided `path` argument, without any sanitization. This is where the command injection vulnerability is introduced because `opn` might execute shell commands with this unsanitized path.

    ```mermaid
    graph LR
        A[User triggers "Open in Browser" command] --> B(extension.ts: activate);
        B --> C(index.ts: openDefault / openBySpecify);
        C --> D(index.ts: currentPageUri / path argument);
        D --> E{Get file path (uri.fsPath)};
        E --> F(util.ts: open);
        F --> G[opn(path, { app: browser })];
        G --> H{System Command Execution (potentially vulnerable)};
        H -- Malicious Path --> I[Command Injection];
        H -- Safe Path --> J[Open Browser];
    ```

* Security Test Case:
    1. Create a new directory named `vscode-open-browser-test`.
    2. Inside `vscode-open-browser-test`, create a file named `test_$(touch injected_default_browser.txt).html`.  (For Windows, use `test_%2528echo injected_default_browser.txt>%USERPROFILE%\\Desktop\\injected_default_browser.txt%2529.html` or similar Windows command injection syntax).
    3. Open VSCode and open the `vscode-open-browser-test` directory as a workspace.
    4. Open the file `test_$(touch injected_default_browser.txt).html` (or the Windows equivalent) in the VSCode editor, making it the active editor.
    5. Execute the "Open in Default Browser" command (e.g., using the default shortcut `Alt + B` or via the command palette).
    6. **Verify Command Execution:** Check if a file named `injected_default_browser.txt` is created in the `vscode-open-browser-test` directory (or on the Desktop for the Windows example). If the file is created, it confirms successful command injection.
    7. Repeat steps 2-6, but create a file named `test_$(touch injected_specified_browser.txt).html` (or Windows equivalent).
    8. Execute the "Open in Specified Browser" command (e.g., using `Shift + Alt + B` or via the command palette) and select any browser from the list.
    9. **Verify Command Execution:** Check if a file named `injected_specified_browser.txt` is created in the `vscode-open-browser-test` directory (or on the Desktop for the Windows example). If the file is created, it confirms successful command injection for the "Open in Specified Browser" command as well.

This test case demonstrates that by crafting a malicious filename within a workspace and using the extension's "Open in Browser" functionality, an attacker can achieve arbitrary command execution on the user's system.