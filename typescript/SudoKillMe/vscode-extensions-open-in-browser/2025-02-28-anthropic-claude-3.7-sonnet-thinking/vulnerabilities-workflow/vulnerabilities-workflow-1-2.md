## Vulnerabilities

- **Vulnerability Name:** Command Injection via Unsanitized File Path

- **Description:**  
  The extension's implementation for opening the current file in a browser uses the external library (opn) and passes the file's system path directly. The file path is obtained from the active text editor (via `vscode.window.activeTextEditor.document.uri.fsPath`) and then relayed—without any sanitization—to the opn function. In a malicious repository, an attacker can craft filenames that include shell metacharacters or injected command sequences. When the user triggers either the "open in default browser" or "open in specify browser" command, the unsanitized file path is used as an argument in the underlying system call. If opn (or its execution environment) constructs the command via shell interpolation, these injected characters may result in command injection and remote code execution.

  **Step-by-step how someone can trigger the vulnerability:**  
  1. The attacker commits a repository that contains a file whose name is deliberately manipulated—for example, `index.html;rm -rf /` or a similar payload incorporating shell metacharacters.  
  2. The victim opens the malicious repository in VS Code.  
  3. The manipulated file becomes the active editor (or is passed as an argument when the extension command is executed).  
  4. The user triggers the extension command (using the defined shortcut or context menu) to open the current file in the browser.  
  5. The extension retrieves the unsanitized file path from the active editor and passes it to the opn library.  
  6. If opn executes the file path within a shell context without proper argument separation, the embedded malicious command may be executed.

- **Impact:**  
  Exploiting this vulnerability can lead to arbitrary command execution on the victim's machine. An attacker may cause arbitrary code to run with the same privileges as the VS Code process—potentially leading to a complete system compromise.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  - The code simply extracts the file system path (via `fsPath`) and passes it directly to opn.  
  - There is no validation or sanitization step applied to the file path in any of the functions (`openDefault` in `index.ts` or `open` in `util.ts`).

- **Missing Mitigations:**  
  - **Input Validation/Sanitization:** The file name/path should be sanitized or validated to remove any shell metacharacters or suspicious patterns before passing it to opn.  
  - **Safe Process Invocation:** Instead of passing an unsanitized string into opn (which may internally use shell invocation), use safer methods that call the target browser with arguments as an array and ensure that no shell interpolation takes place.  
  - **File Type Restrictions:** Optionally, restrict the types of files that may be opened (or enforce a whitelist of file extensions) so that arbitrary files cannot trigger execution in unexpected programs.

- **Preconditions:**  
  - The victim must open a repository that contains at least one file with a specially crafted filename containing command injection payloads.  
  - That file must become the active file (or be explicitly provided as the target path) when the extension command is executed.  
  - The underlying opn library (or its particular usage in the current environment) must pass the argument to a shell without proper escaping, thereby allowing the injection payload to be interpreted.

- **Source Code Analysis:**  
  1. In `src/index.ts`, the function `openDefault` retrieves the current file's URI:  
     - It calls `currentPageUri()`, which returns `vscode.window.activeTextEditor.document.uri` and then extracts `fsPath`.  
     - No sanitization or validation is performed on the `fsPath` value.
  2. The obtained path (`uri`) is then used to determine the browser to open via:  
     ```ts
     const browser = standardizedBrowserName(defaultBrowser());
     ```
     (where `defaultBrowser()` reads the workspace configuration, and `standardizedBrowserName` merely maps a value to one of the allowed browser names).
  3. Finally, the path is handed off to the `open` function (in both `src/util.ts` and `out/util.js`):  
     ```js
     opn(path, { app: browser })
       .catch(_ => {
         vscode.window.showErrorMessage(`Open browser failed!! Please check if you have installed the browser ${browser} correctly!`);
       });
     ```
     Here, the unsanitized `path` (which came directly from the repository file's name) is passed into opn. There is no filtering, escaping, or other mitigation to prevent an attacker's crafted filename from influencing the underlying process call.
  4. Given that opn potentially spawns a command (and may use a shell under certain conditions), malicious characters in `path` may be interpreted as part of the command line, leading to command injection.

- **Security Test Case:**  
  1. **Setup:**  
     - Create a local Git repository containing a file with a manipulated name. For example, name the file:  
       ```
       test.html;echo "InjectedCommandExecuted"
       ```  
     - Ensure that this repository is structured as a legitimate VS Code workspace.
  2. **Precondition:**  
     - Open the repository in VS Code.  
     - Activate the file with the malicious filename (make sure it is the active editor).
  3. **Execution:**  
     - Trigger the "Open in Default Browser" command (either by using the defined shortcut or via the context menu).
  4. **Observation:**  
     - Monitor the system for evidence that the injected command (`echo "InjectedCommandExecuted"`) has executed. This can be done by redirecting output to a log file or by using system monitoring tools.
  5. **Expected Result:**  
     - The file should open in the default browser without executing any injected command. If the injected command executes, it confirms the presence of a command injection vulnerability.
  6. **Cleanup:**  
     - Remove the malicious repository or file after testing.