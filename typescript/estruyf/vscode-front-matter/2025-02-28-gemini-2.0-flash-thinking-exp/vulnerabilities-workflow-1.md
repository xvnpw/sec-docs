## Consolidated Vulnerability List

This document combines identified vulnerabilities from provided lists, removing duplicates and presenting them in a structured format.

### Remote Code Execution via Custom Scripts

- **Vulnerability Name:** Remote Code Execution via Custom Scripts
- **Description:** An external attacker could potentially inject malicious commands into custom scripts defined in the Front Matter extension settings or within the `frontmatter.json` configuration file. These scripts are executed by the extension using `child_process.exec`, which can be vulnerable to command injection if arguments are not properly sanitized. This vulnerability can also be exploited by crafting a malicious `frontmatter.json` file in a workspace, allowing an attacker to define and execute arbitrary commands when a user opens the workspace and triggers the script.

    To trigger this vulnerability:
    1. Define a custom script in the Front Matter settings or in `frontmatter.json` that is designed to process arguments, for example, a script that logs the arguments to the console or performs some file operations based on input paths.
    2. As an attacker, create or modify a `frontmatter.json` file in the workspace with a malicious custom script definition. Alternatively, if targeting custom scripts defined in settings, manipulate content files to inject payloads into script arguments.
    3. Introduce a malicious payload into the custom script definition within `frontmatter.json`. For example, set the `script` field to execute a command like `echo 'Vulnerable' > vulnerable.txt` or similar command suitable for the target operating system. If targeting scripts using content file arguments, introduce a malicious payload into the content file's metadata or content, which will be passed as an argument to the custom script (e.g., `"; touch injected.txt"` in a title field).
    4. Open the workspace containing the malicious `frontmatter.json` in VSCode with the Front Matter extension activated.
    5. Trigger the execution of the custom script. This can be done through the "Custom Actions" in the Front Matter panel or dashboard.
    6. If the vulnerability is successfully triggered, the injected command (e.g., creating `vulnerable.txt` or `injected.txt`) will be executed by the system shell in the context of the VSCode extension.

- **Impact:** **Critical**. Remote code execution. An attacker can gain full control over the user's machine, steal sensitive information, install malware, or perform other malicious actions. Successful exploitation allows an attacker to execute arbitrary commands with the privileges of the VSCode process. This can lead to:
    - Data theft: Accessing and exfiltrating sensitive information from the user's workspace or machine.
    - System compromise: Modifying system files, installing malware, or creating backdoors.
    - Lateral movement: Using the compromised VSCode instance as a stepping stone to access other systems on the network.
- **Vulnerability Rank:** critical
- **Currently implemented mitigations:** No specific mitigations are implemented in the provided code to prevent command injection in custom scripts. The extension allows users to define and execute custom scripts without any sanitization or security checks. The code directly uses `child_process.exec` without sanitizing or validating the arguments passed to the shell command.
- **Missing mitigations:**
    - Input sanitization for custom scripts: Implement robust input sanitization for all arguments passed to custom scripts, especially those derived from user-controlled content (like file metadata or content) or configuration files (`frontmatter.json`). This should include escaping shell metacharacters and validating input formats.
    - Secure execution environment: Consider using safer alternatives to `child_process.exec`, such as `child_process.spawn` with properly escaped arguments, or sandboxing the script execution environment to limit the impact of malicious code.
    - Principle of least privilege: Ensure that the custom scripts are executed with the minimum necessary privileges to reduce the potential impact of successful exploitation.
    - User confirmation before script execution: The extension should prompt the user for confirmation before executing any custom script, especially those defined in workspace configurations that could be controlled by an attacker.
    - Sandboxing or isolation for script execution: Run custom scripts in a sandboxed environment to limit their access to system resources and prevent them from causing harm to the user's machine.
    - Code review: Conduct a thorough security code review of the custom script execution functionality to identify and address any potential injection points or insecure coding patterns.
- **Preconditions:**
    - The Front Matter extension must be installed and activated in VSCode.
    - The user must open a workspace containing a malicious `frontmatter.json` file or have configured at least one custom script within the Front Matter extension settings.
    - The configured custom script must be designed to accept and process command-line arguments or if defined in `frontmatter.json` can be directly malicious.
    - An attacker needs to be able to influence the `frontmatter.json` file in the workspace or input arguments that are passed to the vulnerable custom script. This could be achieved by compromising the workspace, manipulating content files, or potentially other extension settings if they are externally controllable.
- **Source code analysis:**
    - File: `/code/src/helpers/CustomScript.ts`
    - Function: `executeScript(script: ICustomScript, wsPath: string, args: string)` and `executeScriptAsync(fullScript: string, wsPath: string)`
    - Vulnerable code snippet:
    ```typescript
    private static async executeScriptAsync(fullScript: string, wsPath: string): Promise<string> {
      return new Promise((resolve, reject) => {
        exec(fullScript, { cwd: wsPath }, (error, stdout) => { // <-- Vulnerable exec call
          if (error) {
            Logger.error(error.message);
            reject(error.message);
            return;
          }
          // ...
        });
      });
    }
    ```

    ```mermaid
    graph LR
        A[Custom Script Execution Triggered] --> B{Construct Command String};
        B --> C{child_process.exec(fullScript, ...)};
        C --> D{System Shell Execution};
        D -- Malicious Command Injected --> E[Arbitrary Code Execution];
    ```

    The `executeScript` function in `CustomScript.ts` uses `child_process.exec` to run shell commands. The `fullScript` variable is constructed by concatenating the script path and `args`. If the `args` string or the `script.script` from `frontmatter.json` contains unescaped shell metacharacters, an attacker can inject arbitrary commands. The arguments can be constructed using user-controlled data such as `wsPath`, `contentPath`, and `articleData` or directly from `frontmatter.json`. Lack of sanitization of these arguments or script definitions before passing them to `exec` creates a command injection vulnerability leading to remote code execution.

- **Security test case:**
    1. **RCE via `frontmatter.json`:**
        1. Create a new folder named `frontmatter-test-rce`.
        2. Inside `frontmatter-test-rce`, create a file named `frontmatter.json` with the following content:
           ```json
           {
             "version": "1.0.0",
             "frontMatter.custom.scripts": [
               {
                 "id": "rce-test",
                 "title": "RCE Test",
                 "description": "Test for RCE vulnerability",
                 "script": "echo 'Vulnerable' > vulnerable.txt",
                 "type": "content",
                 "command": "node"
               }
             ]
           }
           ```
        3. Open the `frontmatter-test-rce` folder in VSCode.
        4. Open the Front Matter panel.
        5. In the Front Matter panel, navigate to "Actions" section.
        6. Click on the "RCE Test" custom action.
        7. After the script execution, check the `frontmatter-test-rce` folder. A new file named `vulnerable.txt` should be created, containing the text "Vulnerable". This proves that arbitrary commands can be executed.

    2. **Command Injection via Custom Script Arguments:**
        1. Open a VSCode workspace with the Front Matter extension installed and activated.
        2. In the Front Matter settings (`frontmatter.custom.scripts`), add a new custom script with the following configuration:
            - Title: `Test Command Injection`
            - Script: `/code/sample/script-sample.js` (or any other script path that exists and can echo arguments, replace `/code/sample/script-sample.js` with an absolute path to the `script-sample.js` file from the provided PROJECT FILES if needed)
            - Command: `node`
            - Bulk: unchecked
        3. Modify the `/code/sample/script-sample.js` file (if you are using it) to simply echo all arguments:
            ```javascript
            const arguments = process.argv;
            console.log(arguments.slice(2).join(" "));
            ```
        4. Create a new markdown file or open an existing one managed by Front Matter.
        5. In the frontmatter of the markdown file, set the `title` to: `Test Article Title\"; touch injected.txt; echo \"`. This is the malicious payload.
        6. In the Front Matter panel, under "Custom Actions", execute the newly created "Test Command Injection" script.
        7. After the script execution, check the workspace root folder for a file named `injected.txt`. If the file exists, it indicates that the command injection vulnerability is present and exploitable.


### Cross-Site Scripting (XSS) in Webviews

- **Vulnerability Name:** Cross-Site Scripting (XSS) in Webviews
- **Description:** An attacker could potentially inject malicious JavaScript code into the webviews of the Front Matter extension. This could be achieved by crafting a malicious markdown file or data file that, when processed and displayed within a webview, executes the injected script.

    Steps to trigger vulnerability:
    1. Create a markdown or data file in the workspace managed by Front Matter.
    2. In the front matter or content of the file, inject malicious JavaScript code. For example, in a markdown file's front matter, add a field like `description: "<img src='x' onerror='alert(\"XSS\")'>"` or in the content `![alt](<img src='x' onerror='alert(\"XSS\")'>)`.
    3. Open the markdown or data file within VSCode and activate the Front Matter panel or dashboard, which renders a webview previewing or displaying file metadata.
    4. The webview, when rendering the crafted content, will execute the injected JavaScript code, leading to XSS.

- **Impact:** Successful exploitation could allow an attacker to:
    - Steal sensitive information, such as user tokens or workspace data, if accessible within the webview context.
    - Perform actions on behalf of the user within the VSCode environment, potentially leading to further compromise.
    - Redirect the user to malicious websites or display misleading information within the extension's UI.
- **Vulnerability Rank:** high
- **Currently implemented mitigations:**
    - Content Security Policy (CSP) is implemented in the webviews (e.g., in `webpack/dashboard.config.js` and `webpack/panel.config.js`). However, the CSP might not be strict enough to prevent all types of XSS attacks, especially if `unsafe-inline` or `unsafe-eval` are allowed for scripts, or if there are loopholes in the CSP configuration.
    - The code uses `WebviewHelper.getNonce()` in `PanelProvider.ts`, `Preview.ts` and `Chatbot.ts` which is intended to enhance CSP security by using nonces for script execution.
- **Missing mitigations:**
    - **Strict CSP:** Enforce a stricter Content Security Policy that disallows `unsafe-inline` and `unsafe-eval` for scripts. Ensure that the CSP is correctly applied to all webviews and that there are no bypasses.
    - **Input Sanitization:** Implement robust input sanitization for all user-controlled data rendered in webviews. This should include sanitizing front matter data, content body, and any other data sources that influence webview rendering. Use a trusted sanitization library to prevent XSS.
    - **Code Review for XSS Vulnerabilities:** Conduct a thorough code review specifically targeting potential XSS vulnerabilities in webview rendering logic, especially in components that display user content like content previews, data dashboards, and panel views.
- **Preconditions:**
    - The user must open a workspace containing a malicious markdown or data file with the Front Matter extension active.
    - The Front Matter extension's panel or dashboard must be used to preview or display the crafted content.
- **Source code analysis:**
    - Files potentially involved in rendering user content in webviews include:
        - `/code/src/panelWebView/PanelProvider.ts`: Creates and manages the main panel webview.
        - `/code/src/dashboardWebView/*`: Contains components for the dashboard webview, including content and media display.
        - `/code/src/commands/Preview.ts`: Handles the preview webview.
    - The CSP is set up in webpack configs (`/code/webpack/dashboard.config.js`, `/code/webpack/panel.config.js`, `/code/webpack/panel.config.js`), but needs to be reviewed for strictness.
    - The use of `WebviewHelper.getNonce()` suggests an attempt to mitigate XSS, but the implementation and effectiveness need to be verified.
    - Code in `/code/src/dashboardWebView/components/` and `/code/src/panelWebView/` should be examined for how user-provided data is rendered and if it's properly sanitized. For instance, check how fields like `title`, `description`, and content are displayed in the UI, particularly in card components and detail panels.
- **Security test case:**
    1. Create a new markdown file named `xss-test.md` in a workspace folder opened in VSCode.
    2. Add the following front matter to the file:
        ```markdown
        ---
        title: XSS Test
        description: "<img src='x' onerror='alert(\"XSS in Description\")'>"
        ---
        ![XSS](<img src='x' onerror='alert(\"XSS in Content\")'>)
        ```
    3. Save the `xss-test.md` file.
    4. Open the Front Matter panel in VSCode (`Ctrl+Shift+P` or `Cmd+Shift+P` and type "Front Matter: Open Panel").
    5. Navigate to the "Contents" section in the Front Matter panel.
    6. Observe if an alert box appears with "XSS in Description" or "XSS in Content". If an alert box appears, it confirms the XSS vulnerability.


### Path Traversal in Custom Scripts

- **Vulnerability Name:** Path Traversal in Custom Scripts
- **Description:** Custom scripts in Front Matter extension may be vulnerable to path traversal attacks. If a custom script is designed to handle file paths received from the extension, a malicious actor could craft a path that escapes the intended directory, potentially allowing access to sensitive files or directories outside the workspace.
- **Impact:** **High**. Path traversal can lead to unauthorized file system access, information disclosure, or even remote code execution if combined with other vulnerabilities.
- **Vulnerability Rank:** high
- **Currently implemented mitigations:** None. The extension does not perform any path sanitization or validation when passing file paths to custom scripts.
- **Missing mitigations:**
    - Path sanitization: Sanitize file paths passed to custom scripts to ensure they are within the intended workspace or media folders.
    - Input validation: Validate user-provided file paths to prevent path traversal attempts.
    - Limiting script access: Restrict the file system access of custom scripts to only the intended directories.
- **Preconditions:**
    - The victim user must open a workspace containing a malicious `frontmatter.json` file with a custom script that processes file paths.
    - The victim user must execute the malicious custom script.
    - The custom script must be designed to handle file paths passed from the extension.
- **Source code analysis:**
    - File: `/code/src/helpers/CustomScript.ts`
    - The extension passes `wsPath` and `contentPath` as arguments to the custom scripts. If these paths are not handled securely within the custom script, they could be exploited for path traversal.
    - ```typescript
      private static async executeScript(
        script: ICustomScript,
        wsPath: string,
        args: string
      ): Promise<string> {
        // ...
        const fullScript = `${command} "${scriptPath}" ${args}`; // wsPath and contentPath are part of args
        Logger.info(localize(LocalizationKey.helpersCustomScriptExecuting, fullScript));

        const output = await CustomScript.processExecution(fullScript, wsPath);
        return output;
      }
      ```
    - If a malicious user crafts a `frontmatter.json` with a custom script that processes `process.argv[2]` (workspace path) or `process.argv[3]` (content path) without proper validation, a path traversal vulnerability can be introduced.
    - File: `/code/sample/script-sample.js`
    - This sample script shows how arguments are accessed in custom scripts.
    - ```javascript
      const arguments = process.argv;

      if (arguments && arguments.length > 0) {
        const workspaceArg = arguments[2]; // The workspace path
        const fileArg = arguments[3]; // The file path
        const frontMatterArg = arguments[4]; // Front matter data

        console.log(`The content returned for your notification.`);
      }
      ```
- **Security test case:**
    1. Create a new folder named `frontmatter-test-path-traversal`.
    2. Inside `frontmatter-test-path-traversal`, create a file named `frontmatter.json` with the following content:
        ```json
        {
          "version": "1.0.0",
          "frontMatter.custom.scripts": [
            {
              "id": "path-traversal-test",
              "title": "Path Traversal Test",
              "description": "Test for path traversal vulnerability",
              "script": "const fs = require('fs'); const path = require('path'); const filePath = path.join(process.argv[2], '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', '..', 'etc', 'passwd'); fs.readFile(filePath, 'utf8', (err, data) => { if (err) { console.error(err); } else { console.log(data); } });",
              "type": "content",
              "command": "node"
            }
          ]
        }
        ```
    3. Open the `frontmatter-test-path-traversal` folder in VSCode.
    4. Open the Front Matter panel.
    5. In the Front Matter panel, navigate to "Actions" section.
    6. Click on the "Path Traversal Test" custom action.
    7. Check the Front Matter output panel. If the script successfully reads and outputs the content of `/etc/passwd` (or similar sensitive file depending on the OS), it indicates a path traversal vulnerability.