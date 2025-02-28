## Vulnerability List

- Vulnerability Name: **Remote Code Execution via Custom Scripts**
- Description: An attacker can craft a malicious Front Matter project configuration (`frontmatter.json`) that defines a custom script with arbitrary commands. When a user opens a workspace with this malicious configuration and executes the custom script through the Front Matter panel or dashboard, the attacker's commands will be executed on the user's machine with the privileges of the VSCode process.
- Impact: **Critical**. Remote code execution. An attacker can gain full control over the user's machine, steal sensitive information, install malware, or perform other malicious actions.
- Vulnerability Rank: critical
- Currently implemented mitigations:
  - None. The extension allows users to define and execute custom scripts without any sanitization or security checks.
- Missing mitigations:
  - Input sanitization for custom scripts: The extension should sanitize or validate the custom script commands to prevent execution of arbitrary code.
  - User confirmation before script execution: The extension should prompt the user for confirmation before executing any custom script, especially those defined in workspace configurations that could be controlled by an attacker.
  - Sandboxing or isolation for script execution: Run custom scripts in a sandboxed environment to limit their access to system resources and prevent them from causing harm to the user's machine.
- Preconditions:
  - The victim user must open a workspace containing a malicious `frontmatter.json` file.
  - The malicious `frontmatter.json` must define a custom script with attacker-controlled commands.
  - The victim user must execute the malicious custom script through the Front Matter extension's UI (panel or dashboard).
- Source code analysis:
  - File: `/code/src/helpers/CustomScript.ts`
  - The `CustomScript.executeScript` method directly executes user-defined scripts using `child_process.exec`.
  - ```typescript
    private static async executeScript(
      script: ICustomScript,
      wsPath: string,
      args: string
    ): Promise<string> {
      // ...
      const fullScript = `${command} "${scriptPath}" ${args}`;
      Logger.info(localize(LocalizationKey.helpersCustomScriptExecuting, fullScript));

      const output = await CustomScript.processExecution(fullScript, wsPath);
      return output;
    }

    private static async processExecution(fullScript: string, wsPath: string): Promise<string> {
      const output: string = await CustomScript.executeScriptAsync(fullScript, wsPath);
      // ...
    }

    private static async executeScriptAsync(fullScript: string, wsPath: string): Promise<string> {
      return new Promise((resolve, reject) => {
        exec(fullScript, { cwd: wsPath }, (error, stdout) => { // Vulnerability: Using exec to run user-defined script
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
  - The `script.script` value, which is directly used in `exec`, is loaded from the `frontmatter.json` configuration file, which can be manipulated by an attacker in a compromised workspace.
- Security test case:
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

- Vulnerability Name: **Path Traversal in Custom Scripts**
- Description: Custom scripts in Front Matter extension may be vulnerable to path traversal attacks. If a custom script is designed to handle file paths received from the extension, a malicious actor could craft a path that escapes the intended directory, potentially allowing access to sensitive files or directories outside the workspace.
- Impact: **High**. Path traversal can lead to unauthorized file system access, information disclosure, or even remote code execution if combined with other vulnerabilities.
- Vulnerability Rank: high
- Currently implemented mitigations:
  - None. The extension does not perform any path sanitization or validation when passing file paths to custom scripts.
- Missing mitigations:
  - Path sanitization: Sanitize file paths passed to custom scripts to ensure they are within the intended workspace or media folders.
  - Input validation: Validate user-provided file paths to prevent path traversal attempts.
  - Limiting script access: Restrict the file system access of custom scripts to only the intended directories.
- Preconditions:
  - The victim user must open a workspace containing a malicious `frontmatter.json` file with a custom script that processes file paths.
  - The victim user must execute the malicious custom script.
  - The custom script must be designed to handle file paths passed from the extension.
- Source code analysis:
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
- Security test case:
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