- Vulnerability name: Command Injection in Custom Scripts
- Description: An external attacker could potentially inject malicious commands into custom scripts defined in the Front Matter extension settings. These scripts are executed by the extension using `child_process.exec`, which can be vulnerable to command injection if arguments are not properly sanitized.

To trigger this vulnerability:
    1. Define a custom script in the Front Matter settings that is designed to process arguments, for example, a script that logs the arguments to the console.
    2. As an attacker, create or modify a content file in the workspace.
    3. Introduce a malicious payload into the content file's metadata or content, which will be passed as an argument to the custom script. For example, if a custom script processes the article title, set the title to include a malicious command like `"; touch injected.txt"` or similar command suitable for the target operating system.
    4. Trigger the execution of the custom script. This could be done through a custom action configured in the Front Matter panel, or if the script is automatically triggered on certain events (though automatic triggering based on file content is less likely in this extension context but should be checked in the code).
    5. If the vulnerability is successfully triggered, the injected command (e.g., `touch injected.txt`) will be executed by the system shell in the context of the VSCode extension.

- Impact: Arbitrary code execution on the user's machine. Successful exploitation allows an attacker to execute arbitrary commands with the privileges of the VSCode process. This can lead to:
    - Data theft: Accessing and exfiltrating sensitive information from the user's workspace or machine.
    - System compromise: Modifying system files, installing malware, or creating backdoors.
    - Lateral movement: Using the compromised VSCode instance as a stepping stone to access other systems on the network.
- Vulnerability rank: High
- Currently implemented mitigations: No specific mitigations are implemented in the provided code to prevent command injection in custom scripts. The code directly uses `child_process.exec` without sanitizing or validating the arguments passed to the shell command.
- Missing mitigations:
    - Input sanitization: Implement robust input sanitization for all arguments passed to custom scripts, especially those derived from user-controlled content (like file metadata or content). This should include escaping shell metacharacters and validating input formats.
    - Secure execution environment: Consider using safer alternatives to `child_process.exec`, such as `child_process.spawn` with properly escaped arguments, or sandboxing the script execution environment to limit the impact of malicious code.
    - Principle of least privilege: Ensure that the custom scripts are executed with the minimum necessary privileges to reduce the potential impact of successful exploitation.
    - Code review: Conduct a thorough security code review of the custom script execution functionality to identify and address any potential injection points or insecure coding patterns.
- Preconditions:
    - The Front Matter extension must be installed and activated in VSCode.
    - The user must have configured at least one custom script within the Front Matter extension settings.
    - The configured custom script must be designed to accept and process command-line arguments.
    - An attacker needs to be able to influence the input arguments that are passed to the vulnerable custom script. This could be achieved by manipulating content files, or potentially other extension settings if they are externally controllable.
- Source code analysis:
    - File: `/code/src/helpers/CustomScript.ts`
    - Function: `executeScript(script: ICustomScript, wsPath: string, args: string)`
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

    The `executeScript` function in `CustomScript.ts` uses `child_process.exec` to run shell commands. The `fullScript` variable is constructed by concatenating the script path and `args`. If the `args` string contains unescaped shell metacharacters, an attacker can inject arbitrary commands. The arguments are constructed using user-controlled data such as `wsPath`, `contentPath`, and `articleData`. Lack of sanitization of these arguments before passing them to `exec` creates a command injection vulnerability.

- Security test case:
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

Rank: high