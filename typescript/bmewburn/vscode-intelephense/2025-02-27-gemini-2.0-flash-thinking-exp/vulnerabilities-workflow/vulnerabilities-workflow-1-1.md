## Vulnerability List:

### 1. Command Injection via `intelephense.runtime` setting

* Description:
    1. The Intelephense extension allows users to configure a custom runtime executable path using the `intelephense.runtime` setting in VSCode settings.
    2. The `createClient` function in `src/extension.ts` reads this setting and directly uses it as the `runtime` for spawning the language server process via `serverOptions.run.runtime = runtime;` and `serverOptions.debug.runtime = runtime;`.
    3. There is no sanitization or validation of the `runtime` setting before it is used in the `child_process.spawn` command internally by `vscode-languageclient`.
    4. An attacker can modify the `intelephense.runtime` setting to inject arbitrary commands that will be executed on the machine when the extension starts or restarts the language server.

* Impact:
    - **Critical**
    - Remote Code Execution (RCE) on the user's machine. An attacker can execute arbitrary commands with the privileges of the VSCode process, which is typically the user's privileges. This can lead to complete compromise of the user's local machine, including data theft, malware installation, and further system exploitation.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    - None. The code directly uses the user-provided `intelephense.runtime` setting without any validation or sanitization.

* Missing mitigations:
    - Input validation and sanitization for the `intelephense.runtime` setting.
    - Restricting the `runtime` setting to only accept absolute paths to executable files and disallowing any shell metacharacters or command separators.
    - Ideally, removing the ability for users to specify a custom runtime altogether if it's not a core feature and introduces significant security risk. If a custom runtime is necessary, use a safer mechanism than directly passing it to `child_process.spawn` without sanitization.

* Preconditions:
    - The attacker needs to be able to modify the VSCode settings for the workspace or user settings. This could be achieved through:
        - Social engineering to trick the user into manually changing the setting.
        - Exploiting another vulnerability in VSCode or another extension that allows modifying settings.
        - If the attacker has write access to the workspace settings file (`.vscode/settings.json` in the workspace root).

* Source code analysis:
    1. **File: `/code/src/extension.ts`**
    2. **Function: `createClient(context:ExtensionContext, middleware:IntelephenseMiddleware, clearCache:boolean)`**
    3. Locate the code block that reads the `intelephense.runtime` setting:
       ```typescript
       let intelephenseConfig = workspace.getConfiguration('intelephense');
       let runtime = intelephenseConfig.get('runtime') as string | undefined;
       // ...
       if (runtime) {
           serverOptions.run.runtime = runtime;
           serverOptions.debug.runtime = runtime;
       }
       ```
    4. Observe that the `runtime` variable, directly obtained from the user configuration, is assigned to `serverOptions.run.runtime` and `serverOptions.debug.runtime`.
    5. Review the `vscode-languageclient` documentation or source code to confirm that the `runtime` option in `ServerOptions` is directly used in `child_process.spawn` or similar functions to execute the language server. Based on typical Node.js `child_process` usage, and lack of sanitization in Intelephense code, command injection is highly likely.
    6. **Visualization:**

       ```
       User Setting (intelephense.runtime) -->  extension.ts (createClient) --> serverOptions.run.runtime --> vscode-languageclient --> child_process.spawn --> System Command Execution
       ```

* Security test case:
    1. Open VSCode with the Intelephense extension installed and activated.
    2. Open the VSCode settings (File -> Preferences -> Settings, or Code -> Settings -> Settings on macOS).
    3. Navigate to the Extension settings for Intelephense (search for "intelephense" in the settings search bar).
    4. Locate the `Intelephense › Runtime` setting.
    5. Modify the `Intelephense › Runtime` setting to the following malicious command (example for Linux/macOS, adjust for Windows if needed): ``/bin/bash -c "touch /tmp/pwned"``
    6. Restart VSCode or trigger a language server restart (e.g., by running the "Intelephense: Index Workspace" command).
    7. Check if the command was executed. In this example, check if the file `/tmp/pwned` was created. If the file exists, the command injection is successful.
    8. For Windows, a similar test can be performed using `cmd.exe /c echo pwned > %TEMP%\pwned.txt` as the runtime.