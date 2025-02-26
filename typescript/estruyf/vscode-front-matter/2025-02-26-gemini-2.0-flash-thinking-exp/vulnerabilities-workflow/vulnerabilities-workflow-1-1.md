## Vulnerability List for Front Matter CMS VSCode Extension

- Vulnerability Name: Command Injection via URI Handler and Message Passing
- Description:
    1. An attacker can trigger command execution through two distinct pathways:
        - **URI Handler:** Crafting a malicious URI that targets the Front Matter CMS VSCode extension.
            - The URI includes a `command` query parameter, starting with the `frontMatter.` prefix to bypass the initial prefix check.
            - The attacker sets the `command` to a sensitive or internal extension command, potentially with manipulated `args` query parameter.
            - When a user clicks on this malicious URI, the VSCode extension's registered URI handler is invoked.
        - **Message Passing (`runCommand`):** Sending a crafted message to the extension's message handler with the `runCommand` command.
            - The message payload includes `command` and `args` properties.
            - This message can be sent from a compromised webview or another extension if message communication is not properly secured.
    2. In both scenarios, the `handleUri` function (for URI) or `BaseListener.process` (for message passing) extracts the `command` and `args`.
    3. Without sufficient validation of the command against a whitelist or sanitization of arguments, the function executes the command using `commands.executeCommand(command, args)`.
    4. This can lead to the execution of unintended extension commands, potentially allowing unauthorized actions within the extension's context.
- Impact:
    - Unauthorized execution of extension commands.
    - Potential information disclosure (though less likely via URI handling).
    - Possible manipulation of extension settings or state.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    - Prefix Check: The `UriHandler` verifies if the received command starts with `EXTENSION_COMMAND_PREFIX` (`frontMatter.`), acting as a basic namespace control. This mitigation is also present in `BaseListener` as the `GeneralCommands.toVSCode.runCommand` is a defined constant.
    - JSON Parsing Error Handling: The argument parsing attempts to parse arguments as JSON, and errors during parsing are ignored, preventing crashes due to malformed arguments, but not preventing command injection itself.
- Missing Mitigations:
    - Command Whitelist: Implement a whitelist of allowed commands that can be executed via the URI handler and `runCommand` message. This would prevent the execution of sensitive or unintended commands.
    - Argument Validation and Sanitization: Validate and sanitize arguments passed to `commands.executeCommand` to prevent malicious inputs from causing unintended behavior or security issues within the executed commands themselves.
- Preconditions:
    - **URI Handler:** A user must click on a maliciously crafted URI that is designed to target the Front Matter CMS VSCode extension.
    - **Message Passing (`runCommand`):** An attacker needs to be able to send messages to the extension, either by compromising a webview within the extension or through another malicious extension.
- Source Code Analysis:
    ```typescript
    // File: /code/src/providers/UriHandler.ts
    import { commands, Uri, window } from 'vscode';
    import { EXTENSION_COMMAND_PREFIX } from '../constants';

    export class UriHandler {
      /**
       * Register the URI handler
       */
      public static register() {
        window.registerUriHandler({
          handleUri(uri: Uri) {
            const queryParams = new URLSearchParams(uri.query);
            if (!queryParams.has('command')) {
              return;
            }

            const command = queryParams.get('command'); // [1] Command is extracted from URI query
            let args = queryParams.get('args'); // [2] Arguments are extracted from URI query

            if (!command || !command.startsWith(EXTENSION_COMMAND_PREFIX)) { // [3] Prefix check
              return;
            }

            if (args) {
              try {
                args = JSON.parse(args); // [4] Arguments are parsed as JSON
              } catch (error) {
                // Ignore error
              }
            }

            commands.executeCommand(command, args); // [5] Command is executed without further validation
          }
        });
      }
    }
    ```
    ```typescript
    // File: /code/src/listeners/general/BaseListener.ts
    import { GeneralCommands } from './../../constants/GeneralCommands';
    import { commands, Uri } from 'vscode';
    import { PostMessageData } from '../../models';

    export abstract class BaseListener {
      public static process(msg: PostMessageData) {
        switch (msg.command) {
          case GeneralCommands.toVSCode.runCommand: // [A] runCommand message handler
            if (msg.payload) {
              const { command, args } = msg.payload; // [B] Command and args extraction
              commands.executeCommand(command, args); // [C] Command execution
            }
            break;
          // ... other cases
        }
      }
      // ... rest of the class
    }
    ```
    - **URI Handler Flow:**
        - [1] `const command = queryParams.get('command');` - The `command` is directly extracted from the URI query parameter named `command`.
        - [2] `let args = queryParams.get('args');` - Similarly, `args` are extracted from the `args` query parameter.
        - [3] `if (!command || !command.startsWith(EXTENSION_COMMAND_PREFIX)) { return; }` - A check is performed to ensure that the extracted `command` starts with the `EXTENSION_COMMAND_PREFIX` (which is `frontMatter.`). This is intended to restrict command execution to extension-specific commands.
        - [4] `args = JSON.parse(args);` - The `args` string is parsed as JSON to be passed as arguments to the command. Error handling is present, but it only ignores parsing errors, not malicious content within valid JSON.
        - [5] `commands.executeCommand(command, args);` - The extracted and potentially parsed `command` and `args` are directly passed to `commands.executeCommand` for execution. **Vulnerability:** There is no further validation on the `command` itself to ensure it's a safe or intended command to be exposed via URI handling, nor is there sanitization or validation of the `args` before execution.
    - **Message Passing (`runCommand`) Flow:**
        - [A] `case GeneralCommands.toVSCode.runCommand:` -  The `BaseListener.process` function handles the `GeneralCommands.toVSCode.runCommand` message.
        - [B] `const { command, args } = msg.payload;` - The `command` and `args` are extracted directly from the message payload.
        - [C] `commands.executeCommand(command, args);` - The extracted `command` and `args` are executed using `commands.executeCommand`. **Vulnerability:** Similar to the URI handler, there is no validation or sanitization of the `command` or `args` before execution, leading to potential command injection.

- Security Test Case:
    1. **URI Handler Test Case (same as before):**
        1. Craft a malicious URI: `vscode://eliostruyf.vscode-front-matter?command=frontMatter.showOutputChannel&args=%7B%22text%22%3A%22Malicious%20Output%22%7D`
            - `command=frontMatter.showOutputChannel`: Specifies the command to execute, which is a valid internal command of the extension to show output channel.
            - `args=%7B%22text%22%3A%22Malicious%20Output%22%7D`: Provides URL-encoded JSON arguments `{"text": "Malicious Output"}` for the `showOutputChannel` command.
        2. Distribute the malicious URI to a user, for example, by embedding it in a webpage, email, or chat message.
        3. The user clicks on the malicious URI. VSCode will attempt to open the URI, triggering the registered `UriHandler` of the Front Matter extension.
        4. Observe the execution: The "Front Matter CMS" output channel will be displayed in VSCode, and it will contain the text "Malicious Output", which was passed as an argument in the malicious URI.
        5. Successful Command Execution: This outcome demonstrates that an attacker can successfully trigger and execute specific extension commands by crafting a malicious URI, highlighting the URI Handler Command Injection vulnerability.
    2. **Message Passing (`runCommand`) Test Case:**
        1. Open the Front Matter CMS Dashboard or Panel.
        2. Open the developer tools for the webview (e.g., right-click on the webview and select "Inspect").
        3. In the developer tools console, execute the following code to send a malicious message to the extension:
           ```javascript
           const vscode = acquireVsCodeApi();
           vscode.postMessage({
               command: 'runCommand',
               payload: {
                   command: 'frontMatter.showOutputChannel',
                   args: { text: 'Malicious Output via runCommand' }
               }
           });
           ```
        4. Observe the execution: The "Front Matter CMS" output channel will be displayed in VSCode, and it will contain the text "Malicious Output via runCommand", which was passed as an argument in the malicious message.
        5. Successful Command Execution: This outcome demonstrates that an attacker can successfully trigger and execute specific extension commands by crafting a malicious message with the `runCommand` command, highlighting the Command Injection vulnerability via message passing.

- Vulnerability Name: SSG Content Config Command Injection
- Description:
    1. The `SsgListener` uses `child_process.exec` to execute a Node.js script (`astroContentCollectionScript`) to get Astro content types.
    2. The script takes the path to the content configuration file (`contentConfigFile.fsPath`) as an argument.
    3. If the content of `astroContentCollectionScript` is vulnerable and executes code from the content configuration file (e.g., using `eval` or similar), an attacker could craft a malicious content configuration file (e.g., `content/config.js`) within the workspace.
    4. When the extension executes `astroContentCollectionScript` with this malicious config file path, it could lead to arbitrary code execution within the extension's context.
- Impact:
    - Arbitrary code execution within the VSCode extension's context.
    - This could allow an attacker to perform actions such as reading/writing files within the workspace, exfiltrating data, or potentially gaining further access to the user's system depending on the extension's permissions and the nature of the executed code.
- Vulnerability Rank: critical
- Currently Implemented Mitigations:
    - Temporary Script: The script is copied to a temporary location before execution.
    - Deletion of Temp Folder: The temporary folder is deleted after execution.
- Missing Mitigations:
    - Secure Script Execution: The `astroContentCollectionScript` should be reviewed and rewritten to avoid insecure practices like `eval` or similar methods that could execute code from user-provided files. The script should parse the config file safely (e.g., using JSON.parse if it's expected to be JSON, or using a secure AST parser for JS/TS).
    - Input Validation/Sanitization: While the root cause is in the external script, consider validating the content of `contentConfigFile.fsPath` in the extension before passing it to the script as a defense-in-depth measure if feasible.
- Preconditions:
    - The attacker needs to trick a user into opening a VSCode workspace that contains a malicious content configuration file (e.g., `content/config.js`) in the expected location (e.g., `src/content/config.js`).
    - The `astroContentCollectionScript` (not provided in PROJECT FILES) must be vulnerable to command injection by executing code from the content configuration file.
- Source Code Analysis:
    ```typescript
    // File: /code/src/listeners/dashboard/SsgListener.ts
    private static async getAstroContentTypes({ command, requestId }: PostMessageData) {
        ...
        const contentConfig = await workspace.findFiles(`**/src/content/config.*`); // [1] Find config file
        ...
        const scriptPath = Uri.joinPath( // [2] Path to script
          Extension.getInstance().extensionPath,
          SsgScripts.folder,
          SsgScripts.astroContentCollectionScript
        );
        ...
        const tempScriptPath = Uri.joinPath(tempLocation, SsgScripts.astroContentCollectionScript); // [3] Temp script path
        ...
        const fullScript = `${nodeExecPath} "${tempScriptPath.fsPath}" "${contentConfigFile.fsPath}"`; // [4] Construct command
        ...
        try {
          const result: string = await SsgListener.executeScript(fullScript, wsFolder?.fsPath || ''); // [5] Execute script
          ...
        } finally {
          await workspace.fs.delete(tempLocation, { recursive: true, useTrash: false }); // [6] Cleanup
        }
    }

    private static executeScript(fullScript: string, wsFolder: string): Promise<string> {
        return new Promise((resolve, reject) => {
          exec(fullScript, { cwd: wsFolder }, (error, stdout) => { ... }); // [7] Command execution
        });
    }
    ```
    - [1] `workspace.findFiles(\`**/src/content/config.*\`)` - Finds the content config file in the workspace. An attacker can create a malicious config file in the workspace.
    - [2] `scriptPath = Uri.joinPath(...)` - Gets the path to the script. This script is part of the extension.
    - [3] `tempScriptPath = Uri.joinPath(...)` - Creates a temporary path for the script.
    - [4] `fullScript = `${nodeExecPath} "${tempScriptPath.fsPath}" "${contentConfigFile.fsPath}"`` - Constructs the command to execute, including the path to the user-controlled `contentConfigFile.fsPath`.
    - [5] `SsgListener.executeScript(fullScript, ...)` - Executes the constructed command.
    - [7] `exec(fullScript, ...)` - Executes the shell command. **Vulnerability:** If `astroContentCollectionScript` (not in PROJECT FILES) insecurely processes `contentConfigFile.fsPath`, it can lead to command injection.
- Security Test Case:
    1. Create a new VSCode workspace.
    2. Inside the workspace, create a folder `src` and then a subfolder `content`.
    3. Inside `content`, create a file named `config.js` (or any extension matched by `**/src/content/config.*`).
    4. Add the following malicious JavaScript code to `config.js`:
       ```javascript
       // config.js
       console.log(process.env);
       require('child_process').execSync('touch /tmp/pwned');
       ```
    5. Open the newly created workspace in VSCode.
    6. Open the Front Matter CMS Dashboard. This action should trigger the `ssgGetAstroContentTypes` command in `SsgListener.ts`.
    7. Observe the results. If the vulnerability exists and is successfully exploited, a file named `pwned` should be created in the `/tmp/` directory.
    8. Successful Command Injection: The creation of the `pwned` file (or other injected commands being executed) confirms the SSG Content Config Command Injection vulnerability.

- Vulnerability Name: Custom Placeholder Script Command Injection
- Description:
    1. The `ArticleHelper.processCustomPlaceholders` function allows users to define custom placeholders with associated scripts.
    2. These scripts are executed using `CustomScript.executeScript`, which utilizes `child_process.exec` to run shell commands.
    3. An attacker can craft a malicious custom placeholder script within the extension's settings.
    4. If a user uses this malicious placeholder in their content or configuration, and the `ArticleHelper.processCustomPlaceholders` function is triggered to process this content, the malicious script will be executed.
    5. This can lead to arbitrary code execution within the extension's context when the extension processes content containing the malicious placeholder.
- Impact:
    - Arbitrary code execution within the VSCode extension's context.
    - This could allow an attacker to perform actions such as reading/writing files within the workspace, exfiltrating data, or potentially gaining further access to the user's system depending on the extension's permissions and the nature of the executed code.
- Vulnerability Rank: critical
- Currently Implemented Mitigations:
    - None in the provided code.
- Missing Mitigations:
    - Secure Script Execution: Instead of using `child_process.exec`, which executes shell commands and is vulnerable to command injection, the extension should use a safer method to execute scripts, such as `child_process.spawn` with arguments separated from the command, or even better, execute the script in a sandboxed environment or use a secure JavaScript runtime.
    - Input Validation and Sanitization: Validate and sanitize the script content defined in custom placeholders to prevent injection of malicious commands. Consider limiting the characters allowed in the script or parsing the script to ensure it only contains intended code.
    - Command Whitelist/Allowlist: If possible, define a whitelist or allowlist of commands that are permitted to be executed within custom placeholder scripts. This would restrict the attacker's ability to execute arbitrary commands.
    - User Confirmation/Warning: Before executing any custom placeholder script, display a warning to the user, especially if the script is defined in workspace settings, as these can be controlled by malicious workspaces. Request user confirmation before script execution.
- Preconditions:
    - An attacker needs to configure a malicious custom placeholder script in the Front Matter CMS extension settings. This could be achieved if the user is tricked into importing malicious settings or if the attacker has write access to the user's settings file.
    - A user must then use this malicious placeholder in their markdown content or trigger a function that processes content with placeholders (e.g., creating a new content, updating content, previewing content, etc.).
- Source Code Analysis:
    ```typescript
    // File: /code/src/helpers/ArticleHelper.ts
    public static async processCustomPlaceholders(
        value: string,
        title: string | undefined,
        filePath: string | undefined,
        skipFileCheck = false
      ) {
        if (value && typeof value === 'string') {
          const dateFormat = Settings.get(SETTING_DATE_FORMAT) as string;
          const placeholders = Settings.get<CustomPlaceholder[]>(SETTING_CONTENT_PLACEHOLDERS);
          if (placeholders && placeholders.length > 0) {
            for (const placeholder of placeholders) {
              if (value.includes(`{{${placeholder.id}}}`)) {
                try {
                  let placeHolderValue = placeholder.value || '';
                  if (placeholder.script) {
                    const wsFolder = Folders.getWorkspaceFolder();
                    const script = {
                      title: placeholder.id,
                      script: placeholder.script,
                      command: placeholder.command
                    };
                    let output: string | any = await CustomScript.executeScript( // [1] Script execution
                      script,
                      wsFolder?.fsPath || '',
                      `'${wsFolder?.fsPath}' '${filePath}' '${title}'` // [2] Arguments passed to script
                    );

                    if (output) {
                      // Check if the output needs to be parsed
                      if (output.includes('{') && output.includes('}')) {
                        try {
                          output = jsoncParser.parse(output);
                        } catch (e) {
                          // Do nothing
                        }
                      } else {
                        if (output.includes('\n')) {
                          output = output.split('\n');
                        }
                      }

                      placeHolderValue = output;
                    }
                  }

                  let updatedValue = placeHolderValue;

                  // Check if the file already exists, during creation it might not exist yet
                  if (filePath && (await existsAsync(filePath)) && !skipFileCheck) {
                    updatedValue = await processArticlePlaceholdersFromPath(placeHolderValue, filePath);
                  }

                  updatedValue = processTimePlaceholders(updatedValue, dateFormat);

                  if (value === `{{${placeholder.id}}}`) {
                    value = updatedValue;
                  } else {
                    const regex = new RegExp(`{{${placeholder.id}}}`, 'g');
                    value = value.replace(regex, updatedValue);
                  }
                } catch (e) {
                  Notifications.error(
                    l10n.t(
                      LocalizationKey.helpersArticleHelperProcessCustomPlaceholdersPlaceholderError,
                      placeholder.id
                    )
                  );
                  Logger.error((e as Error).message);

                  value = DefaultFieldValues.faultyCustomPlaceholder;
                }
              }
            }
          }
        }

        return value;
      }

    // File: /code/src/helpers/CustomScript.ts
    import { exec } from 'child_process';
    import { CustomScript as ICustomScript } from '../models';

    export class CustomScript {
      /**
       * Execute a custom script
       * @param script
       * @param wsFolder
       * @param args
       * @returns
       */
      public static executeScript(script: ICustomScript, wsFolder: string, args?: string): Promise<string | undefined> {
        return new Promise((resolve, reject) => {
          if (!script || !script.script) {
            return resolve(undefined);
          }

          let scriptToRun = script.script;
          if (script.command) {
            scriptToRun = `${script.command} ${scriptToRun}`;
          }

          if (args) {
            scriptToRun += ` ${args}`; // [3] Arguments appended to script
          }

          exec(scriptToRun, { // [4] Command executed using exec
            cwd: wsFolder
          }, (err, stdout, stderr) => {
            if (err) {
              console.error(`Error executing script: ${script.title}`, err);
              reject(err);
            } else {
              if (stderr) {
                console.error(`Script stderr: ${script.title}`, stderr);
              }
              resolve(stdout);
            }
          });
        });
      }
    }
    ```
    - [1] `let output: string | any = await CustomScript.executeScript(...)` - Executes the custom script using `CustomScript.executeScript`. This is also used in `ContentType.ts` during content creation in `ContentType.create` function when handling `contentType.postScript`.
    - [2] `'${wsFolder?.fsPath}' '${filePath}' '${title}'` - Workspace path, file path and title are passed as arguments to the script. These paths and title could be influenced by the attacker if they can control the workspace content or settings.
    - [3] `scriptToRun += \` \${args}\`` - Arguments are appended to the script command string. This is a classic command injection vulnerability pattern if `args` are not properly sanitized.
    - [4] `exec(scriptToRun, ...)` - `child_process.exec` is used to execute the constructed `scriptToRun` string as a shell command. **Vulnerability:**  Directly executing shell commands with `child_process.exec` and unsanitized arguments allows for command injection. An attacker can inject malicious shell commands into the `script` or `args` variables, leading to arbitrary code execution.
- Security Test Case:
    1. Configure a malicious custom placeholder:
        - In VSCode settings, navigate to Front Matter CMS extension settings.
        - Locate the "Content: Placeholders" setting and add a new placeholder.
        - Set the "Id" to `maliciousPlaceholder`.
        - Set the "Script" to `node -e "require('child_process').execSync('touch /tmp/pwned_placeholder')";`
        - Leave the "Command" field empty or set to `node`.
    2. Create a markdown file that uses the malicious placeholder:
        ```markdown
        ---
        title: Test Article
        ---
        # This is a test article with a malicious placeholder: {{maliciousPlaceholder}}
        ```
    3. Open this markdown file in VSCode. Front Matter CMS might try to process placeholders when the file is opened or previewed, depending on extension features and configurations.
        4. Observe the results. If the vulnerability is successfully exploited, a file named `pwned_placeholder` should be created in the `/tmp/` directory.
        5. Successful Command Injection: The creation of the `pwned_placeholder` file (or other injected commands being executed) confirms the Custom Placeholder Script Command Injection vulnerability.
    6. **New Test Case - Trigger via `SnippetListener.updateSnippetPlaceholders`:**
        1. Configure the same malicious custom placeholder as in step 1 above.
        2. Open the Front Matter CMS Dashboard.
        3. Open the developer tools for the webview.
        4. In the developer tools console, execute the following JavaScript code to trigger the `updateSnippetPlaceholders` message:
           ```javascript
           const vscode = acquireVsCodeApi();
           vscode.postMessage({
               command: 'updateSnippetPlaceholders',
               requestId: 'testRequest', // Or any unique request ID
               payload: {
                   value: '{{maliciousPlaceholder}}',
                   filePath: '/path/to/any/markdown/file.md' // Path doesn't strictly matter for this test
               }
           });
           ```
        5. Observe the results. If the vulnerability is successfully exploited, a file named `pwned_placeholder` should be created in the `/tmp/` directory, same as before.
        6. Successful Command Injection: The creation of the `pwned_placeholder` file via `updateSnippetPlaceholders` message confirms that this listener is also vulnerable to Custom Placeholder Script Command Injection.

- Vulnerability Name: Dynamic Configuration File Arbitrary Code Execution
- Description:
    1. The extension allows specifying a dynamic configuration file path via the `frontmatter.config.dynamicFilePath` setting.
    2. The `SettingsHelper.readConfig` function loads and executes this dynamic configuration file using `import(absFilePath)`.
    3. If an attacker can control the `dynamicConfigFilePath` setting (e.g., by contributing a malicious workspace configuration), they can point it to a malicious JavaScript file.
    4. When the extension loads the configuration, it will execute the code in the malicious JavaScript file within the extension's context.
    5. This can lead to arbitrary code execution within the VSCode extension's context.
- Impact:
    - Arbitrary code execution within the VSCode extension's context.
    - This could allow an attacker to perform actions such as reading/writing files within the workspace, exfiltrating data, or potentially gaining further access to the user's system depending on the extension's permissions and the nature of the executed code.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    - Path Resolution: `Folders.getAbsFilePath` is used to resolve the dynamic config path, which restricts the path to within the workspace.
- Missing Mitigations:
    - Input Validation: Validate that the `dynamicConfigFilePath` setting points to a file within the workspace and potentially restrict the file extension to `.js` or `.json`.
    - Sandboxed Execution: Instead of directly using `import()`, consider executing the dynamic config file in a sandboxed environment to limit the potential impact of malicious code.
    - User Warning: Display a warning to the user when a dynamic configuration file is loaded, especially if it's from workspace settings, as these can be controlled by malicious workspaces.
- Preconditions:
    - An attacker needs to control the `frontmatter.config.dynamicFilePath` setting. This could be achieved by tricking a user into opening a malicious workspace that includes this setting in its workspace configuration (`.vscode/settings.json`).
- Source Code Analysis:
    ```typescript
    // File: /code/src/helpers/SettingsHelper.ts
    private static async readConfig() {
        ...
        if (
          Settings.globalConfig &&
          Settings.globalConfig[`${CONFIG_KEY}.${SETTING_CONFIG_DYNAMIC_FILE_PATH}`]
        ) {
          const dynamicConfigPath =
            Settings.globalConfig[`${CONFIG_KEY}.${SETTING_CONFIG_DYNAMIC_FILE_PATH}`]; // [1] Dynamic config path from settings
          if (dynamicConfigPath) {
            const absFilePath = Folders.getAbsFilePath(dynamicConfigPath); // [2] Absolute path resolution
            if (await existsAsync(absFilePath)) {
              try {
                const configModule = await import(absFilePath); // [3] Dynamic import execution
                if (configModule) {
                  config = {
                    ...config,
                    ...configModule.default
                  };
                }
              } catch (e) {
                Logger.error(`Error while loading dynamic config file: ${absFilePath}`);
                Logger.error(e);
              }
            }
          }
        }
        ...
    }
    ```
    - [1] `dynamicConfigPath = Settings.globalConfig[\`${CONFIG_KEY}.${SETTING_CONFIG_DYNAMIC_FILE_PATH}\`];` - Retrieves the dynamic config file path from the extension settings. This setting can be controlled by workspace configuration.
    - [2] `const absFilePath = Folders.getAbsFilePath(dynamicConfigPath);` - Resolves the absolute file path, restricting it to within the workspace, but still allowing any `.js` file within the workspace.
    - [3] `const configModule = await import(absFilePath);` - Dynamically imports and executes the JavaScript file specified by `absFilePath`. **Vulnerability:** Using `import()` on a user-controlled file path allows arbitrary code execution.
- Security Test Case:
    1. Create a new VSCode workspace.
    2. Inside the workspace root, create a folder named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json`.
    4. Add the following malicious configuration to `settings.json`:
       ```json
       {
           "frontmatter.config.dynamicFilePath": "malicious_config.js"
       }
       ```
    5. In the workspace root, create a file named `malicious_config.js` with the following content:
       ```javascript
       // malicious_config.js
       require('child_process').execSync('touch /tmp/pwned_dynamic_config');
       module.exports = {
           config: {
               // Your configurations here
           }
       };
       ```
    6. Open the newly created workspace in VSCode and activate the Front Matter CMS extension (e.g., by opening the dashboard or any Front Matter command).
    7. Observe the results. If the vulnerability is successfully exploited, a file named `pwned_dynamic_config` should be created in the `/tmp/` directory.
    8. Successful Arbitrary Code Execution: The creation of the `pwned_dynamic_config` file (or other injected commands being executed) confirms the Dynamic Configuration File Arbitrary Code Execution vulnerability.