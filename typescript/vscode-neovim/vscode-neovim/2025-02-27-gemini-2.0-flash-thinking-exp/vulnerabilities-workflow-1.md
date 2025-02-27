## Combined Vulnerability List

### Javascript Code Injection in `eval_for_client` / Arbitrary Code Execution via Unsafe JavaScript Eval / Arbitrary Javascript Execution via `vscode.eval`

- **Description:**
  The `eval_for_client` function in `/code/src/actions_eval.ts` evaluates Javascript code received from Neovim using the `eval()` function. This allows for arbitrary Javascript code execution if an attacker can control the `code` parameter passed to this function. The VSCode Neovim extension provides a Lua API function `vscode.eval(code[, opts, timeout])` that allows execution of arbitrary Javascript code within the VSCode extension host. An attacker can craft a malicious Neovim script or plugin that calls `vscode.eval` with attacker-controlled Javascript code. When a user executes this malicious Neovim script or plugin within VSCode-Neovim, the provided Javascript code is executed within the VSCode extension's context using the `eval_for_client` function in `actions_eval.ts`. The `eval_for_client` function directly uses Javascript's `eval()` function to execute the provided `code` string without any sanitization or security checks.

  - **Attack Steps:**
    1. An attacker who controls an input channel (for example, via a compromised Neovim communication interface) supplies a specially crafted code string.
    2. The code is concatenated into a function body and passed to `eval()`.
    3. Once evaluated, the malicious payload executes with full privileges in the extension host.
    4. Alternatively, an attacker can craft a malicious Neovim script or plugin that calls `vscode.eval` with attacker-controlled Javascript code. When a user executes this malicious Neovim script or plugin within VSCode-Neovim, the provided Javascript code is executed.

- **Impact:**
  Arbitrary code execution within the VSCode extension context. This allows an attacker to execute any arbitrary JavaScript code with full access to the extension’s privileges, potentially compromising the file system, settings, or even facilitating a full remote code execution attack. An attacker could potentially exfiltrate sensitive information, install malware, or further compromise the user's system by controlling the behavior of the VSCode editor.
  - **Critical**: Arbitrary Javascript execution in the VSCode extension host allows a complete compromise of the VSCode environment.
  - An attacker could potentially:
      - Read, modify, and delete files accessible to VSCode.
      - Exfiltrate sensitive information such as API keys, source code, and user data.
      - Install or modify VSCode extensions, potentially introducing further malicious functionality.
      - Control the user's VSCode instance and potentially the underlying system depending on VSCode's permissions.

- **Vulnerability Rank:** Critical

- **Currently implemented mitigations:**
  None. The code directly uses `eval()` without any sanitization or validation of the input. There is no input sanitization, filtering, or sandboxing for the code string before it is concatenated and evaluated via `eval()`. Based on the documentation and source code analysis, there are no input sanitization or security checks for the `code` argument in `vscode.eval`. The `eval_for_client` function in `actions_eval.ts` directly passes the input to Javascript's `eval()`.

- **Missing mitigations:**
  - Input sanitization: The `code` parameter should be strictly validated and sanitized to prevent execution of malicious Javascript code. However, input validation is generally good practice, it is extremely difficult to effectively sanitize arbitrary Javascript code to prevent malicious actions. This is likely not a viable mitigation for this vulnerability.
  - Avoid `eval()`:  Using `eval()` to execute arbitrary code is inherently unsafe. A safer alternative should be used, or the functionality should be restricted to prevent arbitrary code execution. Replace `eval()` with a secure evaluation mechanism or execute code in a sandboxed environment.
  - Limit or whitelist the communication channels from which the code can be supplied.
  - Remove or Restrict `vscode.eval`: Ideally, the most secure mitigation would be to remove the `vscode.eval` API entirely if arbitrary Javascript execution is not a core requirement. If it is necessary, its functionality should be severely restricted.
  - Principle of Least Privilege: Limit the permissions and capabilities available to Javascript code executed via `vscode.eval`. However, even with limited privileges, significant damage can be done within the VSCode environment.
  - User Warnings and Documentation: If `vscode.eval` is retained, comprehensive documentation must be provided, clearly outlining the significant security risks. Users should be strongly warned against using untrusted Neovim plugins or scripts that utilize this API.

- **Preconditions:**
  - The attacker needs to be able to send a `vscode-action` notification to the extension with the action name `eval` and a malicious Javascript code string as the `code` argument.
  - This can be achieved by a malicious Neovim plugin, a compromised Neovim configuration, or if the user executes a malicious command within Neovim that triggers this action.
  - The attacker must be able to control the code string (for example, through a compromised or unauthorized Neovim interface).
  - The extension must be active and process the eval request.
  - The user must have the VSCode Neovim extension installed and activated.
  - An attacker needs to be able to execute a Neovim script that calls `vscode.eval` with malicious Javascript code. This can be achieved through a malicious Neovim plugin, a crafted Neovim configuration, or social engineering to convince the user to run a malicious command.

- **Source code analysis:**
  - File: `/code/src/actions_eval.ts`
  - Step 1: The `eval_for_client` function is defined to accept a `code` string and `args` as input.
  - Step 2: The function uses `eval("async () => {" + code + "}")` to create an asynchronous function from the provided `code` string.
  - Step 3: This dynamically created function is then executed using `await func()`.
  - Step 4: The result is serialized to JSON and returned.
  ```typescript
  // /code/src/actions_eval.ts
  export async function eval_for_client(code: string, args: any): Promise<any> {
      void args;

      const func: () => Promise<any> = eval("async () => {" + code + "}"); // Vulnerable line
      const result = await func();

      let data: string | undefined;
      try {
          data = JSON.stringify(result);
      } catch (e) {
          throw new Error(`Return value of eval not JSON serializable: ${e}`);
      }

      return data ? JSON.parse(data) : data;
  }
  ```
  - In `/code/src/actions.ts`, the code registers the `eval` action and links it to the `eval_for_client` function.
  ```typescript
  import { eval_for_client } from "./actions_eval";
  // ...
  private initActions() {
      // ...
      this.add("eval", (code: string, args: any) => eval_for_client(code, args));
      // ...
  }
  ```
  - In **/code/src/actions_eval.ts**, the code takes an external string, embeds it into an async function template, and passes it directly to `eval()` without escaping or verification.
  - The `eval("async () => {" + code + "}")` line directly executes the `code` provided as input using Javascript's `eval()` function.
  - There is no input sanitization or validation performed on the `code` before execution.
  - The function is designed to be called from Lua within the Neovim context, allowing Lua scripts to execute arbitrary Javascript in the VSCode extension host.
  - Visualization:
    ```mermaid
    graph LR
        A[Neovim (Attacker Controlled)] --> B(vscode-neovim Extension);
        B -- vscode-action: eval, {code: "malicious code"} --> C[actions.ts: runAction];
        C --> D[actions.ts: ActionManager.run];
        D --> E[actions.ts: commands.executeCommand("neovim:eval")];
        E --> F[actions.ts: eval_for_client];
        F --> G[actions_eval.ts: eval(code)];
        G --> H[Arbitrary Javascript Code Execution in VSCode Extension Context];
    ```

- **Security test case:**
  - Step 1: Install and activate the vscode-neovim extension in VSCode.
  - Step 2: Open any text file in VSCode to ensure the extension is active.
  - Step 3: Open the Neovim editor (either embedded or a separate Neovim instance connected to VSCode).
  - Step 4: In Neovim, execute the following Lua command:
    ```vimscript
    :lua require'vscode'.run_action('eval', {code='vscode.window.showErrorMessage("Vulnerable to Javascript Injection!")'})
    ```
    Or using command in `init.lua`:
    ```lua
    vim.api.nvim_command [[
        command! ExploitVSCodeLuaEval call v:lua.require('vscode').eval('vscode.window.showInformationMessage("Vulnerability Exploited! Arbitrary Javascript Execution!")')
    ]]
    ```
  - Step 5: Trigger the command in Neovim `:ExploitVSCodeLuaEval` or action from step 4.
  - Step 6: Observe that a VSCode error message box appears with the text "Vulnerable to Javascript Injection!" or information message "Vulnerability Exploited! Arbitrary Javascript Execution!".
  - Step 7: This confirms that arbitrary Javascript code provided from Neovim can be executed within the VSCode extension context via the `eval` action. An attacker can replace `"vscode.window.showErrorMessage(\"Vulnerable to Javascript Injection!\")"` with more malicious Javascript code to further compromise the system.
  - **Demonstrate File System Access (Optional)**: For a more impactful demonstration, replace the Javascript code in step 4 with the following to attempt writing to a file:
    ```lua
    vim.api.nvim_command [[
        command! ExploitVSCodeLuaEval call v:lua.require('vscode').eval('const fs = require("fs"); fs.writeFileSync("evil.txt", "Vulnerability Exploited! File System Access!"); vscode.window.showInformationMessage("File \'evil.txt\' written!")')
    ]]
    ```
  - Step 8: Re-run test and verify file creation. Repeat step 5. After executing the command, check if a file named `evil.txt` has been created in your workspace or home directory (depending on VSCode's working directory) containing the text "Vulnerability Exploited! File System Access!". Also, verify the VSCode information message box "File 'evil.txt' written!". Successful file creation further demonstrates the severity of the arbitrary Javascript execution vulnerability.

### Potential Path Traversal in `handleOpenFile`

- **Description:**
  The `handleOpenFile` function in `/code/src/buffer_manager.ts` uses `path.resolve` to construct file paths based on the `fileName` received from Neovim's `open-file` event. If an attacker can control the `fileName` parameter, they might be able to perform path traversal attacks and access files outside of the workspace.

  - **Attack Steps:**
    1. The attacker controls an `open-file` event and supplies a malicious `fileName` string containing path traversal sequences.
    2. The extension uses `path.resolve(folders[0].uri.fsPath, name)` to resolve the file path.
    3. Due to `path.resolve`, the attacker can navigate outside the workspace directory.
    4. The contents of the targeted file are then attempted to be opened in VSCode.

- **Impact:**
  An attacker could potentially read arbitrary files on the user's system if they can control the `fileName` parameter in the `open-file` event. This could lead to information disclosure.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
  None. The code uses `path.resolve` without sanitizing or validating the `fileName`.

- **Missing mitigations:**
  - Input sanitization: Validate and sanitize the `fileName` parameter to prevent path traversal characters like `..` or absolute paths.
  - Use `path.join` instead of `path.resolve`: `path.join` is generally safer for joining path segments and preventing traversal.

- **Preconditions:**
  - The attacker needs to be able to send an `open-file` event to the extension with a malicious `fileName` string.
  - This can be achieved by a malicious Neovim plugin, a compromised Neovim configuration, or if the user executes a malicious command within Neovim that triggers this action with attacker controlled filename.

- **Source code analysis:**
  - File: `/code/src/buffer_manager.ts`
  - Step 1: The `handleOpenFile` function is called when the `open-file` event is received from Neovim.
  - Step 2: The function extracts the `fileName` from the event data.
  - Step 3: The function calls `this.findPathFromFileName(normalizedName)` to resolve the file path.
  - Step 4: `findPathFromFileName` uses `path.resolve(folders[0].uri.fsPath, name)` which can be vulnerable to path traversal.
  ```typescript
  // /code/src/buffer_manager.ts
  private findPathFromFileName(name: string): string {
      const folders = workspace.workspaceFolders;
      return folders && folders.length > 0 ? path.resolve(folders[0].uri.fsPath, name) : name; // Vulnerable line
  }

  private async handleOpenFile(data: EventBusData<"open-file">) {
      const [fileName, close] = data;
      ...
      else {
          const normalizedName = fileName.trim();
          let uri = Uri.from({ scheme: "file", path: this.findPathFromFileName(normalizedName) }); // Call to vulnerable function
          ...
      }
      ...
  }
  ```
  - Visualization:
    ```mermaid
    graph LR
        A[Neovim (Attacker Controlled)] --> B(vscode-neovim Extension);
        B -- open-file: {fileName: "malicious/path"} --> C[buffer_manager.ts: handleOpenFile];
        C --> D[buffer_manager.ts: findPathFromFileName];
        D --> E[path.resolve(workspaceRoot, fileName)];
        E --> F[Potential Path Traversal];
    ```

- **Security test case:**
  - Step 1: Install and activate the vscode-neovim extension in VSCode.
  - Step 2: Open a workspace in VSCode.
  - Step 3: Open the Neovim editor (either embedded or a separate Neovim instance connected to VSCode).
  - Step 4: In Neovim, execute the following Lua command:
    ```vimscript
    :lua require'vscode'.run_action('open-file', {'../../../sensitive_file.txt'})
    ```
    Replace `../../../sensitive_file.txt` with a path to a file you want to test for access (e.g., a file outside of your workspace but accessible by your user).
  - Step 5: Check if VSCode opens the file specified in the path traversal attempt. If it does, the vulnerability is confirmed.

### Arbitrary File Disclosure via Unvalidated External Buffer Name

- **Description:**
  When an external-buffer event is processed and if no trusted URI is available, the extension falls back on using an unsanitized buffer name to construct a file URI. In doing so, an attacker may supply an absolute path (e.g. “/etc/passwd”) to trick the extension into opening sensitive files.

  - **Attack Steps:**
    1. The attacker controls an external-buffer event and omits the trusted URI.
    2. The buffer “name” field is maliciously set to an absolute file path.
    3. The extension wraps the name using `Uri.file(name)` and passes it to `workspace.openTextDocument()`.
    4. The contents of the sensitive file are then displayed in the editor.

- **Impact:**
  Exposes sensitive files from the user’s system, potentially leading to confidential information disclosure.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
  There are no checks or sanitization on the buffer name when a trusted URI is absent.

- **Missing mitigations:**
  - Validate or sanitize the file path derived from the buffer name.
  - Require the source to be trusted or implement a strict whitelist for file URIs.
  - Reject absolute paths that reference critical system files.

- **Preconditions:**
  The attacker must be able to send an external-buffer event in which the trusted URI is omitted and a malicious file name is provided.

- **Source Code Analysis:**
  The buffer manager extracts the unsanitized “name” and uses it to create a file URI via `Uri.file(name)` before passing it to `workspace.openTextDocument()`.

- **Security Test Case:**
  1. Simulate an external-buffer event that omits a trusted URI and provides a buffer name such as “/etc/passwd.”
  2. Verify that the extension opens and displays the contents of that file.

### Arbitrary Command Execution via Malicious Composite Key Configuration

- **Description:**
  The extension supports custom composite key mappings in the workspace configuration. The configuration only validates the key format (expecting exactly two ASCII characters) but does not validate the command name or its arguments.

  - **Attack Steps:**
    1. An attacker provides a malicious composite key mapping via a compromised or malicious `.vscode/settings.json`.
    2. The mapping associates a two‑character key (e.g. “ab”) with a dangerous VSCode command and attacker‑controlled arguments.
    3. When the user triggers the mapping, the unsafe command is executed.

- **Impact:**
  Arbitrary command execution within VSCode, which could lead to unauthorized file access or further compromise of system integrity.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
  Only a simple check for the two‑character ASCII format is performed; no further sanitization or whitelisting of commands/arguments is done.

- **Missing mitigations:**
  - Validate the complete composite key configuration against a whitelist of allowed and safe commands.
  - Require user confirmation before executing commands derived from workspace settings.
  - Sanitize all command arguments in the composite key mappings.

- **Preconditions:**
  - The attacker must be able to modify the workspace configuration (for example, via a malicious `.vscode/settings.json` file).
  - The user later triggers the configured composite key mapping.

- **Source Code Analysis:**
  In **/code/src/typing_manager.ts**, only the key format is verified using a regex check. There is no proper vetting of the command or its arguments before calling `commands.executeCommand()`.

- **Security Test Case:**
  1. Create a `.vscode/settings.json` with a composite key mapping that associates “ab” with a dangerous VSCode command (for example, one that opens a sensitive file).
  2. Reload the extension and trigger the composite key mapping.
  3. Verify that the unsafe command is executed.

### Arbitrary Command Execution via Malicious Neovim Configuration

- **Description:**
  The extension spawns an external Neovim process using configuration parameters taken directly from the workspace settings without sufficient sanitization. An attacker can supply a malicious configuration (for instance, in `.vscode/settings.json`) that sets parameters like `"neovimPath"`, `"wslDistribution"`, or `"neovimInitPath"` to attacker‑controlled values.

  - **Attack Steps:**
    1. The attacker supplies a configuration that sets `"neovimPath"` to a path pointing to a malicious executable and may also manipulate `"wslDistribution"` or `"neovimInitPath"`.
    2. When the extension initializes, it uses these unsanitized values in the `buildSpawnArgs` method (in **/code/src/main_controller.ts**) to construct the arguments for spawning the Neovim process.
    3. The malicious executable is launched with arbitrary arguments in the user’s context.

- **Impact:**
  Arbitrary command execution with the privileges of the VSCode extension host, potentially leading to full system compromise.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
  Default values are used when standard configuration is detected (such as when `neovimPath` is `"nvim"`). However, when custom settings are provided by the user, no further validation is applied.

- **Missing mitigations:**
  - Validate and sanitize each configuration parameter used for spawn-argument construction.
  - Enforce a whitelist of approved executable paths and acceptable parameter values.
  - Consider sandboxing or limiting the privileges of the spawned Neovim process.

- **Preconditions:**
  - The attacker must be able to supply a malicious workspace configuration.
  - The extension must load these configuration values during startup.

- **Source Code Analysis:**
  In **/code/src/main_controller.ts**, the `buildSpawnArgs` method directly reads configuration values and incorporates them into the command-line arguments without proper sanitization.

- **Security Test Case:**
  1. Create a workspace configuration (e.g. in `.vscode/settings.json`) containing malicious values for `"neovimPath"`, `"wslDistribution"`, and `"neovimInitPath"`.
  2. Restart the extension and monitor for the launch of the malicious executable (for example, via side effects like creating a known marker file).
  3. Verify that arbitrary command execution occurs.

### Arbitrary File Overwrite via Malicious Save Buffer Request

- **Description:**
  The extension supports a "save_buffer" action (triggered via Neovim commands) in which unsanitized file name parameters (`current_name` and `target_name`) are used to compute a file path. If an attacker supplies a `target_name` containing directory traversal sequences (for example, `"../../malicious_file"`), the final computed path may fall outside the intended workspace.

  - **Attack Steps:**
    1. An attacker with control over the external input (e.g. through a compromised Neovim channel) provides a `target_name` with directory traversal characters.
    2. The extension normalizes the target name and uses functions like `path.relative` and `Uri.joinPath` to compute the save location.
    3. Without proper enforcement to confine the path within the workspace, the file may be (over)written at an arbitrary location.

- **Impact:**
  This can lead to an attacker overwriting arbitrary files in the user’s file system (within the limits of write access granted to VSCode), potentially corrupting critical data or installing malicious payloads.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
  The code attempts to normalize the file paths using functions such as `path.normalize` and uses `workspace.saveAs()` when the computed path does not appear relative to the working directory. However, these measures are insufficient to completely prevent directory traversal attacks.

- **Missing mitigations:**
  - Enforce strict validation to ensure that the final computed file path resides within an approved workspace directory.
  - Explicitly reject any file paths that contain directory traversal sequences (e.g. strings containing `"../"`).
  - Consider implementing a whitelist of allowed target directories.

- **Preconditions:**
  - The attacker must be able to inject a malicious `target_name` into the external save-buffer event (for example, via an untrusted or compromised Neovim channel).
  - The user must trigger the save-buffer action.

- **Source Code Analysis:**
  In **/code/src/buffer_manager.ts**, the `handleSaveBuf` function takes unsanitized file name parameters from an external source, normalizes them, and then joins them with the workspace folder’s URI. There is no strong check to ensure that the resulting path does not escape the intended workspace directory.

- **Security Test Case:**
  1. Simulate a save-buffer request by supplying a `target_name` with directory traversal (e.g. `"../../malicious_file"`).
  2. Confirm that the computed path escapes the workspace and that the file is saved (or overwritten) at that unintended location.
  3. Verify that the file’s contents match the payload, thereby demonstrating the vulnerability.