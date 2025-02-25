- **Vulnerability Name:** Malicious Plugin Injection via Workspace Plugin Configuration
  - **Description:**
    The Draw.io VS Code Integration extension supports the dynamic loading of external Draw.io plugins. Users can add plugin definitions via the configuration property `hediet.vscode-drawio.plugins` using file paths that support workspace variables (e.g. `${workspaceFolder}/plugin.js`). When a plugin is first encountered or its file changes, the extension displays a dialog prompting the user to allow or block its loading; the user’s decision is then stored in the `hediet.vscode-drawio.knownPlugins` setting. However, this mechanism does not enforce additional integrity checks (such as cryptographic signature verification) or sandboxing of plugin code. An attacker who can write to the workspace (for instance, during a Liveshare session or via a compromised repository) may inject or replace a plugin file with malicious JavaScript. Once the user approves plugin loading, the extension will load and execute the malicious file without re-verifying its integrity, which can lead to arbitrary code execution in the user’s VS Code instance.
  - **Impact:**
    An attacker’s malicious plugin can run with the privileges of the user’s VS Code session. This could lead to arbitrary code execution, data exfiltration, unauthorized access to files, and further compromise of the local environment.
  - **Vulnerability Rank:**
    High
  - **Currently Implemented Mitigations:**
    - The extension prompts the user (via a dialog box) to explicitly allow or deny the loading of a plugin when it is first encountered or when its hash changes.
    - The user’s decision is stored locally in the `hediet.vscode-drawio.knownPlugins` setting so that the same plugin is not prompted for repeatedly.
  - **Missing Mitigations:**
    - **Robust Integrity Verification:** There is no cryptographic signature or strict integrity check on the plugin file once approved. An attacker who can later modify the file may alter its content without triggering a new user prompt.
    - **Sandboxing:** The extension does not sandbox the plugin’s execution environment, which means malicious plugins run with full extension privileges.
    - **Automated Re-validation:** After the initial approval, updates or modifications to the plugin file are not re-validated before execution.
  - **Preconditions:**
    - The attacker must gain write access to the workspace directory (for example, by compromising a collaborative Liveshare session or by injecting files into a shared repository).
    - The affected user must open a Draw.io file in VS Code so that the extension loads the plugin according to the workspace configuration.
  - **Source Code Analysis:**
    Although the actual implementation code is not provided, the documentation and configuration files reveal the following process:
    1. **Configuration Reading:** On startup (or when opening a Draw.io file), the extension reads the user or workspace setting `hediet.vscode-drawio.plugins`. This setting accepts an array of plugin definitions with file paths that may include variables (e.g. `${workspaceFolder}`).
    2. **File Resolution and Loading:** The extension resolves the absolute path for each plugin file and loads the file’s contents.
    3. **Hash Calculation and User Prompt:** When a plugin is first loaded, the extension computes a hash (e.g. SHA-256) of the file content and compares it to the entry in `hediet.vscode-drawio.knownPlugins`. If the plugin is new or its hash has changed, a dialog box is displayed requesting user approval.
    4. **Post-Approval Loading:** Once the user approves a plugin, the decision is stored locally, and the plugin is loaded in the same execution context as the extension. There is no subsequent re-validation of the file’s integrity on each load.

    **Visualization of the Flow:**

    • **User Settings (`hediet.vscode-drawio.plugins`):** → File path resolved (with `${workspaceFolder}` support)
    • **File Loaded:** → Hash computed → Check against `hediet.vscode-drawio.knownPlugins`
      → If new/changed → Prompt user for approval
      → User approves → Store decision and load plugin
      → *No further integrity checks are applied if the file is modified later*

  - **Security Test Case:**
    1. **Test Setup:**
       - Create a test workspace that simulates a shared environment (for example, by using a Liveshare session).
       - In the workspace root, add a file named `malicious.js` that contains a small script (for instance, a script that logs a unique message or calls `alert('Malicious Plugin Executed')` to prove code execution).
    2. **Configure the Plugin:**
       - In the workspace or user settings for the extension, add the following entry:
         ```json
         "hediet.vscode-drawio.plugins": [
             { "file": "${workspaceFolder}/malicious.js" }
         ]
         ```
    3. **Execution and Approval:**
       - Open any Draw.io file in VS Code so that the extension processes the plugin settings.
       - When the plugin prompt appears, approve the loading of the plugin.
    4. **Post-Approval Modification:**
       - Modify `malicious.js` (for instance, change the script to call a different function or log additional messages) and save the file.
    5. **Observation:**
       - Reload the Draw.io file (or trigger any action that causes the plugin to be reloaded) and observe whether the changes in `malicious.js` are executed without a new integrity check or user prompt.
       - Examine the VS Code developer console or output logs for the malicious payload’s indicators (e.g., the alert or log messages).
    6. **Evaluation:**
       - If the malicious payload is executed upon reloading without triggering a new approval, the test confirms that the extension does not enforce robust integrity verification or sandboxing—thereby validating the vulnerability.

By exploiting this vulnerability, an external attacker capable of tampering with a shared or compromised workspace can inject and modify code that runs with the extension’s privileges in VS Code.