# Vulnerabilities in VS Code Debug Visualizer Extension

## Arbitrary Code Execution via Unsanitized Eval of Custom Visualizer/Script Files

- **Vulnerability Name:** Arbitrary Code Execution via Unsanitized Eval of Custom Visualizer/Script Files

- **Description:**  
  When the extension starts up it looks for custom JavaScript files (both for injected "data extractors" and visualizer‐alternative scripts) via configuration settings (for example, the setting  
  `"debugVisualizer.customVisualizerScriptPaths"` and `"debugVisualizer.js.customScriptPaths"`). The extension's file‐watcher reads the referenced files from disk and then sends their content (without additional validation or sanitization) over to the webview. In the webview a message handler receives a command (with a field called `jsSource`) and immediately passes that value into an `eval()` call. That eval call wraps the file content inside a function call which is used to register a visualizer module (via a call such as `setVisualizationModule(id, fn)`). Because no sanitization or integrity checks are performed on the file content before it is embedded into an eval string—and because the Content Security Policy in the webview explicitly allows the use of unsafe eval—an attacker who supplies a malicious repository (for example, by including a manipulated custom visualizer script file and pointing the workspace settings to it) can cause arbitrary JavaScript code to run in the context of the debug visualizer's webview.

  **Step‑by‑step Trigger:**  
  1. The malicious repository contains a custom visualizer (or JavaScript "helper" script) file whose content is controlled by the attacker (for example, a file with additional code that exfiltrates sensitive information or opens a backdoor).  
  2. The repository (or an included workspace settings file such as `.vscode/settings.json`) sets the relevant configuration property (for example, `"debugVisualizer.customVisualizerScriptPaths"`) to point to this malicious file.  
  3. When the victim opens the repository in VS Code with the Debug Visualizer extension enabled, the extension's file-watcher (see the code in the file watcher implementation in the webview connection code) reads the content of the file and sends it via a JSON-RPC message (using the command `"setCustomVisualizerScript"`) to the webview.  
  4. Inside the webview (in the message event handler), the supplied `jsSource` is interpolated (wrapped into a function literal) and then passed directly to an `eval()` call.  
  5. The malicious JavaScript is executed in the webview context—thus the attacker achieves remote code execution (RCE) within the extension.

- **Impact:**  
  An attacker who successfully exploits this vulnerability can execute arbitrary JavaScript code in the context of the extension's webview. This can lead to:  
  - Hijacking or exfiltrating sensitive debug or configuration data.  
  - Manipulating the visualization output or further compromising the VS Code session.  
  - Using the compromised extension as a stepping stone for broader attacks on the user's system (for example, if additional privileges are available in the webview or extension host).

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  - The extension's webview does specify a Content Security Policy (CSP) in its HTML (via a meta tag). However, the CSP explicitly allows the use of `'unsafe-eval'` and does not prevent the dynamic evaluation needed to run custom scripts.  
  - No additional integrity checks (e.g. digital signatures or hash verification) are performed on the file content loaded from disk.

- **Missing Mitigations:**  
  - **Sanitization/Validation:** The file content taken from custom script files is not validated or sanitized before being interpolated into an eval string.  
  - **Secure Evaluation:** Instead of using a naked `eval()`, the extension could use a safer controlled sandbox or a library for secure script isolation.  
  - **Integrity Verification:** Verifying the integrity or origin (e.g. via cryptographic hashes or signatures) of any external script file before execution could help prevent tampering.
  - **Stricter CSP:** The CSP could be tightened to disallow unsafe eval in sensitive components.

- **Preconditions:**  
  - An attacker must be able to influence the content of a file loaded by the extension—for example, by providing a malicious repository or by influencing workspace settings (such as a hidden `.vscode/settings.json`) that specify a custom script path.  
  - The victim must open the repository in VS Code so that the extension's file watcher picks up the manipulated custom visualizer (or script) file and passes its content to the webview for evaluation.

- **Source Code Analysis:**  
  1. **Configuration & File Watcher:**  
     - In `extension/src/Config.ts` the extension defines settings such as `"debugVisualizer.customVisualizerScriptPaths"`. The getter for this setting uses a `SimpleTemplate` to substitute placeholders (most often for the workspace folder) but does not validate the resulting path.  
     - In `webview/WebviewConnection.ts`, a `FileWatcher` is created that monitors all paths returned by the configuration getter. When a file event is triggered, it reads the file content (using Node's `fs.readFileSync`) and calls  
       ```js
       client.setCustomVisualizerScript({
           id: file.path,
           jsSource: file.content || null,
       });
       ```
  2. **Webview Message Handling & Eval:**  
     - In the webview HTML (assembled in `InternalWebviewManager.ts` via the function `getDebugVisualizerWebviewHtml`), a script is injected that adds a message listener. When a message is received with the command `"setCustomVisualizerScript"`, the code runs an `eval()` call:
       ```js
       eval(`
         ((load) => {
           let fn = undefined;
           if (load) {
             const module = {};
             load(module);
             fn = module.exports;
           }
           setVisualizationModule(${JSON.stringify(id)}, fn);
         })(
           ${jsSource ? `function (module) { ${jsSource} }` : "undefined"}
         )
       `);
       ```
     - Here the value of `jsSource` is taken verbatim from the file and inserted into the eval string. No sanitization is performed, so any malicious payload included in the file will be executed.
  3. **Result:**  
     - The attacker-controlled `jsSource` is executed in the webview's context, allowing full arbitrary JavaScript code execution.

- **Security Test Case:**  
  1. **Setup a Malicious Script:**  
     - Create a file (for example, `evil_visualizer.js`) with the following content:
       ```js
       // Malicious payload (for testing, show an alert or log a message)
       alert('Malicious code executed!');
       // In a real attack, this could be any harmful code such as exfiltrating data.
       ```
  2. **Configure the Workspace:**  
     - In a workspace-specific settings file (e.g. `.vscode/settings.json`), add (or modify) the following setting:
       ```json
       {
         "debugVisualizer.customVisualizerScriptPaths": [
           "absolute/path/to/evil_visualizer.js"
         ]
       }
       ```
  3. **Trigger the Loading:**  
     - Open the repository in VS Code. The extension's file watcher will detect the file change and send its content (with the malicious payload) to the webview.  
  4. **Observe the Effect:**  
     - When the webview receives the message carrying the `evil_visualizer.js` content, it will execute the eval call. If the vulnerability is present, an alert dialog (or any other observable effect from the payload) will appear, confirming RCE.  
  5. **Cleanup:**  
     - Remove the test settings and file after verifying the vulnerability.