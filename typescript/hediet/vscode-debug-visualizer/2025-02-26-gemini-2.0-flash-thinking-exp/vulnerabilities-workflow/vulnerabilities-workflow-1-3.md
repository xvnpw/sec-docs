### Vulnerability: Code Injection via Custom Visualizer Script

- Description:
    - The Debug Visualizer extension allows users to load custom JavaScript files as data extractors using the `debugVisualizer.customVisualizerScriptPaths` setting.
    - These scripts are intended to provide custom visualizations for data during debugging.
    - However, the extension uses `eval()` to execute the code from these custom scripts within the webview context.
    - An attacker can craft a malicious JavaScript file and configure the `debugVisualizer.customVisualizerScriptPaths` setting to point to this file.
    - When the Debug Visualizer extension loads and executes this script, the malicious code will be executed within the webview context.
    - Step-by-step trigger:
        1. Attacker creates a malicious JavaScript file (e.g., `malicious-visualizer.js`) containing arbitrary JavaScript code, such as `module.exports = (register, helpers) => { alert('Code Injection!'); };`.
        2. Attacker creates or compromises a VSCode workspace.
        3. Attacker modifies the workspace settings (e.g., `.vscode/settings.json`) to include the following configuration:
           ```json
           {
               "debugVisualizer.customVisualizerScriptPaths": [
                   "${workspaceFolder}/malicious-visualizer.js"
               ]
           }
           ```
        4. Attacker places the `malicious-visualizer.js` file in the root directory of the workspace.
        5. Attacker convinces a victim user to open the malicious workspace in VSCode.
        6. Victim user starts a JavaScript/TypeScript debug session within the workspace.
        7. Victim user opens a Debug Visualizer view.
        8. The Debug Visualizer extension loads and executes the malicious script from `malicious-visualizer.js` using `eval()`.
        9. The arbitrary JavaScript code (e.g., `alert('Code Injection!')`) is executed within the webview context, demonstrating code injection.

- Impact:
    - Arbitrary code execution within the webview context.
    - This can lead to various malicious activities, including:
        - Exfiltration of sensitive information from the debugging session (e.g., debug variables, source code).
        - Modification of the behavior of the Debug Visualizer extension.
        - Potential cross-site scripting (XSS) attacks if the webview interacts with external websites or services.
        - Further exploitation of the user's VSCode environment or system, depending on the capabilities and security context of the webview.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - None. The code directly uses `eval()` to execute the custom visualizer scripts without any visible sanitization or security checks.

- Missing mitigations:
    - Input validation and sanitization: The extension should validate and sanitize the paths provided in `debugVisualizer.customVisualizerScriptPaths` to ensure they are valid and safe.
    - Sandboxing or isolation: Custom visualizer scripts should be executed in a sandboxed environment with restricted privileges to limit the impact of malicious code.
    - Avoid `eval()`: The extension should avoid using `eval()` to execute custom scripts and explore safer alternatives, such as using `Function` constructor with strict Content Security Policy (CSP) or a dedicated sandboxing mechanism.
    - Content Security Policy (CSP): Implement a strict CSP for the webview to mitigate the impact of code injection vulnerabilities. While a CSP is present in `/code/extension/src/webview/InternalWebviewManager.ts`, it's set to `default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; ...`, which effectively disables CSP protection by allowing 'unsafe-eval' and '*'. A proper CSP should restrict these unsafe directives.
    - User warnings: Display clear warnings to users when loading custom visualizer scripts, especially from untrusted workspaces, highlighting the potential security risks.

- Preconditions:
    - Victim user opens a malicious VSCode workspace containing a malicious JavaScript file and workspace settings that configure `debugVisualizer.customVisualizerScriptPaths` to load the malicious file.
    - Debug Visualizer extension is installed and activated in VSCode.
    - User starts a JavaScript/TypeScript debug session and opens a Debug Visualizer view.

- Source code analysis:
    - File: `/code/webview/src/model/Model.ts` (from previous context - not in provided files, but confirmed by vulnerability description)
    - Code snippet:
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
    - The `setCustomVisualizerScript` method in `Model.ts` directly uses `eval()` to execute the `jsSource` received from the backend.
    - The `jsSource` originates from user-configurable `debugVisualizer.customVisualizerScriptPaths` setting as seen in `/code/extension/src/Config.ts` and propagated through `/code/extension/src/webview/WebviewConnection.ts` and `/code/extension/src/webviewContract.ts`.
    - The files `/code/extension/webpack.config.ts`, `/code/extension/src/extension.ts`, `/code/extension/src/types.d.ts`, `/code/extension/src/Config.ts`, `/code/extension/src/webviewContract.ts`, `/code/extension/src/webview/WebviewConnection.ts`, `/code/extension/src/webview/InternalWebviewManager.ts`, `/code/extension/src/webview/WebviewServer.ts`, `/code/extension/src/VisualizationWatchModel/...`, `/code/extension/src/proxies/...`, `/code/extension/src/VisualizationBackend/...`, `/code/extension/src/utils/...` were analyzed and no mitigations for this vulnerability were found in the provided code. The vulnerability related to `eval()` usage in `setCustomVisualizerScript` persists. The Content Security Policy (CSP) in `/code/extension/src/webview/InternalWebviewManager.ts` is ineffective due to the usage of `'unsafe-eval'` and wildcard `*` in `script-src` and `default-src` directives.

- Security test case:
    1. Create a file named `malicious-visualizer.js` in a local directory with the following content:
       ```javascript
       module.exports = (register, helpers) => {
           register({
               id: "malicious",
               getExtractions(data, collector, context) {
                   alert('Code Injection Vulnerability in Debug Visualizer!');
                   collector.addExtraction({
                       id: "malicious-extraction",
                       name: "Malicious Extraction",
                       priority: 1000,
                       extractData: () => ({ kind: { text: true }, text: "Malicious Code Executed!" }),
                   });
               },
           });
       };
       ```
    2. Create a new VSCode workspace or open an existing one.
    3. Create a `.vscode` folder in the workspace root if it doesn't exist.
    4. Inside the `.vscode` folder, create a `settings.json` file and add the following configuration, replacing `/path/to/your/malicious-visualizer.js` with the absolute path to the `malicious-visualizer.js` file created in step 1:
       ```json
       {
           "debugVisualizer.customVisualizerScriptPaths": [
               "/path/to/your/malicious-visualizer.js"
           ]
       }
       ```
       **Note:** For testing, you can place `malicious-visualizer.js` in the workspace root and use `"${workspaceFolder}/malicious-visualizer.js"` in the settings.
    5. Open the workspace in VSCode.
    6. Open a JavaScript or TypeScript file in the workspace.
    7. Start a debugging session (e.g., Node.js debug configuration).
    8. Open a Debug Visualizer view using the command `Debug Visualizer: New View`.
    9. Observe if an alert dialog with the message 'Code Injection Vulnerability in Debug Visualizer!' is displayed in the webview. If the alert is displayed, it confirms the code injection vulnerability.
    10. Additionally, try to visualize a variable in the Debug Visualizer. You should see a new data extractor named "Malicious Extraction" and selecting it should display "Malicious Code Executed!", further confirming the execution of the custom malicious script.