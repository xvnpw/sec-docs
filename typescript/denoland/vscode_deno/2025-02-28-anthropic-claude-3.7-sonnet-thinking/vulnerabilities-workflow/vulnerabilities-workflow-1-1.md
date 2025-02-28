# Vulnerabilities in VSCode Deno Extension

## 1. Remote Code Execution via deno.path Setting

### Description
The VSCode Deno extension allows users to specify a custom path to the Deno executable using the `deno.path` setting. When processing this setting, the extension performs minimal validation and will execute whatever binary is at the specified path. An attacker can create a malicious repository with a custom `.vscode/settings.json` file that points `deno.path` to a malicious executable within the repository or at an attacker-controlled location.

Step by step exploitation:
1. Attacker creates a repository with a `.vscode/settings.json` file containing a malicious deno.path value
2. The settings.json file points to a malicious executable in the repository: `"deno.path": "./tools/deno"`
3. Attacker also includes the malicious executable in the repository
4. When a victim opens this repository in VSCode with the Deno extension installed
5. The extension reads the deno.path setting from settings.json
6. It resolves the relative path against the workspace folder
7. It confirms the file exists (but doesn't validate if it's actually Deno)
8. It executes the malicious file with the victim's privileges

### Impact
This vulnerability allows arbitrary code execution on the victim's machine with the victim's privileges. Since VSCode extensions run with the same privileges as the user, the malicious executable can access all resources available to the user, including files, network access, and system resources.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The only existing mitigation is a basic check that the file exists, but there's no validation that the file is actually a legitimate Deno executable.

### Missing Mitigations
1. Signature or checksum verification of the Deno binary before execution
2. Warning users when they're opening a repository that has a custom deno.path setting
3. Sandboxing the execution of the binary
4. Restricting execution to known Deno binaries or requiring explicit user confirmation

### Preconditions
- Victim must have the Deno extension installed in VSCode
- Victim must open a malicious repository
- The extension must be activated (which happens automatically when opening a Deno project or when Deno settings are detected)

### Source Code Analysis
In `client/src/util.ts`, the `getDenoCommandPath()` function resolves the path to the Deno executable:

```typescript
export async function getDenoCommandPath() {
  const command = getWorkspaceConfigDenoExePath();
  const workspaceFolders = workspace.workspaceFolders;
  if (!command || !workspaceFolders) {
    return command ?? await getDefaultDenoCommand();
  } else if (!path.isAbsolute(command)) {
    // if sent a relative path, iterate over workspace folders to try and resolve.
    for (const workspace of workspaceFolders) {
      const commandPath = path.resolve(workspace.uri.fsPath, command);
      if (await fileExists(commandPath)) {
        return commandPath;
      }
    }
    return undefined;
  } else {
    return command;
  }
}
```

This function gets the Deno path from the workspace configuration using `getWorkspaceConfigDenoExePath()`. If the path is relative, it resolves it against the workspace folders. It only checks if the file exists but doesn't validate that it's a legitimate Deno executable.

In `client/src/commands.ts`, the `startLanguageServer` function uses this path to start the Deno language server:

```typescript
const command = await getDenoCommandPath();
if (command == null) {
  // ... error handling ...
  return;
}

const serverOptions: ServerOptions = {
  run: {
    command,
    args: ["lsp"],
    options: { env },
  },
  debug: {
    command,
    args: ["lsp"],
    options: { env },
  },
};
```

The command is directly executed with the argument "lsp", expecting it to be the Deno executable. If it's a malicious executable, it will be executed with the victim's privileges.

### Security Test Case
1. Create a new repository with the following structure:
   ```
   .vscode/settings.json
   malicious-deno
   ```

2. In `.vscode/settings.json`, add:
   ```json
   {
     "deno.enable": true,
     "deno.path": "../malicious-deno"
   }
   ```

3. Create a malicious executable (`malicious-deno`):
   ```bash
   #!/bin/bash
   # This is just an example - in a real attack this would be more sophisticated
   echo "Malicious code executed" > /tmp/pwned
   # Then run the real Deno LSP to avoid suspicion
   /usr/bin/deno lsp "$@"
   ```
   (Make it executable: `chmod +x malicious-deno`)

4. When a victim opens this repository in VSCode with the Deno extension installed, the malicious executable will run.

5. Verify that `/tmp/pwned` file exists, indicating the malicious code was executed.

## 2. Command Injection via Environment Variables

### Description
The VSCode Deno extension allows users to specify environment variables through the `deno.env` setting and an environment file via the `deno.envFile` setting. These environment variables are passed directly to the Deno process without validation. An attacker can craft a malicious repository that sets environment variables designed to exploit vulnerabilities in Deno or the host system.

Step by step exploitation:
1. Attacker creates a repository with settings that specify malicious environment variables
2. The malicious environment variables could include those that affect dynamic library loading (e.g., LD_PRELOAD on Linux)
3. When a victim opens this repository in VSCode with the Deno extension installed
4. The extension reads the environment variables and applies them to the Deno process
5. The malicious environment variables cause the Deno process to execute attacker-controlled code

### Impact
This vulnerability could lead to arbitrary code execution within the Deno process context. Depending on the specific environment variables and the platform, this could allow accessing user's files, network resources, or even full system compromise.

### Vulnerability Rank
High

### Currently Implemented Mitigations
There are no meaningful mitigations. The environment variables are read and applied without validation.

### Missing Mitigations
1. Sanitizing or validating environment variables
2. Maintaining a whitelist of allowed environment variables
3. Warning users when potentially dangerous environment variables are being set
4. Running the Deno process in a restricted environment

### Preconditions
- Victim must have the Deno extension installed in VSCode
- Victim must open a malicious repository
- The extension must be activated
- The specific attack vector depends on the operating system and its vulnerabilities

### Source Code Analysis
In `client/src/commands.ts`, the `startLanguageServer` function reads environment variables from configuration:

```typescript
const env: Record<string, string | undefined> = {
  ...process.env,
};
const denoEnvFile = config.get<string>("envFile");
if (denoEnvFile) {
  if (workspaceFolder) {
    const denoEnvPath = path.join(workspaceFolder.uri.fsPath, denoEnvFile);
    try {
      const content = fs.readFileSync(denoEnvPath, { encoding: "utf8" });
      const parsed = dotenv.parse(content);
      Object.assign(env, parsed);
    } catch (error) {
      vscode.window.showErrorMessage(
        `Could not read env file "${denoEnvPath}": ${error}`,
      );
    }
  }
}
const denoEnv = config.get<Record<string, string>>("env");
if (denoEnv) {
  Object.assign(env, denoEnv);
}
```

These environment variables are then passed directly to the Deno process without any validation:

```typescript
const serverOptions: ServerOptions = {
  run: {
    command,
    args: ["lsp"],
    options: { env },
  },
  debug: {
    command,
    args: ["lsp"],
    options: { env },
  },
};
```

Similarly, in other parts of the codebase, environment variables are collected and passed to Deno processes without validation, such as in the `test` function and the `DenoDebugConfigurationProvider` class.

### Security Test Case
For Linux systems:

1. Create a new repository with the following structure:
   ```
   .vscode/settings.json
   evil.so
   ```

2. In `.vscode/settings.json`, add:
   ```json
   {
     "deno.enable": true,
     "deno.env": {
       "LD_PRELOAD": "./evil.so"
     }
   }
   ```

3. Create a malicious shared library (`evil.so`) that hooks into standard library functions and executes attacker code.

4. When a victim opens this repository in VSCode with the Deno extension installed, the malicious shared library will be loaded into the Deno process.

5. Verify that the malicious code in the shared library is executed when the Deno language server starts.

## 3. Code Injection via Import Maps

### Description
The VSCode Deno extension allows users to specify import maps through the `deno.importMap` setting. Import maps allow redirecting module specifiers to different URLs or local files. An attacker can create a malicious repository with an import map that redirects legitimate modules to attacker-controlled code.

Step by step exploitation:
1. Attacker creates a repository with a custom import map file
2. The import map redirects standard modules to attacker-controlled versions
3. When a victim opens this repository in VSCode with the Deno extension installed
4. The extension passes the import map to the Deno language server
5. When Deno resolves imports, it uses the attacker-controlled modules

### Impact
This vulnerability allows an attacker to inject malicious code that will be executed within the Deno language server process. This can lead to theft of sensitive information, execution of arbitrary code in the victim's environment, and potentially compromise of the entire system.

### Vulnerability Rank
High

### Currently Implemented Mitigations
There are no specific mitigations for this vulnerability. The import map is passed directly to the Deno language server without validation.

### Missing Mitigations
1. Validating import maps for suspicious redirects
2. Warning users when opening projects with custom import maps
3. Restricting the types of redirects that can be performed via import maps
4. Sandboxing the execution of code loaded through import maps

### Preconditions
- Victim must have the Deno extension installed in VSCode
- Victim must open a malicious repository containing a custom import map
- The extension must be activated and the Deno language server must use the import map

### Source Code Analysis
In `client/src/debug_config_provider.ts`, the `#getAdditionalRuntimeArgs()` method adds the import map to the Deno CLI arguments:

```typescript
#getAdditionalRuntimeArgs() {
  const args: string[] = [];
  const settings = this.#extensionContext.clientOptions
    .initializationOptions();
  if (settings.unstable) {
    args.push("--unstable");
  }
  if (settings.importMap) {
    args.push("--import-map");
    args.push(settings.importMap.trim());
  }
  if (settings.config) {
    args.push("--config");
    args.push(settings.config.trim());
  }
  return args;
}
```

Similarly, in the `test` function in `client/src/commands.ts`, the import map is added to the test command:

```typescript
if (!testArgs.includes("--import-map")) {
  const importMap: string | undefined | null = config.get("importMap");
  if (importMap?.trim()) {
    testArgs.push("--import-map", importMap.trim());
  }
}
```

The import map path is passed directly to the Deno CLI without validating its contents or warning the user about potential security risks.

### Security Test Case
1. Create a new repository with the following structure:
   ```
   .vscode/settings.json
   import_map.json
   malicious_module.ts
   ```

2. In `.vscode/settings.json`, add:
   ```json
   {
     "deno.enable": true,
     "deno.importMap": "./import_map.json"
   }
   ```

3. In `import_map.json`, create mappings that redirect standard modules to local malicious versions:
   ```json
   {
     "imports": {
       "https://deno.land/std/http/server.ts": "./malicious_module.ts"
     }
   }
   ```

4. In `malicious_module.ts`, include code that executes malicious operations when imported:
   ```typescript
   console.log("Malicious module loaded");
   // Steal sensitive data, execute commands, etc.
   // Then re-export the expected API to avoid detection
   export * from "https://deno.land/std@0.177.0/http/server.ts";
   ```

5. When a victim opens this repository and imports the standard HTTP server module, the malicious version will be loaded instead.

6. Verify that the malicious code is executed when the module is imported in the Deno language server.