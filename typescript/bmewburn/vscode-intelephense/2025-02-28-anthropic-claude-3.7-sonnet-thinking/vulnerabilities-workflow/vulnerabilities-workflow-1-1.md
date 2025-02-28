# Vulnerabilities in Intelephense VSCode Extension

## Custom Runtime Configuration RCE Vulnerability

### Vulnerability Name
Custom Runtime Configuration Remote Code Execution (RCE) Vulnerability

### Description
The Intelephense VSCode extension allows users to specify a custom Node.js runtime through the `intelephense.runtime` configuration setting. This configuration is loaded without proper validation and used directly to spawn a new process for the language server. A malicious repository can include a `.vscode/settings.json` file that specifies a malicious executable as the runtime. When a victim opens this repository in VSCode and accepts the workspace settings (which many developers do automatically), the extension will use the attacker-specified executable instead of the legitimate Node.js runtime.

Step by step exploitation:
1. An attacker creates a malicious repository with a `.vscode/settings.json` file
2. The settings file contains a modified `intelephense.runtime` value pointing to a malicious executable
3. When a victim opens the repository in VSCode, they are prompted to trust the workspace settings
4. If the victim trusts the settings (a common action for developers), the extension will use the malicious executable
5. The next time the PHP language server activates, it will execute the attacker's code with the same privileges as the VSCode process

### Impact
This vulnerability allows for remote code execution on the victim's system. The malicious code would execute with the same privileges as the VSCode process, giving the attacker access to the victim's system. The attacker could potentially access sensitive files, install additional malware, or establish persistence on the system.

### Vulnerability Rank
High

### Currently Implemented Mitigations
There are no mitigations currently implemented in the code. The extension trusts the runtime value from configuration without any validation.

### Missing Mitigations
1. Validation of the runtime path to ensure it's a legitimate Node.js executable
2. Ignoring workspace settings for security-critical configurations like runtime
3. Implementing a whitelist of allowed runtime executables
4. Adding a warning or prompt when a custom runtime is specified

### Preconditions
1. The victim must open a malicious repository in VSCode
2. The victim must trust the workspace settings when prompted
3. The victim must have the Intelephense extension installed
4. The malicious executable specified in the settings must be accessible on the victim's system

### Source Code Analysis
In `/code/src/extension.ts`, the function `createClient` retrieves the runtime configuration from the workspace settings without any validation:

```typescript
let intelephenseConfig = workspace.getConfiguration('intelephense');
let runtime = intelephenseConfig.get('runtime') as string | undefined;

if (runtime) {
    serverOptions.run.runtime = runtime;
    serverOptions.debug.runtime = runtime;
}
```

This configuration is then used to set up the server options:

```typescript
let serverOptions: ServerOptions = {
    run: { module: serverModule, transport: TransportKind.ipc },
    debug: { module: serverModule, transport: TransportKind.ipc, options: debugOptions }
}
```

The `runtime` value directly controls which executable will be used to run the language server, without any validation or sanitization. If this value points to a malicious executable, that executable will be run when the language server is started.

### Security Test Case
To verify this vulnerability:

1. Create a proof-of-concept repository with the following structure:
   - `.vscode/settings.json` containing:
     ```json
     {
       "intelephense.runtime": "/path/to/malicious/executable"
     }
     ```
   - Create some PHP files to ensure the extension activates

2. Create a benign "malicious" executable that proves code execution, such as a script that:
   - Creates a file in a known location with a timestamp and identifier
   - Logs information to demonstrate it ran
   - Then launches the actual Node.js to allow the extension to function normally

3. Open the repository in VSCode with the Intelephense extension installed:
   - When prompted to trust the workspace settings, accept them
   - Open a PHP file to trigger the extension's activation
   - Verify that the malicious executable ran by checking for the created file or logs

4. This confirms that an attacker can achieve arbitrary code execution through a malicious repository by specifying a custom runtime in the workspace settings.