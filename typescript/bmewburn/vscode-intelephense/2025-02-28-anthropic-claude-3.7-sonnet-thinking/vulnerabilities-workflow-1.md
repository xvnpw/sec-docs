# Vulnerabilities in Intelephense VSCode Extension

## Custom Runtime Configuration Remote Code Execution (RCE)

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
This vulnerability allows for remote code execution on the victim's system. The malicious code would execute with the same privileges as the VSCode process, giving the attacker access to the victim's system. The attacker could potentially access sensitive files, install additional malware, or modify files, or further compromise the host.

### Vulnerability Rank
High

### Currently Implemented Mitigations
There are no mitigations currently implemented in the code. The extension trusts the runtime value from configuration without any validation or sanitization step against a whitelist of allowed runtime executables.

### Missing Mitigations
1. Validation of the runtime path to ensure it's a legitimate Node.js executable
2. Ignoring workspace settings for security-critical configurations like runtime
3. Implementing a whitelist of allowed runtime executables
4. Adding a warning or prompt when a custom runtime is specified
5. Sanitizing and rejecting unexpected characters or paths that could lead to command injection
6. Consider adding logging when a non-default runtime is specified to alert users to possible tampering

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

The language client (from the vscode-languageclient library) will use these options to start a new process:

```typescript
languageClient = new LanguageClient('intelephense', 'intelephense', serverOptions, clientOptions);
```

The `runtime` value directly controls which executable will be used to run the language server, without any validation or sanitization. If this value points to a malicious executable, that executable will be run when the language server is started.

**Visualization:**
- **Step 1:** Attacker supplies a repository with a `.vscode/settings.json` that contains:
  ```json
  {
    "intelephense.runtime": "/tmp/malicious.sh"
  }
  ```
- **Step 2:** On activation, the extension calls `workspace.getConfiguration('intelephense')` and retrieves the attacker-controlled value.
- **Step 3:** The extension passes this value directly to `serverOptions.run.runtime` (and its debug equivalent).
- **Step 4:** When the language server spawns, it runs `/tmp/malicious.sh`, executing arbitrary code with the victim's privileges.

### Security Test Case
To verify this vulnerability:

1. **Setup a Malicious Repository:**
   - Create a proof-of-concept repository with the following structure:
   - `.vscode/settings.json` containing:
     ```json
     {
       "intelephense.runtime": "/path/to/malicious/executable"
     }
     ```
   - Create some PHP files to ensure the extension activates
   - Ensure that the test script is accessible and performs an observable action (creating a file or writing to a log)

2. **Create a benign "malicious" executable that proves code execution:**
   - A script that creates a file in a known location with a timestamp and identifier
   - Logs information to demonstrate it ran
   - Then launches the actual Node.js to allow the extension to function normally

3. **Open the Workspace in VSCode:**
   - Open the test repository in VSCode with the Intelephense extension installed
   - When prompted to trust the workspace settings, accept them
   - Open a PHP file to trigger the extension's activation

4. **Observation:**
   - Verify that the malicious executable ran by checking for the created file or logs
   - This confirms that an attacker can achieve arbitrary code execution through a malicious repository by specifying a custom runtime in the workspace settings

5. **Validation:**
   - Confirm that without mitigation the malicious executable is invoked
   - Then, apply a mitigation (such as enforcing a whitelist) and repeat the test to ensure the malicious value is rejected or ignored