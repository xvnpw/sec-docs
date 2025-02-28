# High-Severity Vulnerabilities

## Command Injection via Unsanitized "eslint.lintTask.options" in ESLint Task

### Description
The extension creates a "lint whole folder" task by building a shell command from the ESLint binary (found via a helper function) concatenated with user-configurable options. The process is as follows:
- The extension reads the user setting `eslint.lintTask.options` from the workspace configuration (typically from a file such as `.vscode/settings.json`). (If the setting is not present, a default value `"."` is used.)
- It then calls a function (e.g. `findEslint(rootPath)`) to determine the correct ESLint command based on the workspace.
- Without validating or sanitizing the retrieved options, the extension constructs a shell command by concatenating the ESLint command with the (potentially malicious) user-provided options:
  ```ts
  new vscode.Task(
    kind,
    this.workspaceFolder,
    'lint whole folder',
    'eslint',
    new vscode.ShellExecution(`${command} ${lintTaskOptions}`, options),
    '$eslint-stylish'
  );
  ```
- Because this command string is passed to the shell, any embedded shell metacharacters (for example "&&", ";", etc.) will be interpreted. A threat actor who supplies a manipulated repository with a workspace configuration setting, such as:
  ```json
  {
    "eslint.lintTask.options": "&& echo INJECTED && <malicious_command>"
  }
  ```
  can inject additional commands into the constructed shell command.
  
**Step-by-step trigger scenario:**
1. An attacker prepares a repository that includes a manipulated `.vscode/settings.json` file setting the value of `eslint.lintTask.options` to a payload containing shell metacharacters.
2. A victim opens this repository in VS Code. Upon loading the workspace, the extension reads the malicious configuration.
3. When the victim executes the "lint whole folder" task, the unsanitized option is concatenated with the ESLint command, resulting in a command string such as:
   ```
   ./node_modules/.bin/eslint && echo INJECTED && <malicious_command>
   ```
4. The integrated terminal (or shell task process) then executes the entire command line, including the injected commands.

### Impact
The attacker can achieve remote code execution (RCE) on the victim's system. Malicious shell commands will run with the privileges of the user, potentially leading to complete host compromise.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The project does not perform any specific sanitization or safe argument handling for the content of `eslint.lintTask.options`. The command is built by simple string concatenation and executed using `vscode.ShellExecution`, which passes the command directly to the shell.

### Missing Mitigations
To mitigate this vulnerability, the extension should:
- **Avoid constructing commands via string concatenation.** Instead, pass the command and its arguments as an array or use an API that safely escapes or quotes all arguments.
- **Implement rigorous input validation.** Validate the contents of `eslint.lintTask.options` against a whitelist of expected safe values or restrict allowed characters to avoid shell metacharacters.

### Preconditions
- A victim opens a workspace (repository) that contains a malicious `.vscode/settings.json` file with the setting `eslint.lintTask.options` manipulated to include shell metacharacters and injected commands.
- The victim later triggers the "lint whole folder" task provided by the extension.

### Source Code Analysis
1. In the file `/code/client/src/tasks.ts`, the extension does the following:
   - It calls a helper function (e.g., `findEslint(rootPath)`) to locate the ESLint command.
   - It then retrieves the task options using:
     ```ts
     const lintTaskOptions = config.get<string>('lintTask.options', '.');
     ```
   - A new task is created using:
     ```ts
     new vscode.ShellExecution(`${command} ${lintTaskOptions}`, options)
     ```
     Here, the string interpolation does not perform any escaping or validation on the `lintTaskOptions`.
2. Since the `ShellExecution` API passes the full command string to an underlying shell, any malicious payload embedded in `lintTaskOptions` (such as `&&` followed by injected commands) will be executed.

### Security Test Case
1. In a test workspace, add a `.vscode/settings.json` file with the following content:
   ```json
   {
     "eslint.lintTask.options": "&& echo INJECTED && <malicious_command>"
   }
   ```
2. Open the test workspace in VS Code so that the ESLint extension loads the malicious configuration.
3. Open the Command Palette and run the "eslint: lint whole folder" task.
4. Verify that the terminal executes the injected command (`echo INJECTED` or an equivalent marker for the malicious payload).
5. Confirm that the injected command produces observable output or side effects, thereby validating the vulnerability.