## Vulnerability List:

- Command Injection via File Path in `leetCodeExecutor.ts`

### Vulnerability name:

Command Injection via File Path in `leetCodeExecutor.ts`

### Description:

The `LeetCodeExecutor` class in `leetCodeExecutor.ts` executes LeetCode CLI commands by spawning child processes. Several functions in this class, such as `submitSolution`, `testSolution`, and `showProblem`, take file paths as input and pass them as arguments to the CLI commands. These file paths are not properly sanitized before being passed to the shell. An attacker could potentially craft a malicious file path that, when processed by the extension, would lead to the execution of arbitrary commands on the user's system.

**Step-by-step trigger:**

1.  An attacker crafts a file path that contains shell command injection payloads. For example, a file path could be named: `"test.js & touch injected.txt"`.
2.  The user opens this malicious file in VS Code and attempts to submit or test the solution using the LeetCode extension (e.g., by clicking "Submit" or "Test" code lens or using commands).
3.  The extension calls the `submitSolution` or `testSolution` function in `leetCodeExecutor.ts`, passing the malicious file path as an argument to the LeetCode CLI command.
4.  The `executeCommandWithProgressEx` or `executeCommandEx` function in `leetCodeExecutor.ts` executes the CLI command using `cp.spawn` with `shell: true`. Due to `shell: true` and lack of sanitization, the shell interprets the malicious file path, executing the injected commands.
5.  In the example path, the command `touch injected.txt` would be executed in addition to the intended LeetCode CLI command.

### Impact:

Successful command injection can allow an attacker to execute arbitrary commands on the user's machine with the privileges of the VS Code process. This could lead to:

-   **Data exfiltration**: Attacker can access and steal sensitive files from the user's system.
-   **Malware installation**: Attacker can download and execute malware on the user's system.
-   **System compromise**: Attacker can gain complete control over the user's system.

This vulnerability is considered **critical** because it allows for arbitrary code execution, which is the most severe type of security vulnerability.

### Vulnerability rank:

Critical

### Currently implemented mitigations:

None. The code directly passes file paths to shell commands without any sanitization or validation. The usage of `shell: true` in `cp.spawn` exacerbates the vulnerability.

### Missing mitigations:

-   **Input sanitization**: File paths should be properly sanitized to remove or escape any characters that could be interpreted as shell commands.
-   **Avoid `shell: true`**:  When using `cp.spawn`, `shell: true` should be avoided unless absolutely necessary. If shell execution is required, arguments should be carefully quoted and escaped. In this case, `shell: true` is likely not needed and can be removed.
-   **Parameterization**: If possible, use parameterized commands to separate commands from arguments, although this is less applicable when directly invoking a CLI tool.
-   **Principle of least privilege**: While not a direct mitigation, running VS Code and the extension with the least necessary privileges can limit the impact of a successful exploit.

### Preconditions:

1.  The user must have the LeetCode extension installed and activated in VS Code.
2.  The attacker needs to trick the user into opening a file with a malicious file path. This could be achieved through various means, such as:
    -   Social engineering: Sending a problem file with a malicious name to the user.
    -   Compromising a project: If the user opens a project containing a file with a malicious name.

### Source code analysis:

1.  **File:** `/code/src/leetCodeExecutor.ts`
2.  **Functions of interest:** `submitSolution`, `testSolution`, `showProblem`, `executeCommandEx`, `executeCommandWithProgressEx`

```typescript
    public async submitSolution(filePath: string): Promise<string> {
        try {
            return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "submit", `"${filePath}"`]);
        } catch (error) {
            if (error.result) {
                return error.result;
            }
            throw error;
        }
    }

    public async testSolution(filePath: string, testString?: string): Promise<string> {
        if (testString) {
            return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`, "-t", `${testString}`]);
        }
        return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`]);
    }

    public async showProblem(problemNode: IProblem, language: string, filePath: string, showDescriptionInComment: boolean = false, needTranslation: boolean): Promise<void> {
        const templateType: string = showDescriptionInComment ? "-cx" : "-c";
        const cmd: string[] = [await this.getLeetCodeBinaryPath(), "show", problemNode.id, templateType, "-l", language];

        if (!needTranslation) {
            cmd.push("-T"); // use -T to force English version
        }

        if (!await fse.pathExists(filePath)) {
            await fse.createFile(filePath);
            const codeTemplate: string = await this.executeCommandWithProgressEx("Fetching problem data...", this.nodeExecutable, cmd);
            await fse.writeFile(filePath, codeTemplate);
        }
    }

    private async executeCommandEx(command: string, args: string[], options: cp.SpawnOptions = { shell: true }): Promise<string> {
        if (wsl.useWsl()) {
            return await executeCommand("wsl", [command].concat(args), options);
        }
        return await executeCommand(command, args, options);
    }

    private async executeCommandWithProgressEx(message: string, command: string, args: string[], options: cp.SpawnOptions = { shell: true }): Promise<string> {
        if (wsl.useWsl()) {
            return await executeCommandWithProgress(message, "wsl", [command].concat(args), options);
        }
        return await executeCommandWithProgress(message, command, args, options);
    }
```

In these functions, `filePath` is directly embedded into the command arguments. The functions `executeCommandEx` and `executeCommandWithProgressEx` then call `executeCommand`:

```typescript
export async function executeCommand(command: string, args: string[], options: cp.SpawnOptions = { shell: true }): Promise<string> {
    return new Promise((resolve: (res: string) => void, reject: (e: Error) => void): void => {
        let result: string = "";

        const childProc: cp.ChildProcess = cp.spawn(command, args, { ...options, env: createEnvOption() });
        // ...
    });
}
```

Here, `cp.spawn` is called with `shell: true`. When `shell: true` is used, the first argument to `spawn` is interpreted as a command string to be executed by a shell (like `bash` or `cmd.exe`), and `args` are passed as arguments to the shell, not directly to the command. This, combined with the lack of sanitization of `filePath`, allows for command injection.

**Visualization:**

```
User Input (Malicious File Path) --> LeetCode Extension --> leetCodeExecutor.ts (submitSolution/testSolution/showProblem) --> executeCommandWithProgressEx/executeCommandEx --> executeCommand --> cp.spawn({shell: true}, ...) --> Shell Execution (Command Injection) --> System Compromise
```

### Security test case:

**Prerequisites:**

1.  VS Code with LeetCode extension installed.
2.  A LeetCode account and signed into the extension.

**Steps:**

1.  Create a new file named `"vuln.js & touch injected_submit.txt"` (or `"vuln.js & calc.exe"` on Windows for a more visible impact).
2.  Add some JavaScript code to the file (e.g., `console.log("test");`).
3.  Open this file in VS Code.
4.  Use the LeetCode extension to submit this file (e.g., click "Submit" code lens or use "LeetCode: Submit Solution" command).
5.  Observe if a file named `injected_submit.txt` is created in your workspace directory (or if calculator app `calc.exe` is launched on Windows). If so, command injection is successful.

**Expected result:**

A file named `injected_submit.txt` (or calculator app) should be created/launched, indicating that the injected command within the file path was executed by the system shell during the submission process.

**Note:** For testing "Test Solution", repeat steps 1-5 but trigger the "Test" functionality instead of "Submit". For "Show Problem", you would need to find a way to control the output file path, which might be less directly exploitable in this scenario but still highlights the underlying issue. For testing "Show Problem" you might need to modify the extension settings to use a predictable file path and then try to create a problem with a name containing injection payload.

This test case demonstrates that arbitrary commands can be executed by crafting a malicious file path and using the submit/test functionalities of the LeetCode extension, confirming the command injection vulnerability.