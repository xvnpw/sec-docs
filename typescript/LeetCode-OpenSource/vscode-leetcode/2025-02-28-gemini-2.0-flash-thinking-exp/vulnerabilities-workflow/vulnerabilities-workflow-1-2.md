## Vulnerability List:

### 1. Command Injection in Test Solution Feature

- **Description:**
    1. An attacker can craft a malicious file path or input string for the "LeetCode: Test Solution" command.
    2. When the extension executes the test command using the LeetCode CLI, this malicious input is passed as an argument to the underlying shell command.
    3. Due to insufficient sanitization of user-provided input, the attacker can inject arbitrary shell commands into the test execution process.
    4. This can be triggered by using the "LeetCode: Test Solution" command and choosing "Write directly..." or "Browse..." options, then providing malicious input in the input box or a selected file.

- **Impact:**
    - **High**
    - Successful command injection allows the attacker to execute arbitrary commands on the user's machine with the privileges of the VS Code process. This could lead to:
        - Data exfiltration: Accessing and stealing sensitive files and information from the user's system.
        - System compromise: Modifying system files, installing malware, creating new user accounts, or taking complete control of the user's machine.
        - Privilege escalation: Potentially escalating privileges if the VS Code process runs with elevated permissions.

- **Vulnerability Rank:**
    - High

- **Currently implemented mitigations:**
    - The `parseTestString` function in `/code/src/commands/test.ts` attempts to quote the test string to prevent command injection.
    - Different quoting methods are used based on the operating system and shell environment (WSL, Windows cmd, PowerShell).

- **Missing mitigations:**
    - Input sanitization: The `parseTestString` function only adds quotes but doesn't sanitize the content of the `testString` itself. It does not prevent all forms of command injection, especially in complex shell environments or with specific characters.
    - Secure command execution: Instead of using `shell: true` in `cp.spawn`, the extension should execute the command directly without involving a shell interpreter. This would prevent shell-based command injection vulnerabilities.
    - Input validation: Implement stricter validation on the `testString` to ensure it only contains expected characters and patterns for test cases, rejecting any potentially malicious input.

- **Preconditions:**
    - The attacker needs to be able to interact with the VS Code extension, specifically by triggering the "LeetCode: Test Solution" command.
    - The user must choose to provide custom test cases, either by writing them directly or by selecting a file.

- **Source code analysis:**
    1. **File:** `/code/src/commands/test.ts`
    2. **Function:** `testSolution(uri?: vscode.Uri)`
    3. **Code snippet:**
    ```typescript
    case ":direct":
        const testString: string | undefined = await vscode.window.showInputBox({
            prompt: "Enter the test cases.",
            validateInput: (s: string): string | undefined => s && s.trim() ? undefined : "Test case must not be empty.",
            placeHolder: "Example: [1,2,3]\\n4",
            ignoreFocusOut: true,
        });
        if (testString) {
            result = await leetCodeExecutor.testSolution(filePath, parseTestString(testString));
        }
        break;
    case ":file":
        const testFile: vscode.Uri[] | undefined = await showFileSelectDialog(filePath);
        if (testFile && testFile.length) {
            const input: string = (await fse.readFile(testFile[0].fsPath, "utf-8")).trim();
            if (input) {
                result = await leetCodeExecutor.testSolution(filePath, parseTestString(input.replace(/\r?\n/g, "\\n")));
            } else {
                vscode.window.showErrorMessage("The selected test file must not be empty.");
            }
        }
        break;
    ```
    4. The `testString` from user input or file is passed to `parseTestString`.
    5. **Function:** `parseTestString(test: string)` in the same file.
    6. **Code snippet:**
    ```typescript
    function parseTestString(test: string): string {
        if (wsl.useWsl() || !isWindows()) {
            return `'${test}'`;
        }

        // In windows and not using WSL
        if (usingCmd()) {
            return `"${test.replace(/"/g, '\\"')}"`;
        } else {
            // Assume using PowerShell
            return `'${test.replace(/"/g, '\\"')}'`;
        }
    }
    ```
    7. `parseTestString` adds single or double quotes based on the environment but does not prevent injection of shell commands within the `test` string itself.
    8. **File:** `/code/src/leetCodeExecutor.ts`
    9. **Function:** `testSolution(filePath: string, testString?: string)`
    10. **Code snippet:**
    ```typescript
    public async testSolution(filePath: string, testString?: string): Promise<string> {
        if (testString) {
            return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`, "-t", `${testString}`]);
        }
        return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`]);
    }
    ```
    11. The `testString` returned from `parseTestString` is directly embedded into the command arguments without further sanitization.
    12. **Function:** `executeCommandWithProgressEx` and `executeCommandEx` call `executeCommand` which uses `cp.spawn` with `shell: true`.
    13. **File:** `/code/src/utils/cpUtils.ts`
    14. **Function:** `executeCommand(command: string, args: string[], options: cp.SpawnOptions = { shell: true })`
    15. **Code snippet:**
    ```typescript
    const childProc: cp.ChildProcess = cp.spawn(command, args, { ...options, env: createEnvOption() });
    ```
    16. `cp.spawn` with `shell: true` interprets the arguments as shell commands, making it vulnerable to command injection.

- **Security test case:**
    1. Install the LeetCode VS Code extension.
    2. Open a LeetCode problem file in VS Code.
    3. Trigger the "LeetCode: Test Solution" command.
    4. Choose the "Write directly..." option.
    5. In the input box, enter a malicious payload that attempts to execute a command, for example: `\`test case\` && touch /tmp/pwned\` (for Linux/macOS) or `\`test case\` & echo pwned > C:\pwned.txt` (for Windows PowerShell).  A simpler payload that should work cross-platform is to use backticks to execute a command substitution like: ```test case`touch poc.txt` ```
    6. Execute the test.
    7. After the test execution, check if the command was executed. For example, check if the `/tmp/pwned` file (or `C:\pwned.txt` or `poc.txt`) was created.
    8. If the file is created, it confirms that command injection is possible through the test input.