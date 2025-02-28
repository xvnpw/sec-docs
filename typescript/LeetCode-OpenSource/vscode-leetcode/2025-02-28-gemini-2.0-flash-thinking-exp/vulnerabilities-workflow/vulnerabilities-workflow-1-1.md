### Vulnerability List:

* Command Injection in Test Solution Feature

- Vulnerability Name: Command Injection in Test Solution Feature
- Description:
    1. An attacker can provide a malicious payload as custom test cases when using the "Test Solution" feature.
    2. The extension passes these test cases to the LeetCode CLI via `test` command.
    3. The LeetCode CLI executes these test cases using `child_process.spawn` without sufficient sanitization.
    4. By crafting a specific payload within the test cases input, an attacker can inject and execute arbitrary shell commands on the user's system.
- Impact:
    - Remote Command Execution: An attacker can execute arbitrary commands on the machine where the VSCode extension is running. This could lead to:
        - Data exfiltration: Access to sensitive files and data on the user's machine.
        - System compromise: Modification or deletion of system files, installation of malware.
        - Privilege escalation: Potential to gain higher privileges on the system depending on the user's context.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - Input Quoting: The `parseTestString` function in `/code/src/commands/test.ts` attempts to mitigate command injection by wrapping the user-provided test string in quotes.
    - Source code location: `/code/src/commands/test.ts`
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
- Missing Mitigations:
    - Input Sanitization: The current quoting mechanism is insufficient to prevent command injection due to the complexities of shell escaping and interpretation. Input sanitization is missing.
    - Input Validation: There is no validation of the test case input to ensure it only contains expected data and not shell commands.
    - Using `child_process.spawn` without `shell: false` can be risky when handling user inputs, even with quoting. Moving to `shell: false` and constructing commands with arguments array can improve security.
- Preconditions:
    - The user must be signed in to LeetCode in the extension.
    - The attacker needs to be able to trick the user into using the "Test Solution" feature and providing malicious input as test cases. This could be achieved through social engineering or by hosting a malicious LeetCode problem with instructions to use specific test cases.
- Source Code Analysis:
    1. **Entry Point:** The vulnerability starts at `/code/src/commands/test.ts` in the `testSolution` function when handling the ":direct" choice for test cases.
    2. **User Input:** The `vscode.window.showInputBox` is used to get test cases from the user:
    ```typescript
    const testString: string | undefined = await vscode.window.showInputBox({
        prompt: "Enter the test cases.",
        validateInput: (s: string): string | undefined => s && s.trim() ? undefined : "Test case must not be empty.",
        placeHolder: "Example: [1,2,3]\\n4",
        ignoreFocusOut: true,
    });
    ```
    3. **Command Execution:** The `testString` is then passed to `leetCodeExecutor.testSolution`:
    ```typescript
    if (testString) {
        result = await leetCodeExecutor.testSolution(filePath, parseTestString(testString));
    }
    ```
    4. **CLI Execution:** In `/code/src/leetCodeExecutor.ts`, the `testSolution` function constructs the command and executes it:
    ```typescript
    public async testSolution(filePath: string, testString?: string): Promise<string> {
        if (testString) {
            return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`, "-t", `${testString}`]);
        }
        return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`]);
    }
    ```
    5. **Vulnerable Function:** `executeCommandWithProgressEx` and `executeCommand` in `/code/src/utils/cpUtils.ts` use `cp.spawn` with `shell: true`:
    ```typescript
    export async function executeCommand(command: string, args: string[], options: cp.SpawnOptions = { shell: true }): Promise<string> {
        return new Promise((resolve: (res: string) => void, reject: (e: Error) => void): void => {
            // ...
            const childProc: cp.ChildProcess = cp.spawn(command, args, { ...options, env: createEnvOption() });
            // ...
        });
    }
    ```
    6. **Input Sanitization Weakness:** While `parseTestString` attempts quoting, it's not robust enough to prevent injection when `shell: true` is used in `cp.spawn`. For example, using backticks or other shell metacharacters within the test string might still lead to command execution.

- Security Test Case:
    1. Open any LeetCode problem file in VSCode using the extension.
    2. Trigger the "LeetCode: Test Solution" command.
    3. Choose the option "Write directly...".
    4. In the input box, enter the following payload as test cases:
    ```
    `whoami > /tmp/pwned`
    ```
    5. Press Enter to run the test.
    6. After the test execution (which might fail as it's not valid test input), check if a file named `pwned` has been created in the `/tmp/` directory of your system.
    7. If the file `pwned` exists and contains the output of the `whoami` command, it confirms that command injection is possible.

    **Note:** For Windows, you might need to adjust the command, e.g., try `powershell.exe -Command "Get-Content whoami > C:\pwned.txt"` and check for `C:\pwned.txt`. For macOS/Linux, `touch /tmp/pwned_test` and check for file creation is a safer test. For security reasons, avoid commands that modify system state or exfiltrate data during testing.