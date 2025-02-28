## Combined Vulnerability List:

### Command Injection Vulnerability in LeetCode Extension

- Vulnerability Name: Command Injection Vulnerability in LeetCode Extension
- Description:
    1. The LeetCode VS Code extension is vulnerable to command injection due to insecure handling of user-provided inputs and file paths when executing LeetCode CLI commands.
    2. Several features, including "Test Solution" and "Submit Solution", and potentially "Show Problem", pass user-controlled data or file paths as arguments to the LeetCode CLI.
    3. Specifically, in the "Test Solution" feature, an attacker can provide malicious payloads as custom test cases, either by writing them directly or through a file.
    4. In features like "Submit Solution", the extension uses the file path of the opened solution file, which could be maliciously crafted.
    5. The extension utilizes `child_process.spawn` with the `shell: true` option to execute these CLI commands.
    6. Due to the `shell: true` setting and insufficient sanitization of user inputs (test cases) and file paths, an attacker can inject and execute arbitrary shell commands on the user's system.
    7. This can be triggered through the "Test Solution" feature by providing malicious test cases, or by opening a file with a malicious file path and using features like "Submit Solution" or "Test Solution".

- Impact:
    - Remote Command Execution: Successful command injection allows an attacker to execute arbitrary commands on the machine where the VSCode extension is running, with the privileges of the VS Code process. This is a critical vulnerability with severe consequences:
        - Data exfiltration: Access to and theft of sensitive files and data on the user's machine, including source code, personal documents, and credentials.
        - System compromise: Modification or deletion of system files, installation of malware (like ransomware, spyware, or botnets), creation of new user accounts, and potentially gaining complete control over the user's machine.
        - Privilege escalation: Potential to escalate privileges further depending on the user's context and system configurations.
        - Denial of Service: Possibility to crash the system or consume resources, leading to denial of service.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - Input Quoting: The `parseTestString` function in `/code/src/commands/test.ts` attempts to mitigate command injection for the "Test Solution" feature by wrapping the user-provided test string in quotes.
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
    - Weakness of Quoting: This quoting mechanism is insufficient to prevent command injection, especially when `shell: true` is used. Shell quoting is complex and can be bypassed using various shell metacharacters and techniques (e.g., backticks, `$(...)`, brace expansion).

- Missing Mitigations:
    - Input Sanitization: The current quoting mechanism is not robust enough. Proper input sanitization is missing. User-provided inputs, especially test cases and file paths, should be sanitized to remove or escape shell-sensitive characters and prevent command injection.
    - Input Validation: There is no validation of the test case input or file paths to ensure they only contain expected data and not shell commands. Input validation should be implemented to restrict the allowed characters and patterns.
    - Secure Command Execution: The extension uses `child_process.spawn` with `shell: true`, which is inherently risky when handling user inputs. The `shell: true` option should be avoided. The extension should be refactored to use `shell: false` and construct commands with arguments array, directly passing arguments to the executable, instead of relying on shell interpretation.
    - Parameterization: While directly parameterizing CLI tools might not always be feasible, the principle of separating commands from arguments should be strictly followed when constructing and executing commands.

- Preconditions:
    - The user must have the LeetCode extension installed and activated in VS Code.
    - The user must be signed in to LeetCode in the extension.
    - For "Test Solution" vulnerability via test cases: The attacker needs to trick the user into using the "Test Solution" feature and providing malicious input as test cases. This could be achieved through social engineering or by hosting a malicious LeetCode problem with instructions to use specific test cases.
    - For "Command Injection via File Path": The attacker needs to trick the user into opening a file with a malicious file path. This could be achieved through social engineering (sending a problem file with a malicious name) or by compromising a project the user opens in VS Code.

- Source Code Analysis:
    1. **Entry Points:**
        - `/code/src/commands/test.ts`: `testSolution` function, handling "Test Solution" feature, especially with ":direct" and ":file" options for custom test cases.
        - `/code/src/leetCodeExecutor.ts`: `submitSolution`, `testSolution`, `showProblem` functions, handling file paths for submission, testing, and problem display features.
    2. **User Input (Test Cases):** In `/code/src/commands/test.ts`, user input for test cases is obtained via `vscode.window.showInputBox` or read from a file. This input is then passed to `leetCodeExecutor.testSolution`.
    ```typescript
    // ... in testSolution function in /code/src/commands/test.ts
    const testString: string | undefined = await vscode.window.showInputBox({ ... }); // User input
    // ...
    result = await leetCodeExecutor.testSolution(filePath, parseTestString(testString));
    ```
    3. **File Path Input (Solution File):** Functions like `submitSolution` and `testSolution` in `/code/src/leetCodeExecutor.ts` take `filePath` as input, representing the path to the solution file opened in VS Code. This file path is controlled by the user (attacker if they can manipulate the file system or project structure).
    4. **Command Construction and Execution:** In `/code/src/leetCodeExecutor.ts`, functions like `testSolution`, `submitSolution`, and `showProblem` construct commands using `filePath` and `testString`.
    ```typescript
    // ... in testSolution function in /code/src/leetCodeExecutor.ts
    public async testSolution(filePath: string, testString?: string): Promise<string> {
        if (testString) {
            return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`, "-t", `${testString}`]);
        }
        return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`]);
    }
    ```
    5. **Vulnerable Function:** `executeCommandWithProgressEx` and `executeCommand` in `/code/src/utils/cpUtils.ts` use `cp.spawn` with `shell: true`.
    ```typescript
    // ... in executeCommand function in /code/src/utils/cpUtils.ts
    export async function executeCommand(command: string, args: string[], options: cp.SpawnOptions = { shell: true }): Promise<string> {
        const childProc: cp.ChildProcess = cp.spawn(command, args, { ...options, env: createEnvOption() });
        // ...
    }
    ```
    6. **`parseTestString` Weakness:** While `parseTestString` attempts quoting, it is insufficient to prevent injection because `shell: true` is used in `cp.spawn`. Shells are complex, and simple quoting can be bypassed. Embedding user-controlled strings into shell commands without proper sanitization or using `shell: false` leads to command injection.
    7. **File Path Vulnerability:**  The `filePath` variable, derived from the name of the opened file in VS Code, is also passed unsanitized into the command arguments. If a user opens a file with a maliciously crafted name (e.g., `vuln.js & touch injected.txt`), this malicious file path will be passed to `cp.spawn({ shell: true })`, leading to command injection.

- Security Test Case:
    1. **Test Case Injection (Test Solution Feature):**
        - Open any LeetCode problem file in VSCode using the extension.
        - Trigger the "LeetCode: Test Solution" command.
        - Choose the option "Write directly...".
        - In the input box, enter the following payload as test cases: `` `touch /tmp/pwned_test_case` `` (for Linux/macOS) or `` `echo pwned > C:\pwned_test_case.txt` `` (for Windows PowerShell). Alternatively, a simple cross-platform payload is ``test case`touch poc.txt` ``.
        - Press Enter to run the test.
        - After the test execution, check if a file named `pwned_test_case` or `poc.txt` (or `C:\pwned_test_case.txt`) has been created in the `/tmp/` directory (or workspace for `poc.txt`) of your system (or C: drive on Windows). If the file exists, command injection via test cases is confirmed.

    2. **File Path Injection (Submit Solution Feature):**
        - Create a new file named `"vuln.js & touch injected_file_path.txt"` (or `"vuln.js & calc.exe"` on Windows for a more visible impact).
        - Add some JavaScript code to the file (e.g., `console.log("test");`).
        - Open this file in VS Code.
        - Use the LeetCode extension to submit this file (e.g., click "Submit" code lens or use "LeetCode: Submit Solution" command).
        - Observe if a file named `injected_file_path.txt` is created in your workspace directory (or if calculator app `calc.exe` is launched on Windows). If so, command injection via file path is successful.

    **Important Note for Testing:** For security reasons, during testing, avoid commands that could potentially harm your system or network. Use simple commands like `touch` or `echo` for file creation or non-disruptive commands like `whoami` or `ipconfig` to verify command execution without causing damage. Always test in a safe, isolated environment.