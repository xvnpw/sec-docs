* Vulnerability 1: Command Injection via File Path in Submit and Test Commands

- Vulnerability Name: Command Injection via File Path in Submit and Test Commands
- Description:
    1. An attacker can create a file with a malicious file name. For example, a file name could be crafted like:  `; touch malicious_file.txt`.
    2. The attacker opens this file in VSCode and uses the LeetCode extension's "Submit" or "Test" command.
    3. The extension executes a command in the shell that includes the file path. Due to insufficient sanitization of the file path, the attacker's injected commands within the file name are executed by the shell.
- Impact: Arbitrary command execution on the user's machine with the privileges of the VSCode process. This can lead to data exfiltration, installation of malware, or other malicious activities.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The code directly passes the file path to the shell without sanitization.
- Missing Mitigations:
    - Sanitize the file path before passing it to the shell command. Use parameterized commands or shell-escape mechanisms to prevent command injection.
    - Avoid using shell execution for operations that can be performed programmatically.
- Preconditions:
    - The attacker needs to trick a user into creating or using a file with a maliciously crafted name within a workspace opened in VSCode with the LeetCode extension installed.
    - The user must then trigger the "Submit" or "Test" command from the LeetCode extension while having the malicious file active.
- Source Code Analysis:
    - File: `/code/src/leetCodeExecutor.ts`
    - Functions: `submitSolution(filePath: string)`, `testSolution(filePath: string, testString?: string)`
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

    private async executeCommandWithProgressEx(message: string, command: string, args: string[], options: cp.SpawnOptions = { shell: true }): Promise<string> {
        if (wsl.useWsl()) {
            return await executeCommandWithProgress(message, "wsl", [command].concat(args), options);
        }
        return await executeCommandWithProgress(message, command, args, options);
    }
    ```
    - The `filePath` variable, which is derived from user-controlled file names, is directly embedded within the command string passed to `executeCommandWithProgressEx`.
    - The backticks `` ` ` `` used for command construction in `submitSolution` and `testSolution` indicate shell execution.
    - No sanitization or escaping is performed on `filePath` before shell execution.

- Security Test Case:
    1. Create a new file in VSCode using the "New File" command.
    2. Name the file with a malicious payload. For example: `test_problem_solution_` + "; touch /tmp/pwned.txt".cpp
    3. Save the file in a workspace opened in VSCode.
    4. Open the malicious file in the editor.
    5. Trigger the "LeetCode: Submit Solution" command (or "LeetCode: Test Solution").
    6. Observe that a file named `pwned.txt` is created in the `/tmp/` directory of your system (or equivalent location based on OS), indicating successful command injection.
    7. For Windows, the payload could be `; New-Item -ItemType file -Path C:\pwned_win.txt` and the file name `test_problem_solution_; New-Item -ItemType file -Path C:\pwned_win.txt.cpp`.