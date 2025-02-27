### Vulnerability List:

- Vulnerability Name: Command Injection via Filename in `testSolution` and `submitSolution`
  - Description:
    1. An attacker can create a file with a malicious filename.
    2. When the user attempts to test or submit this file using the LeetCode extension, the filename is passed unsanitized to the `leetcode test` or `leetcode submit` command in `leetCodeExecutor.ts`.
    3. If the filename contains shell-escaped characters or commands, these could be executed by the underlying shell when the extension executes the LeetCode CLI.
    4. For example, a filename like `pwn$(touch /tmp/pwned).js` could execute the `touch /tmp/pwned` command on a Linux/macOS system during test or submission.
  - Impact: Arbitrary command execution on the user's machine with the privileges of the VSCode process. This can lead to data exfiltration, malware installation, or system compromise.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations: None. The filename is directly passed to the shell command.
  - Missing Mitigations:
    - Sanitize or validate filenames before passing them to shell commands.
    - Use parameterized commands or direct function calls instead of shell execution where possible.
    - Quote or escape filenames properly when constructing shell commands to prevent shell injection.
  - Preconditions:
    - Attacker needs to trick the user into creating or downloading a file with a malicious filename within their workspace.
    - User must attempt to test or submit this file using the LeetCode extension.
  - Source Code Analysis:
    - File: `/code/src/leetCodeExecutor.ts`
    - Function: `submitSolution(filePath: string)` and `testSolution(filePath: string, testString?: string)`
    - Lines:
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
      ```
    - Visualization:
      ```
      User -> Filename Input (Malicious) -> submitSolution/testSolution -> executeCommandWithProgressEx -> cp.spawn (Unsanitized Filename) -> Shell Command Execution
      ```
    - The `filePath` variable, derived from user workspace, is directly embedded within double quotes in the command arguments passed to `executeCommandWithProgressEx`.
    - The `executeCommandWithProgressEx` function, and subsequently `executeCommandEx` and `executeCommand`, uses `cp.spawn` with `shell: true`. This setting allows shell command injection if the arguments are not properly sanitized.
    - The double quotes around `filePath` are insufficient to prevent command injection in all shell environments and scenarios, especially when filenames contain backticks, dollar signs, or other shell metacharacters.

  - Security Test Case:
    1. Create a new file in VSCode named `pwn$(touch /tmp/pwned).js`.
    2. Add any valid Javascript code to the file (e.g., `console.log("hello");`).
    3. In VSCode, use the LeetCode extension command "LeetCode: Test Current File" or "LeetCode: Submit Current File" when the malicious file `pwn$(touch /tmp/pwned).js` is active.
    4. Observe if the file `/tmp/pwned` is created on the system. If it is, then command injection is successful.
    5. To verify on Windows, create a file named `pwn&echo pwned > pwned.txt.js` and check if `pwned.txt` is created in the workspace directory after testing or submitting.

- Vulnerability Name: Command Injection via Test String in `testSolution`
  - Description:
    1. An attacker can provide a malicious test string when using the "LeetCode: Test Current File" command and choosing the "Write directly..." option.
    2. This test string is passed unsanitized to the `leetcode test` command in `leetCodeExecutor.ts`.
    3. Similar to the filename vulnerability, if the test string contains shell-escaped characters or commands, they could be executed by the underlying shell.
    4. For example, a test string like `; touch /tmp/pwned2` could execute the `touch /tmp/pwned2` command.
  - Impact: Arbitrary command execution on the user's machine, same as the filename vulnerability.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations: None. The test string is passed to the shell command with minimal quoting.
  - Missing Mitigations:
    - Sanitize or validate the test string input.
    - Use parameterized commands or direct function calls.
    - Properly escape or quote the test string when constructing the shell command.
  - Preconditions:
    - User must choose the "Write directly..." option when testing a solution.
    - User must enter a malicious test string containing shell commands.
  - Source Code Analysis:
    - File: `/code/src/leetCodeExecutor.ts`
    - Function: `testSolution(filePath: string, testString?: string)`
    - Lines:
      ```typescript
      public async testSolution(filePath: string, testString?: string): Promise<string> {
          if (testString) {
              return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`, "-t", `${testString}`]);
          }
          return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`]);
      }
      ```
    - Visualization:
      ```
      User -> Test String Input (Malicious) -> testSolution -> executeCommandWithProgressEx -> cp.spawn (Unsanitized Test String) -> Shell Command Execution
      ```
    - The `testString` variable, directly derived from user input, is embedded within backticks (in `src/commands/test.ts`) and then string interpolated using `${testString}` in `leetCodeExecutor.ts`.
    - The quoting and escaping applied in `src/commands/test.ts` (using single or double quotes based on OS and shell) and in `leetCodeExecutor.ts` are likely insufficient to prevent injection in all cases.

  - Security Test Case:
    1. Open any LeetCode problem file in VSCode.
    2. Use the LeetCode extension command "LeetCode: Test Current File".
    3. Choose the "Write directly..." option.
    4. Enter the following test case: `; touch /tmp/pwned2`
    5. Click "Enter" or submit the input.
    6. Observe if the file `/tmp/pwned2` is created on the system. If it is, command injection is successful.
    7. To verify on Windows, try inputting `; echo pwned2 > pwned2.txt` as the test case and check for `pwned2.txt`.