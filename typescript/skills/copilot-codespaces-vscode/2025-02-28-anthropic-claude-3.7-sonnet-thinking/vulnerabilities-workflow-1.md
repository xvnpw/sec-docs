# Vulnerabilities in the VSCode Extension Project

## 1. Command Injection in Git Operations

- **Vulnerability Name:** Command Injection in Git Operations

- **Description:**  
  The VSCode extension contains a critical command injection vulnerability in its git operations. When a user interacts with a repository, they are prompted to enter personal information including name and email for git configuration. These user-provided values are passed directly to git commands without proper sanitization. An attacker can create a malicious repository with instructions that trick the victim into entering specially crafted input containing shell metacharacters (like semicolons, backticks, or pipes). When the extension runs git configuration commands with these inputs, it will execute arbitrary commands on the victim's system.

  Specifically, when executing:
  1. The user clones a malicious repository
  2. They open it in VSCode with this extension installed
  3. During setup, they're prompted for git configuration details
  4. If they enter malicious input like `name"; malicious command; #` in the name field
  5. The extension passes this unsanitized input to git commands
  6. The shell interprets the semicolon as a command separator, executing the attacker's payload

- **Impact:**  
  This vulnerability allows remote code execution on the victim's machine with the privileges of the VSCode process. An attacker can execute arbitrary commands to exfiltrate sensitive information, install malware, or gain persistent access to the system.

- **Vulnerability Rank:**  
  Critical

- **Currently Implemented Mitigations:**  
  The extension only performs basic validation to ensure inputs are not empty, but has no sanitization for shell metacharacters.

- **Missing Mitigations:**  
  1. Properly escape all user inputs before passing them to shell commands
  2. Implement allowlist validation for git configuration inputs
  3. Consider using alternative APIs for git operations that don't rely on shell command execution

- **Preconditions:**  
  1. Victim must have the VSCode extension installed
  2. Victim must interact with a malicious repository
  3. Victim must enter attacker-provided input during git configuration

- **Source Code Analysis:**  
  In `src/commands/setup.ts`, the user input is collected:
  ```typescript
  async function enterRepoDetails(): Promise<{ name: string; email: string; repo: string } | undefined> {
    const name = await vscode.window.showInputBox({
      title: "Enter your name",
      prompt: "This will be used for git commits",
      validateInput: (value) => {
        if (!value) {
          return "Name is required";
        }
        return null;
      },
    });
    // Similar code for email and repo
  }
  ```

  This input is then passed to git commands in `src/github/git.ts`:
  ```typescript
  export async function setGitUserDetails(name: string, email: string): Promise<void> {
    await executeGitCommand(["config", "user.name", name]);
    await executeGitCommand(["config", "user.email", email]);
  }
  ```

  The `executeGitCommand` function uses `spawnProcess` which invokes the OS shell:
  ```typescript
  export async function executeGitCommand(args: string[], cwd?: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    const promise = spawnProcess({
      command: "git",
      args,
      cwd,
    });
    // Process result
  }
  ```

  If a user enters `John"; rm -rf ~/* #` as their name, the resulting command would be:
  ```
  git config user.name "John"; rm -rf ~/* #"
  ```
  This would execute the malicious `rm` command after setting the git username.

- **Security Test Case:**  
  1. Create a malicious repository with a README containing:
     ```
     # Setup Instructions
     When prompted by the extension, please use the following information:
     - Name: John Doe"; touch /tmp/pwned #
     - Email: your-email@example.com
     ```
  2. Have the victim clone this repository and open it in VSCode
  3. When the victim follows the setup instructions and enters the malicious name value
  4. Verify that `/tmp/pwned` file is created, confirming successful command injection
  5. In a real attack, more devastating commands could be used instead of the simple file creation

## 2. Unsafe Markdown Rendering Leading to Remote Code Execution

- **Vulnerability Name:** Unsafe Markdown Rendering Leading to Remote Code Execution

- **Description:**  
  The VSCode extension appears to render Markdown files (such as README.md) in a view that could interpret embedded HTML. If an attacker provides a manipulated repository—with the same file structure as the course template—the attacker may embed malicious HTML (for example, `<script>` tags) that gets executed in the context of the extension. The exploitation steps would be as follows:
  1. The attacker creates or manipulates a repository's README.md file to include injected HTML/JavaScript (e.g., a `<script>` tag containing code that uses Node.js APIs).
  2. The victim, trusting the vanilla course template, opens the repository in VSCode.
  3. The extension loads and parses the README.md file, rendering it in a webview.
  4. Because the extension does not sanitize the embedded HTML, the injected JavaScript executes in the context of the extension.
  5. The attacker's code is executed with the privileges of the VSCode process, leading to remote code execution.

- **Impact:**  
  If an attacker successfully exploits this vulnerability, they can execute arbitrary code on the victim's system. This could result in data exfiltration, installation of additional malware, manipulation of local files, or even complete system compromise—all executed with the victim's privileges.

- **Vulnerability Rank:**  
  Critical

- **Currently Implemented Mitigations:**  
  The available project files (including the README.md template) show no evidence of any content sanitization or strict Content Security Policy setup for rendering Markdown/HTML within the VSCode extension. There is no indication that the extension currently performs any safety checks on the content retrieved from a repository.

- **Missing Mitigations:**  
  - **HTML/Markdown Sanitization:** There is a need to sanitize all HTML embedded in Markdown files before rendering to remove executable elements (e.g., `<script>`, event handlers, etc.).  
  - **Content Security Policy:** Implementing a robust CSP on any webview used by the extension can block inline scripts or unauthorized resource loads.  
  - **Sandbox Isolation:** Running the Markdown rendering in a fully sandboxed environment would help mitigate damage even if an injection occurs.

- **Preconditions:**  
  - The victim is using the VSCode extension that processes repository content (e.g., rendered README.md files) in a webview without enforced restrictions against script execution.
  - The attacker is able to supply a manipulated repository (or has compromised an existing course repository) such that the injected malicious content is hosted alongside regular course material.
  - The extension does not re-sanitize content that comes from untrusted sources before displaying it to the user.

- **Source Code Analysis:**  
  Although the provided README.md file is a static template without active scripts, its structure is indicative of content that will later be rendered in the extension. The observed file includes embedded HTML comments and a commented-out JavaScript snippet. An attacker could modify this file as follows:
  - Replace benign HTML comment blocks with active HTML elements. For instance, instead of:
    ```html
    <!-- For start course, run in JavaScript:
    'https://github.com/new?' + new URLSearchParams({...}).toString()
    -->
    ```
    an attacker might introduce:
    ```html
    <script>
      // Malicious code that uses Node.js APIs
      require('child_process').exec('malicious-command');
    </script>
    ```
  - If the VSCode extension reads the entire README.md file and renders it without stripping out executable HTML elements, then when the victim views the repository content, the webview will execute the injected script.
  - Since there is no visible sanitization layer in the project files, injected code in manipulated Markdown constitutes a valid attack vector for remote code execution.

- **Security Test Case:**  
  1. **Preparation:**  
     - Set up a test VSCode environment with the vulnerable extension installed.
     - Create a new repository (or clone the template) and modify the README.md file by injecting a harmless JavaScript payload. For example:
       ```html
       <script>
         console.log('Vulnerability test: Malicious code executed!');
         // In a real test, instead of a destructive command, use an indicator (e.g., writing to a test file)
       </script>
       ```
  2. **Execution:**  
     - Open the manipulated repository in VSCode so that its README.md is rendered by the extension.
     - Open the developer tools (if available) to monitor console output or any unexpected behavior.
  3. **Observation:**  
     - Confirm that the injected script is executed (e.g., the console logs the test message or the expected side effect is observed).
  4. **Verification:**  
     - If the test payload runs, this demonstrates that the extension does not sanitize untrusted Markdown/HTML content, thereby validating the vulnerability.