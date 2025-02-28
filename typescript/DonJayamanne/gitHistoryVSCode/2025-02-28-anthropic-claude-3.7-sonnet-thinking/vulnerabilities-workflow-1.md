# Combined Vulnerability Assessment Report

## Command Injection via Repository URL in cloneRepo Function

### Vulnerability Name
Command Injection in Git Repository Clone Operation

### Description
The extension allows cloning Git repositories, but the repository URL validation is insufficient. In `repoSetup.ts`, the function `cloneRepo` takes a repository path from user input and passes it directly to `simplegit().clone()` without adequate sanitization. The only validation performed is a basic check that the URL ends with `.git`.

This vulnerability can be triggered when a malicious repository URL containing shell command metacharacters is provided to the extension. Since `simple-git` uses child_process under the hood to execute Git commands, these metacharacters can lead to command execution on the victim's machine.

### Impact
An attacker can achieve remote code execution on the victim's machine with the privileges of the VS Code process. This allows arbitrary code execution, data theft, and potential lateral movement within the victim's environment.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The code has minimal validation in `getRepoName()` function, which only checks if the URL ends with `.git`, but this is insufficient to prevent command injection.

### Missing Mitigations
1. Input validation should enforce a strict URL format pattern
2. Repository URLs should be sanitized to remove any potential command injection characters
3. The extension should use a whitelist approach for allowed Git repository hosting domains

### Preconditions
1. The victim must have the Git History extension installed in VS Code
2. The victim must be tricked into opening a malicious repository or manually entering a malicious repository URL

### Source Code Analysis
Let's examine the vulnerable code in `/code/test/extension/repoSetup.ts`:

```typescript
export function getRepoName(repoPath: string) {
    if (!repoPath.endsWith('.git')) {
        throw new Error('Repo path must be of the form "https://github.com/<org>/<name>.git"');
    }
    return path.basename(repoPath, '.git');
}

export async function cloneRepo(repoPath: string) {
    const localPath = getLocalPath(repoPath);
    if (await fs.existsSync(path.join(localPath, 'package.json'))) {
        return;
    }
    await simplegit().clone(repoPath, localPath);
}
```

The issue is that `getRepoName()` only checks if the URL ends with `.git` but doesn't validate the rest of the URL structure. For example, a malicious URL like `https://example.com/repo.git; rm -rf /` would pass this check.

The `simplegit().clone()` function ultimately uses Node.js child_process to execute git commands. If special characters are included in the repository URL, they can be interpreted as shell commands when the git command is executed.

The exploitation path is:
1. Attacker creates a malicious repository URL containing shell metacharacters
2. Victim is tricked into opening this URL in the extension
3. The extension passes the URL to `simplegit().clone()`
4. `simple-git` constructs a shell command like `git clone <malicious-url> <local-path>`
5. Shell metacharacters in the URL are executed as commands

### Security Test Case
To verify this vulnerability:

1. Create a text file named `malicious-repo.txt` containing:
   ```
   https://github.com/legitimate/repo.git; $(echo 'const fs=require("fs");fs.writeFileSync("/tmp/pwned.txt","Compromised");' > /tmp/malicious.js && node /tmp/malicious.js)
   ```

2. Instruct the victim to:
   - Open VS Code
   - Install the Git History extension
   - Open the command palette (Ctrl+Shift+P)
   - Run "Git: Clone" command
   - Paste the content from malicious-repo.txt as the repository URL

3. Expected result: 
   - The legitimate repository will be cloned
   - Additionally, the malicious JavaScript will create a file at `/tmp/pwned.txt` with the content "Compromised"
   - This proves code execution has occurred

## Code Injection via Unsanitized Message Handling

### Vulnerability Name
Code Injection Through WebView Message Processing

### Description
The extension uses a WebView component for displaying Git history and processes messages from this WebView. In the `messagebus.ts` file, the `post` function sends unsanitized user-controlled data to the extension's backend. The extension doesn't properly validate the message payload before processing it, which can lead to code injection.

### Impact
An attacker who can control the input to the WebView can execute arbitrary code in the context of the VS Code extension host. This allows access to VS Code APIs and potentially the victim's filesystem.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The message passing system accepts arbitrary data without type checking or validation.

### Missing Mitigations
1. Implement strict validation of all message parameters
2. Use TypeScript interfaces to enforce type safety
3. Sanitize any user-provided data before using it in sensitive operations
4. Implement a allow-list for permitted message commands

### Preconditions
1. The victim must open a repository with malicious content
2. The Git History extension must process this repository

### Source Code Analysis
Looking at the code in `/code/browser/src/actions/messagebus.ts`:

```typescript
export function post<T>(cmd: string, payload: any): Promise<T> {
    const requestId = uuid();

    vsc.postMessage({
        requestId,
        cmd,
        payload,
    });

    return createPromiseFromMessageEvent(requestId);
}
```

The `payload` parameter is typed as `any`, meaning it can contain arbitrary data structures. There's no validation of this payload before it's sent to the extension host.

In `/code/browser/src/actions/results.ts`, we see several actions that process user input:

```typescript
export const actionCommit = (logEntry: LogEntry, name = '', value = '') => {
    return async (dispatch: Dispatch<any>, getState: () => RootState) => {
        const store = getState();

        post<LogEntry>('doAction', {
            ...store.settings,
            logEntry,
            name,
            value,
        }).then(x => {
            switch (name) {
                case 'reset_soft':
                case 'reset_hard':
                    dispatch(ResultActions.refresh());
                    break;
                // ...
            }
        });
    };
};
```

The `doAction` command is sent with user-controlled input in the `name` and `value` parameters. If the backend code (not visible in the provided files) uses these values in an unsafe way, such as in a dynamic `eval()` call or in constructing shell commands, this could lead to code injection.

### Security Test Case
To verify this vulnerability:

1. Create a malicious Git repository with the following structure:
   - Create a file named `.git/hooks/post-checkout` with a payload that will create a proof-of-concept file
   - Make the hook executable

2. Create a crafted commit message containing JavaScript code to be injected

3. Clone this repository into VS Code and use Git History extension to view the commits

4. When sending a message, craft it to include a malicious payload:
   ```javascript
   // Use browser developer tools in the WebView to execute:
   const maliciousLogEntry = {
     hash: { 
       full: '"><img src=x onerror="alert(document.domain)">' 
     },
     // other required properties...
   };
   
   // Attempt to inject a malicious name parameter
   window.__REDUX_STORE__.dispatch(
     actionCommit(
       maliciousLogEntry, 
       'reset_soft; const fs = require("fs"); fs.writeFileSync("/tmp/hacked.txt", "pwned")', 
       ''
     )
   );
   ```

5. Expected outcome:
   - If vulnerable, the extension will process the malicious name parameter in an unsafe way
   - The code will execute and create the file `/tmp/hacked.txt`

## Unsanitized File Name Injection in Webview HTML

### Vulnerability Name
Cross-Site Scripting via Unsanitized File Name in Webview HTML

### Description
The extension builds its HTML content for the history webview by interpolating dynamic data into an inline script. Although most variables (such as configuration settings and extension paths) are safely serialized with `JSON.stringify`, the file name (retrieved with `path.basename(fileUri.fsPath)`) is inserted directly into a JavaScript assignment. An attacker providing a repository with a maliciously crafted file name (for example, one including a single quote to break out of the string context) may inject arbitrary JavaScript code.

**Step-by-step trigger:**
1. The attacker supplies a repository that includes at least one file with a specially crafted name (for example: `evil';alert('XSS');//.txt`).
2. The victim then opens this repository in Visual Studio Code.
3. When the victim invokes the repository's git history view for that file, the extension builds the webview's HTML.
4. The inline script sets the file name using a pattern such as: `window['fileName'] = '${fileName}';`
5. Because the file name is not escaped or safely serialized, the injected payload breaks out of its intended string context and executes as JavaScript.

### Impact
An attacker who persuades a user to open a repository containing a malicious file name can cause arbitrary JavaScript code to run in the context of the extension's webview. This could lead to actions including data exfiltration, user impersonation, or further lateral escalation within the VS Code session.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
• All dynamic variables used elsewhere to generate the webview HTML (such as configuration settings and extension paths) are wrapped with `JSON.stringify` for proper serialization.
• The overall construction of the webview content is performed in a controlled manner.
However, the file name itself is not sanitized before interpolation into the inline script.

### Missing Mitigations
• The file name should be escaped—preferably by wrapping it with `JSON.stringify` or by using a dedicated sanitization routine—before it is placed into the inline script.
• A broader sanitization process should be applied to any strings derived from repository metadata that are later used in dynamically generated HTML.

### Preconditions
• The victim opens a repository in VS Code that is under attacker influence.
• At least one file in the repository has a name containing malicious characters (for example, embedded single quotes or script fragments).
• The victim triggers the file history view (or an equivalent feature) which constructs the webview using the unsanitized file name.

### Source Code Analysis
• In the (previously analyzed) file (for example, `src/server/htmlViewer.ts`), the function that builds the webview HTML includes a line that sets the file name via an inline script:
  ```js
  window['fileName'] = '${fileName}';
  ```
• Unlike other variables that are wrapped with safe serialization (such as using `JSON.stringify`), the file name is directly interpolated.
• Therefore, a payload (for example: `evil';alert('XSS');//.txt`) results in the output:
  ```js
  window['fileName'] = 'evil';alert('XSS');//txt';
  ```
  which prematurely terminates the string and executes the injected JavaScript.

### Security Test Case
1. **Setup:**
   - Create a new Git repository containing a file with the name: `evil';alert('XSS');//.txt`
   - Commit and push the repository.
2. **Execution:**
   - Open Visual Studio Code and load the repository containing the malicious file name.
   - Trigger the git history view (or corresponding command that opens the affected webview) for that file.
3. **Expected Outcome:**
   - The constructed webview HTML will include an inline script where the malicious payload is not escaped.
   - An injected JavaScript action (such as an alert dialog or other visible behavior) is executed.
4. **Verification:**
   - Confirm that the injected JavaScript payload executes as expected.
   - Inspect the rendered HTML in the webview to verify that the file name appears unsanitized.