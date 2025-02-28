# Vulnerabilities in Live Server VS Code Extension

## 1. Command Injection via Custom Browser Setting

### Description
A remote code execution vulnerability exists in the Live Server extension's custom browser command line feature. When a user opens a repository and activates the Live Server extension (by clicking "Go Live"), the extension executes the browser command specified in the settings. An attacker can create a malicious repository with a custom `.vscode/settings.json` file containing a crafted `liveServer.settings.AdvanceCustomBrowserCmdLine` value that includes shell command operators, which will be executed on the victim's system.

Step by step how to trigger:
1. Attacker creates a repository with a `.vscode/settings.json` file containing malicious command injection
2. Victim clones or downloads the repository and opens it in VSCode
3. When victim clicks "Go Live" in the status bar, the extension reads the custom browser setting
4. The extension processes this setting in the `openBrowser` method in `appModel.ts`
5. The malicious command is executed alongside the legitimate browser command

### Impact
The impact is critical as it allows arbitrary command execution on the victim's system with the same privileges as the VSCode process. An attacker can execute any command including data exfiltration, malware installation, or persistent access to the victim's system.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension does attempt to parse the custom browser command line by splitting it on `--` tokens and processing each part separately:

```typescript
// in appModel.ts, openBrowser method
advanceCustomBrowserCmd
    .split('--')
    .forEach((command, index) => {
        if (command) {
            if (index !== 0) command = '--' + command;
            params.push(command.trim());
        }
    });
```

However, this does not prevent command injection if shell operators are used in the first segment of the command.

### Missing Mitigations
The extension should:
1. Validate and sanitize the custom browser command string
2. Use a whitelist approach for allowed browsers and parameters
3. Implement proper shell escaping for all user-provided input
4. Consider using an API that doesn't invoke shell execution

### Preconditions
- Victim must have the Live Server extension installed
- Victim must open a repository containing malicious settings
- Victim must activate the Live Server extension by clicking "Go Live"

### Source Code Analysis
The vulnerability is in the `openBrowser` method in `appModel.ts`:

```typescript
private openBrowser(port: number, path: string) {
    // ...
    let params: string[] = [];
    let advanceCustomBrowserCmd = Config.getAdvancedBrowserCmdline;
    if (advanceCustomBrowserCmd) {
        advanceCustomBrowserCmd
            .split('--')
            .forEach((command, index) => {
                if (command) {
                    if (index !== 0) command = '--' + command;
                    params.push(command.trim());
                }
            });
    }
    // ...
    try {
        require('opn')(`${protocol}://${host}:${port}/${path}`, { app: params || [''] });
    } catch (error) {
        // Error handling
    }
}
```

When a user configures `liveServer.settings.AdvanceCustomBrowserCmdLine` with a value like `chrome & calc.exe`, the first segment "chrome & calc.exe" becomes the first element in the `params` array. The `opn` package then uses this to spawn a process, which can lead to command injection if the string contains shell operators like `&`, `|`, or `;`.

The Config class in `Config.ts` retrieves this setting directly from VSCode workspace configuration without any validation:

```typescript
public static get getAdvancedBrowserCmdline(): string {
    return Config.getSettings<string>('AdvanceCustomBrowserCmdLine');
}
```

### Security Test Case
To prove the vulnerability:

1. Create a new directory for a test project
2. Create a `.vscode` folder inside it
3. Create a `settings.json` file inside the `.vscode` folder with the following content:
   ```json
   {
       "liveServer.settings.AdvanceCustomBrowserCmdLine": "chrome & calc.exe"
   }
   ```
4. Create a simple `index.html` file in the project root
5. Open the project in VSCode
6. Click the "Go Live" button in the status bar
7. Observe that both Chrome and Calculator application are launched, proving command execution