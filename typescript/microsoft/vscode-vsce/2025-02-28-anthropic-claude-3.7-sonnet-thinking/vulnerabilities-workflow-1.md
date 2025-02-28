# Vulnerabilities

## Remote Code Execution via vscode:prepublish Script

### Description
The VS Code Extension Manager (`@vscode/vsce`) executes the `vscode:prepublish` script from the extension's `package.json` file when packaging or publishing an extension. This script is executed with `shell: true`, which means it can run arbitrary shell commands on the user's system.

A threat actor could create a malicious repository with a harmful `vscode:prepublish` script, and if they convince a victim to package or publish this extension, the malicious script will be executed on the victim's machine with the privileges of the victim.

Step by step exploitation:
1. Create a malicious repository with a `package.json` file containing a dangerous `vscode:prepublish` script
2. Share the repository with a victim (e.g., via a GitHub repository)
3. When the victim runs `vsce package` or `vsce publish` on this repository
4. The tool executes the malicious script defined in `vscode:prepublish`

### Impact
This vulnerability allows for arbitrary code execution on the user's machine with the permissions of the user running the tool. An attacker can:
- Access sensitive information
- Establish persistence on the system
- Execute further malicious commands
- Compromise the development environment

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
There are no mitigations in place. The code directly executes the script from the `package.json` file without any validation, sandboxing, or warning to the user.

### Missing Mitigations
1. Warn users about executing scripts from untrusted sources
2. Provide an option to skip script execution (e.g., `--no-scripts` flag)
3. Sandbox script execution or use a more restricted environment
4. Validate and sanitize the script content before execution

### Preconditions
1. Victim must use the `vsce` tool on a repository controlled by the attacker
2. The repository must contain a `package.json` file with a malicious `vscode:prepublish` script

### Source Code Analysis
In the `package.test.ts` file, we can see that the `prepublish` function is tested:

```typescript
export async function prepublish(cwd: string, manifest: ManifestPackage, useYarn?: boolean): Promise<void> {
    if (!manifest.scripts || !manifest.scripts['vscode:prepublish']) {
        return;
    }

    if (useYarn === undefined) {
        useYarn = await detectYarn(cwd);
    }

    console.log(`Executing prepublish script '${useYarn ? 'yarn' : 'npm'} run vscode:prepublish'...`);

    await new Promise<void>((c, e) => {
        const tool = useYarn ? 'yarn' : 'npm';
        const child = cp.spawn(tool, ['run', 'vscode:prepublish'], { cwd, shell: true, stdio: 'inherit' });
        child.on('exit', code => (code === 0 ? c() : e(`${tool} failed with exit code ${code}`)));
        child.on('error', e);
    });
}
```

This function is called in the packaging process, as shown in the `packageCommand` function test:

```typescript
export async function packageCommand(options: IPackageOptions = {}): Promise<any> {
    const cwd = options.cwd || process.cwd();
    const manifest = await readManifest(cwd);
    util.patchOptionsWithManifest(options, manifest);

    await prepublish(cwd, manifest, options.useYarn);
    await versionBump(options);
    // ...
}
```

The vulnerability exists because:
1. The code reads the `package.json` file from the repository
2. It executes the `vscode:prepublish` script with `shell: true`
3. There is no validation or sandboxing of this script

### Security Test Case
To verify this vulnerability:

1. Create a test repository with the following `package.json`:
```json
{
  "name": "malicious-extension",
  "version": "1.0.0",
  "engines": {
    "vscode": "^1.74.0"
  },
  "scripts": {
    "vscode:prepublish": "echo 'Code execution successful' > /tmp/vsce-vulnerability-test.txt"
  }
}
```

2. Clone the repository and run:
```bash
vsce package
```

3. Verify that the file `/tmp/vsce-vulnerability-test.txt` has been created, confirming successful code execution.

## Command Injection via Commit Message on Non-Windows Platforms

### Description
On non-Windows platforms, the `versionBump` function in `package.ts` passes the user-provided commit message directly to the command line without proper sanitization when executing the `npm version` command. This can allow an attacker to inject malicious commands.

Step by step exploitation:
1. Create a repository with a `package.json` that includes a malicious commit message in the `vsce` property
2. Share the repository with a victim
3. When the victim runs `vsce package <version>` on a non-Windows platform
4. The malicious commit message is passed to the command line, executing arbitrary commands

### Impact
This vulnerability allows for command injection, leading to arbitrary code execution on the victim's machine.

### Vulnerability Rank
High

### Currently Implemented Mitigations
On Windows platforms, the `sanitizeCommitMessage` function is used to remove dangerous characters from the commit message. However, this sanitization is not applied on non-Windows platforms.

### Missing Mitigations
The `sanitizeCommitMessage` function should be used on all platforms, not just Windows.

### Preconditions
1. The victim must use the `vsce` tool on a non-Windows platform
2. The victim must specify a version parameter or the package must have a commit message configured
3. The attacker must control the commit message through the `package.json` configuration

### Source Code Analysis
In `package.test.ts`, the `versionBump` function test shows:

```typescript
export async function versionBump(options: IVersionBumpOptions): Promise<void> {
    // ...
    const args = ['version', options.version];
    const isWindows = process.platform === 'win32';
    
    const commitMessage = isWindows ? sanitizeCommitMessage(options.commitMessage) : options.commitMessage;
    if (commitMessage) {
        args.push('-m', commitMessage);
    }
    // ...
    const { stdout, stderr } = await promisify(cp.execFile)(isWindows ? 'npm.cmd' : 'npm', args, { cwd, shell: isWindows });
    // ...
}
```

The vulnerability exists because:
1. On non-Windows platforms, the `commitMessage` is used without sanitization
2. This unsanitized message is passed to the `npm version` command via the `-m` flag
3. If an attacker controls this message, they can inject commands

### Security Test Case
To verify this vulnerability:

1. Create a test repository with the following `package.json`:
```json
{
  "name": "malicious-extension",
  "version": "1.0.0",
  "engines": {
    "vscode": "^1.74.0"
  },
  "vsce": {
    "commitMessage": "'; touch /tmp/vsce-commit-injection.txt; echo '"
  }
}
```

2. On a non-Windows platform, clone the repository and run:
```bash
vsce package patch
```

3. Verify that the file `/tmp/vsce-commit-injection.txt` has been created, confirming successful command injection.