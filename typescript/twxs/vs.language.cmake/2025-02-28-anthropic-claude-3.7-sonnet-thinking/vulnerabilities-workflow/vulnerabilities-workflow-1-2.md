# Vulnerabilities in VSCode CMake Extension

## Arbitrary Command Execution via Malicious `cmakePath` Configuration

- **Description:**  
  The extension reads the CMake executable path from the workspace configuration (`cmake.cmakePath`) without performing any validation or sanitization. An attacker can supply a manipulated repository (for example, via a malicious `.vscode/settings.json`) that sets the `cmake.cmakePath` value to a path or command of the attacker's choosing. When the victim opens this repository in Visual Studio Code and triggers an extension command (such as "CMake: Online Help"), the extension calls its internal `cmake()` function. This function splits the configured path into an executable and its arguments and then invokes it using Node's `child_process.spawn` API. Because the extension directly passes the attacker‑controlled executable path to `spawn`, the attacker can force the execution of arbitrary code under the privileges of the victim.

  **Step by step trigger:**
  1. The attacker prepares a malicious repository that includes a `.vscode/settings.json` file with a content like:
     ```json
     {
       "cmake.cmakePath": "node /path/to/malicious_script.js"
     }
     ```
     Here, `/path/to/malicious_script.js` is a script under the attacker's control that executes harmful actions.
  2. The attacker distributes this repository.
  3. The victim opens the repository in Visual Studio Code.
  4. The extension uses the workspace configuration via `workspace.getConfiguration('cmake')` to retrieve the `cmakePath` value.
  5. The `cmake()` function processes this value by calling `commandArgs2Array`, splitting it into an executable and its arguments.
  6. The extension then invokes `child_process.spawn` with the attacker‑provided executable.
  7. The malicious script is executed, resulting in arbitrary code execution.

- **Impact:**  
  Exploitation allows the attacker to run arbitrary code within the context of the victim's VSCode process. This could lead to system compromise, data theft, and further lateral movement in the victim's environment.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  - **None observed.**  
    The extension simply reads the configuration value and uses it in a child process call without any verification.

- **Missing Mitigations:**  
  - Validate and sanitize the `cmake.cmakePath` value before use—e.g., by verifying that it points to an expected executable (such as a known CMake binary) or by implementing a strict allowlist.
  - Consider sandboxing or restricting the rights of spawned processes.
  - Provide error handling/logging around the spawn call to detect unexpected executable behavior.

- **Preconditions:**  
  - The victim opens a repository that contains a malicious `.vscode/settings.json` file with an attacker‑controlled `cmake.cmakePath`.
  - The victim triggers any command (like "CMake: Online Help") that causes the extension to call the `cmake()` function.
  - The malicious executable is accessible (or the malicious command is valid) on the victim's system.

- **Source Code Analysis:**  
  - **Configuration Retrieval:**  
    In the helper function `config<T>(key: string, defaultValue?: any)`, the extension retrieves the executable path:
    ```typescript
    const cmake_conf = workspace.getConfiguration('cmake');
    return cmake_conf.get<T>(key, defaultValue);
    ```
    There is no check to ensure that the returned value is a trusted or valid executable path.
  
  - **Processing and Execution:**  
    In the `cmake` function:
    ```typescript
    let cmake_config = config<string>('cmakePath', 'cmake');
    let cmake_args = commandArgs2Array(cmake_config);
    let cmd = child_process.spawn(
        cmake_args[0],
        cmake_args.slice(1, cmake_args.length).concat(args.map(arg => { return arg.replace(/\r/gm, ''); }))
    );
    ```
    The function splits the attacker-controlled string into an array (using `commandArgs2Array`) and then passes the first element as the executable. No further sanitization is performed, so if the configuration was manipulated via a malicious repository, a harmful executable is invoked.
  
  - **Visualization of the Exploitation Chain:**
    - The malicious repository supplies a custom `.vscode/settings.json` with:
      ```
      "cmake.cmakePath": "node /path/to/malicious_script.js"
      ```
    - → When a command (e.g., "CMake: Online Help") fires, the extension calls `config('cmakePath')` and obtains the malicious value.
    - → The value is processed by `commandArgs2Array` into `[ "node", "/path/to/malicious_script.js" ]`.
    - → `child_process.spawn` is invoked with these parameters, executing the malicious script.
  
- **Security Test Case:**  
  1. **Setup the Test Repository:**
     - Create a test repository that includes a `.vscode/settings.json` file:
       ```json
       {
         "cmake.cmakePath": "node /absolute/path/to/test_malicious.js"
       }
       ```
  2. **Prepare the Malicious Script:**
     - Develop a simple script (`test_malicious.js`) that performs a benign but visible action (for example, creating a unique file or writing to a log) to simulate malicious activity:
       ```javascript
       const fs = require('fs');
       fs.writeFileSync('/tmp/extension_exploited.txt', 'Malicious script executed.');
       ```
     - Ensure that this script is accessible at the specified path.
  3. **Install the Vulnerable Extension:**
     - Open the test repository in Visual Studio Code with the vulnerable CMake extension installed.
  4. **Trigger the Vulnerability:**
     - Use the Command Palette (Ctrl+Shift+P or Cmd+Shift+P) to execute the "CMake: Online Help" command.
  5. **Observation and Verification:**
     - Confirm that the script `/tmp/extension_exploited.txt` is created and contains the expected content.
     - Verify that the undesired command (i.e., execution of `node /absolute/path/to/test_malicious.js`) took place.
  6. **Result:**
     - The test should demonstrate that the extension executes the attacker‑controlled command, confirming the vulnerability.