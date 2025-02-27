- **Vulnerability Name:** Arbitrary Command Execution via Malicious Workspace Configuration

  - **Description:**
    - The extension reads the CMake executable path from the user/ workspace configuration (using the key `cmake.cmakePath`) without any validation or sanitization.
    - An attacker who is able to supply or modify a workspace settings file (for example, via an unsuspecting developer opening a project repository that carries a malicious `.vscode/settings.json`) can control this configuration value.
    - When the extension later calls functions that invoke the CMake command (for example, to get the CMake version or to open online help), it uses the configuration value directly to spawn a process via Node’s `child_process.spawn()`.
    - If the attacker sets `cmake.cmakePath` to an executable or even to a command line that launches a shell with custom parameters, the extension will execute that command. This effectively leads to arbitrary command execution on the end user’s machine.

  - **Impact:**
    - A malicious workspace configuration can result in arbitrary command execution with the privileges of the user running Visual Studio Code.
    - The attacker can execute commands of their choice (for example, dropping files, exfiltrating data, or compromising the entire system) if the developer accepts the workspace’s configuration without verifying its origin.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - The project uses Node’s `child_process.spawn()` with an argument array (which avoids classic shell interpolation), yet it does not validate or sanitize the configuration value for `cmake.cmakePath`.
    - There is no whitelist or strict check to ensure that the provided path is a legitimate CMake executable.

  - **Missing Mitigations:**
    - Input validation and sanitation should be added for the value of `cmake.cmakePath` so that it only accepts known safe paths (or at minimum, checks that the binary path exists and is not a shell).
    - The extension should consider enforcing workspace trust policies or at least warn users when a workspace configuration supplies a nonstandard executable path.
    - Hardening the spawn call by explicitly setting options (for example, ensuring that no shell is used by setting `shell: false` explicitly) would further reduce risk if combined with path validation.

  - **Preconditions:**
    - The end user opens a workspace that includes a malicious or attacker-controlled `.vscode/settings.json` setting the key `cmake.cmakePath` to an arbitrary command (for example, `/bin/sh -c 'malicious-command'`).
    - The extension is then triggered (for example by executing “CMake: Online Help” or any other command that invokes the `cmake` function) so that the attacker’s configured value is used in a call to `child_process.spawn`.

  - **Source Code Analysis:**
    - **Step 1:** In the helper function
      ```ts
      function config<T>(key: string, defaultValue?: any): T {
          const cmake_conf = workspace.getConfiguration('cmake');
          return cmake_conf.get<T>(key, defaultValue);
      }
      ```
      the extension retrieves the CMake-related configuration. There is no check to verify that the resulting value is a valid path.
    - **Step 2:** In the `cmake` function, the code does the following:
      ```ts
      let cmake_config = config<string>('cmakePath', 'cmake');
      let cmake_args = commandArgs2Array(cmake_config);
      let cmd = child_process.spawn(cmake_args[0],
          cmake_args.slice(1).concat(args.map(arg => { return arg.replace(/\r/gm, ''); })));
      ```
      Here, the configuration string is split into an array of arguments by `commandArgs2Array`. The first element is then used as the executable, and any remaining parts (plus additional arguments) are passed as parameters.
    - **Step 3:** Because the configuration value is entirely under the control of the workspace (and in turn potentially by an external attacker supplying a malicious repository), an attacker can set this value to launch any executable. For example, if `cmake.cmakePath` is set to a string that starts a shell with the `-c` flag, a malicious command passed by the attacker will be executed.

  - **Security Test Case:**
    - **Step 1:** Prepare a test workspace that includes a `.vscode/settings.json` file with the following (malicious) configuration:
      ```json
      {
          "cmake.cmakePath": "/bin/sh -c 'echo HACKED; touch /tmp/hacked'"
      }
      ```
    - **Step 2:** Open the test workspace in Visual Studio Code with the vulnerable extension enabled.
    - **Step 3:** Execute a command that triggers the CMake process. For example, run “CMake: Online Help” from the command palette. This call should invoke the `cmake` function.
    - **Step 4:** Verify whether the external command is executed by checking for the side effect (e.g., the file `/tmp/hacked` is created or the expected “HACKED” output appears in logs).
    - **Step 5:** Conclude that the command execution occurs based solely on the unsafe configuration data without proper validation, thereby confirming the vulnerability.