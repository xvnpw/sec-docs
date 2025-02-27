## Vulnerability List for Python extension for Visual Studio Code

- Vulnerability name: Command Injection via ActiveState Tool Path setting
- Description:
    1. An attacker can modify the VSCode settings for the Python extension, specifically the `python.activeStateToolPath` setting.
    2. The attacker sets this setting to point to a malicious executable file under their control.
    3. When the Python extension attempts to discover ActiveState environments, it executes the command specified in `python.activeStateToolPath` using `shellExecute`.
    4. The malicious executable is executed, allowing the attacker to run arbitrary commands on the user's machine with the privileges of the VSCode process.
- Impact: Arbitrary code execution on the user's machine. This can lead to data theft, malware installation, or complete system compromise.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None in the provided code. The code directly uses the user-provided path from settings to execute a command.
- Missing mitigations:
    - Input validation: The extension should validate the `activeStateToolPath` setting to ensure it points to a legitimate ActiveState tool executable. Ideally, the extension should locate the `state` tool itself and not rely on user settings for the full path, or at least verify the path is within expected locations.
    - Command sanitization: If external commands must be executed based on user settings, ensure proper sanitization of the command and arguments to prevent injection. In this case, avoid using `shellExecute` with user-controlled paths as the command itself.
- Preconditions:
    - The user must have the Python extension for VSCode installed.
    - The attacker needs to have the ability to modify VSCode settings (e.g., through a workspace configuration if the user opens a malicious workspace, or by social engineering to trick the user into changing user settings).
- Source code analysis:
    1. File: `/code/src/client/pythonEnvironments/common/environmentManagers/activestate.ts`
    2. Function: `getProjectsCached`
    3. Line:
    ```typescript
    const result = await shellExecute(`${stateCommand} projects -o editor`, {
        timeout: STATE_GENERAL_TIMEOUT,
    });
    ```
    4. The `stateCommand` variable is derived from user settings using:
    ```typescript
    const stateCommand =
        getPythonSetting<string>(ACTIVESTATETOOLPATH_SETTING_KEY) ?? ActiveState.defaultStateCommand;
    ```
    5. `getPythonSetting` retrieves the value of `python.activeStateToolPath` from VSCode settings.
    6. If an attacker can control the value of `python.activeStateToolPath` setting, they can inject arbitrary commands by pointing this setting to a malicious executable. `shellExecute` will then execute this malicious executable.
- Security test case:
    1. On a test machine with VSCode and Python extension installed, create a malicious executable file (e.g., `malicious_state.sh` on Linux/macOS or `malicious_state.bat` on Windows). This script should perform an easily verifiable action, like creating a file in the user's home directory or printing a specific message to stdout. For example, on Linux/macOS: `echo 'touch /tmp/pyscript_vulnerability_test' > malicious_state.sh && chmod +x malicious_state.sh` and on Windows: `echo "echo Vulnerable > %TEMP%\\pyscript_vulnerability_test.txt" > malicious_state.bat`.
    2. In VSCode settings (User settings), search for `python.activeStateToolPath` and set its value to the absolute path of the malicious executable created in step 1 (e.g., `/path/to/malicious_state.sh` or `C:\\path\\to\\malicious_state.bat`).
    3. Open any Python project in VSCode (or create a new one).
    4. Trigger the ActiveState environment discovery. This might happen automatically, or you may need to manually trigger environment discovery or any feature that relies on environment discovery and utilizes ActiveState detection.
    5. After triggering the discovery, check if the action defined in the malicious script has been executed. For example, check if the file `/tmp/pyscript_vulnerability_test` (Linux/macOS) or `%TEMP%\\pyscript_vulnerability_test.txt` (Windows) has been created.
    6. If the file is created, it confirms that arbitrary code execution was achieved by modifying the `python.activeStateToolPath` setting.

- Vulnerability name: Command Injection via TensorBoard Remote URL
- Description:
    1. An attacker can trick a user into launching TensorBoard and selecting the "Enter remote URL" option.
    2. The attacker provides a malicious URL that includes command injection payloads.
    3. The extension executes `tensorboardLauncher` with the user-provided URL as the log directory.
    4. Due to insufficient sanitization of the `logDir` parameter, the attacker's injected commands are executed via `shellExec`.
- Impact: Arbitrary code execution on the user's machine. This can lead to data theft, malware installation, or complete system compromise.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None in the provided code. User-provided URL is directly passed to `shellExec`.
- Missing mitigations:
    - Input sanitization: Sanitize the user-provided URL in `getLogDirectory` to remove or escape any characters that could be used for command injection before passing it to `tensorboardLauncher`.
    - Avoid shell execution: Ideally, avoid using `shellExec` to execute TensorBoard. Explore using direct function calls or safer process spawning methods that don't involve shell interpretation of the command string.
- Preconditions:
    - The user must have the Python extension for VSCode installed.
    - The user must choose to launch TensorBoard and select the "Enter remote URL" option.
    - The attacker needs to socially engineer or otherwise induce the user to enter a malicious URL.
- Source code analysis:
    1. File: `/code/src/client/tensorBoard/tensorBoardSession.ts`
    2. Function: `getLogDirectory`
    3. Line:
    ```typescript
    case enterRemoteUrl:
        return this.applicationShell.showInputBox({
            prompt: TensorBoard.enterRemoteUrlDetail,
        });
    ```
    4. The user input from `showInputBox` is returned as `logDir`.
    5. File: `/code/src/client/tensorBoard/tensorBoardSession.ts`
    6. Function: `startTensorboardSession`
    7. Line:
    ```typescript
    const args = tensorboardLauncher([logDir]);
    const observable = processService.execObservable(args, {});
    ```
    8. `tensorboardLauncher` constructs a command including `logDir`.
    9. `processService.execObservable` (or potentially `shellExec` in `InvalidPythonInterpreterService` as seen in other files) executes this command, leading to command injection if `logDir` is malicious.
- Security test case:
    1. On a test machine with VSCode and Python extension installed, prepare a command injection payload. For example, a simple payload to create a file: `http://127.0.0.1:6006; touch /tmp/tensorboard_vulnerability_test` (Linux/macOS) or `http://127.0.0.1:6006& echo Vulnerable > %TEMP%\\tensorboard_vulnerability_test.txt` (Windows).
    2. In VSCode, trigger the "Launch TensorBoard" command (e.g., via Command Palette).
    3. When prompted to select a log directory, choose "Enter remote URL".
    4. Paste the malicious URL crafted in step 1 into the input box and press Enter.
    5. After TensorBoard attempts to launch (it will likely fail to connect to the invalid URL, but that's expected), check if the injected command was executed. For example, check if the file `/tmp/tensorboard_vulnerability_test` (Linux/macOS) or `%TEMP%\\tensorboard_vulnerability_test.txt` (Windows) has been created.
    6. If the file is created, it confirms command injection vulnerability via the TensorBoard remote URL input.