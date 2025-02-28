# List of Vulnerabilities

## Insecure API Key Vault Command Execution

### Description
The extension attempts to retrieve the API key using an externally configured command defined by the setting `api_key_vault_cmd` in its INI configuration file (stored at `$HOME/.wakatime.cfg`).

In the function `getApiKeyFromVaultCmd` (located in `/code/src/options.ts`), the extension reads this setting and then naïvely splits its value by whitespace to obtain a command name and its arguments.

It then calls `child_process.spawn` with these values. Because no proper validation or sanitization is performed on this command string, an attacker who can supply or force the user to install a malicious configuration file could craft a value that executes arbitrary commands.

**Step-by-step trigger:**  
1. A threat actor provides a repository (or instructs the victim during installation) that includes a modified `.wakatime.cfg` with a malicious `api_key_vault_cmd` value—for example:  
   ```
   [settings]
   api_key_vault_cmd = malicious_script.sh --run-malicious-action
   ```
   or, on Windows, something like:
   ```
   [settings]
   api_key_vault_cmd = cmd.exe /c calc.exe
   ```
2. The victim installs the extension and (if no other trusted API key is supplied) the extension calls `getApiKey()`.
3. Failing to retrieve the API key from other sources, the extension invokes `getApiKeyFromVaultCmd`, which reads the malicious command string and splits it into a command and arguments.
4. The extension then executes the attacker‑controlled command via `child_process.spawn`, causing the malicious script (or command) to run.

### Impact
**Remote Code Execution (RCE):** An attacker who can influence the contents of the configuration file (for example, by supplying a malicious repository or convincing the user to copy a tampered config) will be able to execute arbitrary commands on the victim's system with the privileges of the user running VS Code.

This could lead to full system compromise, data theft, or further lateral movement.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
There is an implicit assumption in the code (see `/code/src/options.ts`, function `getApiKeyFromVaultCmd`) that the configuration file is trusted. The code simply reads and splits the command string without any validation or sandboxing.

The command is executed via `child_process.spawn` (which avoids shell interpretation) but this does not protect against an attacker who controls the entire command string.

### Missing Mitigations
- **Input Validation/Sanitization:** There is no validation (or safe parsing) on the value of `api_key_vault_cmd` before splitting it into a command and arguments.
- **Restricting Command Choices:** The extension does not restrict or whitelist acceptable values for the API key vault command.
- **User Confirmation/Sandboxing:** There is no prompt or sandboxing when executing an external command defined in configuration.
- A robust mitigation would include parsing the setting using a secure, well‑defined format; verifying that the command being executed is allowed; and possibly requiring explicit user consent before executing an external process.

### Preconditions
- The attacker must be able to influence the contents of the configuration file (for example, by providing a malicious repository along with instructions or an installer that copies a malicious `.wakatime.cfg` to the victim's home directory).
- No valid API key is provided through the other channels (editor settings, environment variable), forcing the extension to fall back to the vault command.

### Source Code Analysis
In `/code/src/options.ts`, the function `getApiKeyFromVaultCmd()` has the following key steps:
- It retrieves the raw command string via:
  ```ts
  const cmdStr = await this.getSettingAsync<string>('settings', 'api_key_vault_cmd');
  ```
- It then naïvely splits the string:
  ```ts
  const cmdParts = cmdStr.trim().split(' ');
  const [cmdName, ...cmdArgs] = cmdParts;
  ```
- Finally, it calls:
  ```ts
  const proc = child_process.spawn(cmdName, cmdArgs, options);
  ```
- **Visualization:**
  - **Input Config:**  
    `api_key_vault_cmd = cmd.exe /c calc.exe`
  - **After Splitting:**  
    `cmdName = 'cmd.exe'`  
    `cmdArgs = ['/c', 'calc.exe']`
  - **Execution:**  
    The extension spawns the process `cmd.exe` with the given arguments—thus executing an attacker‑supplied command.

### Security Test Case
**Test Setup:**  
1. In a controlled testing environment (a VM or container), prepare a malicious configuration file located at the expected path (e.g. `${HOME}/.wakatime.cfg`).
2. Include in the configuration file under the `[settings]` section a malicious API key vault command. For example, on Windows:
   ```
   [settings]
   api_key_vault_cmd = cmd.exe /c echo MALICIOUS_CODE_EXECUTED && calc.exe
   ```
   (On Unix, you might use a benign command such as `echo "MALICIOUS_CODE_EXECUTED"` instead of starting a calculator.)
3. Ensure that no API key is preset in other configuration channels.

**Execution:**
1. Launch Visual Studio Code with the extension installed.
2. As the extension initializes and tries to retrieve the API key via `getApiKeyFromVaultCmd`, observe that the malicious command is executed.
3. Verify by checking system indicators (for example, the calculator application starts on Windows or the test command output appears).

**Expected Result:**
- If the malicious command is executed as described (e.g. calculator launches or the test message is output), this confirms the vulnerability.