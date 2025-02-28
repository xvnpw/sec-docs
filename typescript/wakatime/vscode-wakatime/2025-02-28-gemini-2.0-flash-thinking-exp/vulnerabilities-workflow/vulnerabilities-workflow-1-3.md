### Vulnerability: Command Injection via Malicious File Path

* Description:
    1. An attacker creates a file with a malicious file name containing shell command injection characters (e.g., backticks, dollar signs, etc.).
    2. The victim opens this malicious file in Visual Studio Code with the WakaTime extension installed and activated.
    3. WakaTime extension attempts to send a heartbeat for the opened file to the `wakatime-cli` executable.
    4. The extension uses a vulnerable quoting mechanism (`Utils.quote()`) which is insufficient to prevent command injection when constructing the command line arguments for `wakatime-cli`.
    5. When `wakatime-cli` is executed with the malicious file path as an argument, the injected shell commands are executed by the system shell.

* Impact:
    Arbitrary command execution on the victim's machine with the privileges of the VSCode process. This can lead to:
    - Data exfiltration: Attacker can access and steal sensitive information from the victim's file system.
    - System compromise: Attacker can install malware, create new user accounts, or modify system settings.
    - Lateral movement: If the victim's machine is part of a network, the attacker might be able to use the compromised machine to gain access to other systems.

* Vulnerability Rank: high

* Currently implemented mitigations:
    - The project uses a quoting function (`Utils.quote()`) to wrap arguments passed to `wakatime-cli`. However, this function only escapes double quotes and handles spaces, which is insufficient to prevent command injection in various shell environments.
    - No other input sanitization or validation is implemented for file paths or project names before passing them as arguments to `wakatime-cli`.

* Missing mitigations:
    - Implement proper sanitization of all arguments passed to `wakatime-cli` to prevent command injection. This should include escaping or removing shell-sensitive characters like backticks, dollar signs, semicolons, ampersands, etc.
    - Consider using parameterized command execution methods if available in the Node.js `child_process` API to avoid shell interpretation of arguments altogether.
    - Input validation: Validate file paths and project names to ensure they conform to expected formats and do not contain suspicious characters.

* Preconditions:
    - Victim has the WakaTime VSCode extension installed and activated.
    - Victim opens a file with a malicious file name crafted by the attacker.

* Source code analysis:
    1. **File:** `/code/src/wakatime.ts`
    2. **Function:** `sendHeartbeat` and `_sendHeartbeat`
    3. **Vulnerable code:**
    ```typescript
    const binary = this.dependencies.getCliLocation();
    this.logger.debug(`Sending heartbeat: ${Utils.formatArguments(binary, args)}`);
    const options = Desktop.buildOptions();
    let proc = child_process.execFile(binary, args, options, ...);
    ```
    - The `child_process.execFile` function is used to execute `wakatime-cli`.
    - The `args` array contains arguments that are constructed using potentially user-controlled inputs like `doc.fileName` and `this.getProjectName(doc.uri)`.
    - The `Utils.formatArguments` function uses `Utils.wrapArg` which in turn calls `Utils.quote` for quoting.
    - `Utils.quote` function in `/code/src/utils.ts` provides insufficient quoting:
    ```typescript
    public static quote(str: string): string {
        if (str.includes(' ')) return `"${str.replace('"', '\\"')}"`;
        return str;
    }
    ```
    - This quoting mechanism is vulnerable to command injection as it does not escape backticks, dollar signs, and other shell metacharacters.

    ```mermaid
    graph LR
        A[User opens malicious file] --> B(WakaTime Extension);
        B --> C{sendHeartbeat()};
        C --> D{_sendHeartbeat()};
        D --> E[Construct command arguments with Utils.quote()];
        E --> F[child_process.execFile(wakatime-cli, args)];
        F --> G[System Shell executes command];
        G --> H{Command Injection Vulnerability};
    ```

* Security test case:
    1. Create a new directory, for example `test-wakatime-command-injection`.
    2. Inside this directory, create a file with the malicious name: ``test`touch /tmp/wakatime-pwned.txt`.js`` (Note the backticks in the filename).
    3. Open Visual Studio Code and open the `test-wakatime-command-injection` directory as a workspace.
    4. Ensure the WakaTime extension is activated.
    5. Open the file ``test`touch /tmp/wakatime-pwned.txt`.js`` in the editor.
    6. Wait for a few seconds to allow WakaTime extension to send a heartbeat.
    7. Check if the file `/tmp/wakatime-pwned.txt` exists. If it exists, the command injection is successful.
    8. (Cleanup) Delete the `/tmp/wakatime-pwned.txt` file.