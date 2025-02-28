### Vulnerability List:

- Vulnerability Name: Command Injection in `dexnode` via `--exec-path`
- Description:
    1. An attacker can control the `--exec-path` argument in `dexnode`.
    2. `dexnode` uses `child_process.spawnSync` to execute the provided executable without sufficient sanitization.
    3. By crafting a malicious executable path, an attacker can inject arbitrary commands that will be executed by `child_process.spawnSync`.
    4. Since VSCode extensions execute with user privileges, this can lead to arbitrary code execution on the user's machine.
- Impact: Arbitrary code execution. An attacker can execute arbitrary commands on the user's machine with the same privileges as VS Code.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None
- Missing Mitigations:
    - Input sanitization for the `--exec-path` argument to prevent command injection.
    - Input validation to ensure `--exec-path` points to a legitimate executable and not a malicious script.
    - Consider disallowing user-provided executable paths altogether or restrict them to a safe list.
- Preconditions:
    - User must use the `dexnode` tool, which is a command-line utility helper for the Deopt Explorer VSCode extension.
    - Attacker must convince the user to run `dexnode` with a crafted `--exec-path` argument.
- Source Code Analysis:
    1. **Entry point:** `tools/dexnode/src/index.ts` uses `child_process.spawnSync(argv.exec_path, args, ...)` to execute a command.
    2. **Argument parsing:** `tools/dexnode/src/args.ts` parses command-line arguments, including `--exec-path`.
    3. **`exec_path` assignment:** In `tools/dexnode/src/args.ts`, the `exec_path` is assigned directly from user input or autodetected host paths without sanitization:
        ```typescript
        async function autodetectExecPath(argv: Options, host: Host) {
            if (!argv.exec_path) {
                argv.exec_path = await getHostExecPath(host); // Autodetected paths
            }
        }

        function parse(args: string[]) {
            ...
            if (STRINGS.has(arg)) {
                ...
                if (value === true) {
                    ...
                    value = args[1]; // User provided value
                    ...
                }
                ...
                (argv as any)[arg] = value; // Assigning to argv.exec_path
                ...
            }
            ...
        }
        ```
    4. **`getHostExecPath`**: `tools/dexnode/src/hosts.ts` and `tools/dexnode/src/util.ts` try to find executable paths from registry and PATH environment variable, but these are still potentially controllable by the user's environment. User can also directly provide path via `--exec-path`.
    5. **No Sanitization**: There is no sanitization or validation of `argv.exec_path` before it is passed to `child_process.spawnSync`.

    ```
    // Visualization of code flow:

    User Input (process.argv) --> args.ts (parseArgs) --> argv.exec_path --> index.ts (spawnSync) --> Command Execution
    ```

- Security Test Case:
    1. Create a malicious file named `malicious.js` with the following content:
    ```javascript
    const { execSync } = require('child_process');
    const command = process.argv[2];
    execSync(command, { stdio: 'inherit' });
    ```
    2. Create a log file using `dexnode` with a crafted `--exec-path` argument pointing to the malicious script and injecting a command to execute:
    ```sh
    dexnode --exec-path="/path/to/malicious.js" -- echo "Vulnerable"
    ```
    *Replace `/path/to/malicious.js` with the actual path to the malicious script.*
    3. Run the command in the terminal.
    4. Observe that the command `echo "Vulnerable"` is executed by `malicious.js` demonstrating command injection.
    5. In a real attack, the malicious script could execute more harmful commands like creating a reverse shell or stealing credentials.