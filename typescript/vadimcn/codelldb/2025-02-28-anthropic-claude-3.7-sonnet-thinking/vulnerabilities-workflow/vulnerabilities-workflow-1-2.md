# Vulnerability List

## 1. Malicious Deep Link Debug Session Launch (RCE)

### Description
The extension registers a URI handler (in *extension/externalLaunch.ts* within the `UriLaunchServer` class) to process deep links such as  
`vscode://vadimcn.vscode-lldb/launch/command?...`. When the user clicks such a link, the handler decodes the query string, uses basic parsing (via Node's `querystring.parse` and `string-argv`) to build a debug configuration, and immediately calls `debug.startDebugging` with that configuration without further validation. An attacker modifying a repository (for example, by embedding such a deep link into project documentation) can supply a malicious configuration specifying an arbitrary executable along with arbitrary arguments.  
*Step by step triggering:*  
1. The attacker embeds a deep link URL that encodes a debug configuration with the "program" field set to a malicious executable (e.g. `/bin/evil`) plus attacker–controlled arguments.  
2. The victim opens the manipulated repository (with the embedded link).  
3. When the victim clicks the link, the URI handler immediately constructs and uses the debug configuration.  
4. The debug session launches the attacker–specified executable.

### Impact
The attacker achieves remote code execution by launching an arbitrary external process with the user's privileges. This may lead to a full compromise of the victim's system.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
Only the RPC launch server (a different code path) optionally uses a token check; the deep link handler does not perform input validation or request user confirmation.

### Missing Mitigations
• Validate and sanitize deep link query parameters rigorously before composing a debug configuration.  
• Require explicit user confirmation or enforce a safe list of allowed executables.  
• Optionally mandate cryptographic signing or a token check for deep link–initiated requests.

### Preconditions
• The victim opens a workspace (or repository) that includes the malicious deep link.  
• The user clicks the link, thereby invoking the URI handler while debugging is allowed.

### Source Code Analysis
1. In *extension/externalLaunch.ts*, the `UriLaunchServer` class's `handleUri(uri: Uri)` method is invoked when a deep link is clicked.  
2. The method decodes the URL (using `decodeURIComponent`) and parses query parameters via `querystring.parse` and `string-argv`.  
3. The parsed parameters are used directly to compose a debug configuration containing a `program` and `args` field.  
4. The configuration is passed unchanged to `debug.startDebugging`, immediately starting the debug session.

### Security Test Case
1. Craft a deep link such as:  
   ```
   vscode://vadimcn.vscode-lldb/launch/command?MALICIOUS_ENV=1&/bin/evil --option "malicious arg"
   ```  
   *(On a test system, substitute `/bin/evil` with a benign executable that logs its execution.)*  
2. Open the manipulated repository or paste the URL into a browser/command line.  
3. Confirm that the extension initiates a debug session that launches the specified executable by monitoring process creation or checking for a marker file.

## 2. Unauthenticated External Debug Session Invocation via RPC Server (RCE)

### Description
The extension also sets up an RPC server (in *extension/externalLaunch.ts* inside the `RpcLaunchServer` class) that listens for YAML‐encoded debug configurations. When a client connects, if the `"lldb.rpcServer"` setting is enabled without enforcing a token, an attacker on the same network may supply a crafted YAML payload that defines a debug configuration with an arbitrary "program".  
*Step by step triggering:*  
1. The attacker locates a workspace where `"lldb.rpcServer"` is enabled without a strong token.  
2. The attacker connects (e.g. via netcat) to the listening port and sends YAML data that sets the "program" field to a malicious executable along with attacker–controlled parameters.  
3. Without proper authentication or validation, the RPC server passes the configuration to `debug.startDebugging`, thereby launching the malicious process.

### Impact
This flaw allows an external attacker to launch arbitrary executables with the victim's user privileges, resulting in potential full remote code execution.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
If a token is configured in the settings, the server checks that the submitted configuration includes a matching token. However, if no token is set, the payload is accepted without authentication.

### Missing Mitigations
• Mandate that a strong authentication token be configured and enforced.  
• Implement robust input validation for the YAML payload and restrict allowed configuration fields.

### Preconditions
• The workspace (or global settings) enables `"lldb.rpcServer"` without a strong (or any) token.  
• The attacker is on the local network and able to connect to the specified port.  
• The attacker can deliver a crafted YAML payload.

### Source Code Analysis
1. In *extension/externalLaunch.ts*, the `RpcLaunchServer` class is activated when a nonempty `"lldb.rpcServer"` setting is detected.  
2. Upon connection, the server listens for data and parses the incoming YAML into a debug configuration object.  
3. If a token is set in the configuration, it is only checked if present; otherwise, no authentication is enforced.  
4. The unvalidated configuration is passed directly to `debug.startDebugging`, launching the debug session.

### Security Test Case
1. Configure a test VSCode instance with:  
   ```json
   "lldb.rpcServer": { "host": "127.0.0.1", "port": 12345 }
   ```  
   (Ensure no token is specified.)  
2. From a machine on the same network, run:  
   ```bash
   echo "{ program: '/path/to/malicious_executable', args: ['--malicious'], name: 'Malicious Launch' }" | nc 127.0.0.1 12345
   ```  
3. Verify that the debug session starts and launches the executable.  
4. Optionally, confirm that providing a token in the settings causes payloads lacking the token to be rejected.

## 3. Command Injection via Process Picker Init Commands

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

## 4. Prototype Pollution via dbgconfig Expansion in Debug Configuration

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

## 5. Manipulated Cargo Executable Launch (RCE)

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