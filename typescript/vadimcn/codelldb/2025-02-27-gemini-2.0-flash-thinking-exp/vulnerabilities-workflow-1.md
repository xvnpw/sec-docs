## Combined Vulnerability List

This document combines vulnerabilities from multiple lists, removing duplicates and formatting them for clarity.

### 1. Command Injection via URI "launch/command" handler

**Description:**
1. An attacker can craft a malicious URI with the prefix `vscode://vadimcn.vscode-lldb/launch/command?`.
2. This URI can be opened by the user, for example, by tricking them into clicking a link or by embedding it in a document.
3. The VSCode extension parses the command line provided in the URI.
4. The extension uses shell-like parsing rules to split the command line into program name and arguments using `stringArgv`.
5. Due to insufficient sanitization of the command line arguments, an attacker can inject arbitrary shell commands.
6. When the debug session starts, the injected commands will be executed by the system.

**Impact:**
- **High**. Arbitrary command execution on the user's machine with the privileges of the VSCode process. This can lead to data exfiltration, malware installation, or complete system compromise.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
- None identified. The code uses `stringArgv` for parsing URI command lines, which is known to be vulnerable to command injection if not handled carefully with untrusted input.

**Missing mitigations:**
- Input sanitization and validation for the command line arguments passed via the URI in `extension/externalLaunch.ts`.
- Avoid using shell-like parsing for command line arguments from untrusted sources in `extension/externalLaunch.ts`. Instead, use a safer parsing method that doesn't interpret shell metacharacters.
- Consider disallowing or providing a configuration option to disable the `launch/command` URI handler in `extension/main.ts` if it's not essential functionality.

**Preconditions:**
- The user must have CodeLLDB extension installed and enabled in VSCode.
- The attacker needs to trick the user into opening a maliciously crafted `vscode://vadimcn.vscode-lldb/launch/command?` URI.

**Source code analysis:**
- File: `/code/extension/externalLaunch.ts`
- Class: `UriLaunchServer`
- Function: `handleUri(uri: Uri)`
- The code extracts the query part of the URI and processes it based on the URI path.
- For the path `/launch/command`, it retrieves the command line from the query.
- `let cmdLine = frags.pop();` gets the last fragment as command line.
- `let args = stringArgv(cmdLine);` uses `stringArgv` to parse the command line into arguments. This function interprets shell-like syntax.
- `let program = args.shift();` extracts the program name.
- A debug configuration is created with `program` and `args` and then `debug.startDebugging` is called.
- There is no sanitization of `cmdLine` before parsing with `stringArgv`, which allows for command injection.
- Example malicious URI: `vscode://vadimcn.vscode-lldb/launch/command?program=/bin/bash%20-c%20'malicious_command'` or `vscode://vadimcn.vscode-lldb/launch/command?program=program_name%20arg1%20$(malicious_command)`

**Security test case:**
1. Create a simple launch configuration in VSCode. This configuration is not actually used, but VSCode requires one to be present to handle debug URIs.
2. Craft a malicious URI that uses the `launch/command` handler to execute a command like `touch /tmp/pwned`. Example URI: `vscode://vadimcn.vscode-lldb/launch/command?program=/bin/bash%20-c%20touch%20/tmp/pwned` (URL encode special characters if needed).
3. Open this URI using `code --open-url "vscode://vadimcn.vscode-lldb/launch/command?program=/bin/bash%20-c%20touch%20/tmp/pwned"`.
4. Check if the file `/tmp/pwned` is created on the system. If the file is created, it confirms command injection vulnerability.
5. For Windows, a similar test can be performed using `cmd.exe /c echo pwned > C:\TEMP\pwned.txt` in the URI.


### 2. Insecure Platform Package Download (MITM Vulnerability)

**Description:**
1. The extension downloads platform-specific packages (VSX files) from a predefined URL during the extension installation or update process.
2. The `download` function in `/code/extension/install.ts` fetches the package over HTTPS, but it **does not perform any integrity checks** on the downloaded file, such as verifying a checksum or digital signature.
3. An attacker capable of performing a Man-in-the-Middle (MITM) attack could intercept the download request and replace the legitimate platform package with a malicious one.
4. If a malicious package is substituted, when VSCode installs the VSIX package, it will install the malicious extension, leading to arbitrary code execution within the VSCode context.

**Impact:**
- **Critical**. Arbitrary command execution on the user's machine with the privileges of the VSCode process upon extension installation or update. This can lead to complete system compromise, including data theft, malware installation, and persistent backdoor creation.

**Vulnerability Rank:** Critical

**Currently implemented mitigations:**
- None. The download process lacks any integrity verification mechanisms. While HTTPS is used, it only protects confidentiality and not integrity against active MITM attacks that can replace the content.

**Missing mitigations:**
- Implement integrity checks for downloaded platform packages.
- The most effective mitigation is to verify a digital signature of the VSIX package before installation. If digital signatures are not feasible, implement checksum verification (e.g., SHA256 hash) of the downloaded file against a known good value.
- Ensure that the checksum or signature is retrieved over a separate secure channel or is embedded within the extension itself and is verified before proceeding with the installation.

**Preconditions:**
- The user's machine is in a network that is susceptible to Man-in-the-Middle attacks.
- The CodeLLDB extension attempts to install or update its platform package.

**Source code analysis:**
- File: `/code/extension/install.ts`
- Function: `download`
- `getPlatformPackageUrl` function determines the download URL from `package.json`.
- `download` function uses `async.https.get(url)` to fetch the package and pipes the response to `fs.createWriteStream(destPath)`.
- **There is no code in the `download` function or the surrounding installation process that performs any kind of checksum or signature verification of the downloaded VSIX package.**
- The downloaded file at `destPath` is directly passed to `commands.executeCommand('workbench.extensions.command.installFromVSIX', [Uri.file(downloadTarget)])` for installation.

**Security test case:**
1. Set up a Man-in-the-Middle proxy (like mitmproxy or Burp Suite) to intercept HTTPS traffic.
2. Configure the proxy to intercept requests to the platform package download URL obtained from `getPlatformPackageUrl()` function in `/code/extension/install.ts`.
3. Create a malicious VSIX package that executes a simple command (e.g., `touch /tmp/codelldb_mitm_pwned`) upon installation.
4. Configure the MITM proxy to replace the legitimate platform package response with the malicious VSIX package.
5. Trigger the platform package installation in VSCode (e.g., by installing CodeLLDB extension for the first time or updating it if a new version is available that triggers platform package re-download).
6. Observe the MITM proxy intercepting and replacing the platform package download.
7. After VSCode attempts to install the (maliciously replaced) platform package, check if the file `/tmp/codelldb_mitm_pwned` exists. If the file exists, the MITM attack and insecure download vulnerability are confirmed.


### 3. Unauthenticated RPC Debug Configuration Injection

**Description:**
1. When the user enables RPC mode (by setting “lldb.rpcServer”), the extension creates a TCP server.
2. This server (implemented in the class `RpcLaunchServer` in `externalLaunch.ts`) listens for incoming data.
3. The raw request payload is directly decoded and passed to YAML’s parser to merge with a default debug configuration.
4. Although the code checks for a matching token if one is configured, the token is optional.
5. An attacker who can connect to the RPC server’s port (if it's bound to a non-localhost interface) and send a crafted YAML payload can inject arbitrary properties into the debug configuration.
6. This results in an unintended debug session that runs arbitrary executables with custom arguments and environment variables.

**Impact:**
- **Critical**. Exploiting this vulnerability may allow an attacker who can reach the RPC server to inject a debug configuration that launches arbitrary processes under the control of the attacker. In the worst case, this can lead to remote code execution and complete system compromise.

**Vulnerability Rank:** Critical

**Currently implemented mitigations:**
- When a token is configured via `"lldb.rpcServer.token"`, the code compares the payload’s `"token"` property with the server’s token before processing the request.

**Missing mitigations:**
- The token is optional, so in many deployments no authentication is enforced.
- There’s no restriction on the listening interface (e.g. forcing binding only to localhost).
- No whitelist of allowed configuration keys or additional input sanitization is applied before merging the payload with the default debug configuration.

**Preconditions:**
- The user must enable the RPC server by setting `"lldb.rpcServer"` in settings.
- The attacker must be able to connect to the TCP port served by the RPC interface—this is possible if the “lldb.rpcServer” setting is misconfigured to bind to an externally reachable interface.

**Source code analysis:**
- File: `/code/extension/externalLaunch.ts`
- Class: `RpcLaunchServer`
- The class `RpcLaunchServer` creates a Node.js net server with `allowHalfOpen: true`.
- On receiving a connection, it reads the full request string and passes it to the asynchronous method `processRequest()`.
- Inside `processRequest()`, a default debug configuration is defined and then extended via `Object.assign(debugConfig, YAML.parse(request))`.
- If a token is configured but the payload does not supply a matching token, the request is rejected—but if no token is set, any payload is accepted.

**Security test case:**
1. Configure a test instance of CodeLLDB with “lldb.rpcServer” enabled but no token set. Ensure it binds to a non-localhost interface if possible for remote testing, or test locally if bound to localhost.
2. From a remote or network-controlled machine (or using a tool like Netcat), connect to the exposed TCP port and send a YAML payload such as:
   ```yaml
   program: /bin/sh
   args: ['-c', 'touch /tmp/malicious_triggered']
   env:
     MALICIOUS: true
   ```
3. Verify that the extension launches a debug session using the supplied configuration (for instance, check that `/tmp/malicious_triggered` is created).
4. Next, set a token via “lldb.rpcServer.token” in your settings and confirm that a payload submitted without the correct token is rejected.


### 4. Malicious Debug Configuration Injection via Custom URI Handler

**Description:**
1. The extension registers a custom URI handler (in `externalLaunch.ts`, class `UriLaunchServer`) that processes “vscode://…” URLs to start a debug session.
2. Depending on the URI path (for example, `/launch/config` or `/launch/command`), the handler decodes the query string.
3. For `/launch/config`, it parses the query as YAML. For `/launch/command`, it tokenizes it using `stringArgv()`.
4. Neither YAML parsing nor `stringArgv()` tokenization involve sanitization or validation of the payload.
5. An attacker who convinces a victim to click on a specially crafted link can thereby control important fields in the debug configuration (such as the target executable, arguments, environment variables, etc.) and initiate a debug session that executes arbitrary commands.

**Impact:**
- **High**. If exploited, this flaw may cause the extension to launch a debugging session with parameters chosen by the attacker. This might result in the execution of untrusted binaries or commands and could lead to remote code execution or system compromise.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
- The URI handler distinguishes between different URI paths but does not otherwise perform any filtering or validation on the supplied payload.

**Missing mitigations:**
- There is no sanitization or whitelist applied to the YAML or query-string payload.
- No user interaction/confirmation step is implemented to verify the debug session parameters before the session is started.
- No authentication checks are performed on the payload.

**Preconditions:**
- An attacker must deliver a crafted debug URI (for example, via phishing or by posting on a webpage) and the victim must click on it while running the extension.

**Source code analysis:**
- File: `/code/extension/externalLaunch.ts`
- Class: `UriLaunchServer`
- Method: `handleUri()`
- For `/launch/config`, it decodes the query string and calls `YAML.parse(query)`, then immediately merges the resulting object into a default debug configuration.
- For `/launch/command`, the handler uses `stringArgv()` to parse a command line and then uses the parsed arguments without further sanitization.

**Security test case:**
1. Start an instance of VSCode with the CodeLLDB extension active.
2. Craft a URI such as:
   ```
   vscode://vadimcn.vscode-lldb/launch/config?program:%20"/bin/sh"%0Aargs:%0A-%20"-c"%0A-%20"touch%20/tmp/malicious_triggered"
   ```
3. Trigger the URI (for example, via the command line using `code --open-url "<crafted URI>"` or by clicking a link).
4. Verify that the extension launches a debug session with the given parameters (e.g. check that `/tmp/malicious_triggered` is created).
5. Optionally, confirm that adding input validation prevents the attack when desired.


### 5. Unvalidated Webview HTML Injection via Debug Session Custom Event

**Description:**
1. The extension creates and manages debug-related webviews via the `WebviewManager` class (in `webview.ts`).
2. In its event handler `onDebugSessionCustomEvent()`, the code listens for custom events with the name `_pythonMessage`.
3. If the event body’s `message` property equals `"webviewSetHtml"`, the handler directly assigns the provided `html` string to the webview’s content.
4. No sanitization or validation is performed on the HTML content.
5. If an attacker can inject a malicious custom event payload, they can cause arbitrary HTML (and potentially JavaScript) to be rendered in the webview.

**Impact:**
- **High**. By injecting malicious HTML/JavaScript into the webview, an attacker could execute arbitrary code in the context of VSCode. This may lead to session hijacking, theft of sensitive data (such as credentials or debug information), or further lateral attacks within the user’s environment.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
- There is no sanitization or filtering of the HTML payload before it is injected into the webview.

**Missing mitigations:**
- Sanitization of the HTML content (e.g. stripping scripts or dangerous tags) before assignment.
- Validation that debug session custom events used to set webview content originate from trusted sources.
- An explicit confirmation step from the user before updating webview content using externally supplied HTML.

**Preconditions:**
- An attacker must be able to inject or manipulate a custom debug session event (for instance, by compromising a debug adapter or leveraging other debug configuration injection vulnerabilities) so that a `_pythonMessage` event with `message: "webviewSetHtml"` is delivered with a malicious HTML payload.

**Source code analysis:**
- File: `/code/webview.ts`
- Method: `onDebugSessionCustomEvent(e: DebugSessionCustomEvent)`
- When `e.body.message` equals `"webviewSetHtml"`, the corresponding webview’s HTML is set directly:
  ```typescript
  this.sessionPanels[e.session.id][e.body.id].webview.html = e.body.html;
  ```
- No input sanitization is performed on `e.body.html` before this assignment.

**Security test case:**
1. Launch VSCode with the CodeLLDB extension installed and start a debug session.
2. Using a tool or a simulated debug adapter, send a custom debug session event with the following structure:
   ```json
   {
     "event": "_pythonMessage",
     "body": {
       "message": "webviewSetHtml",
       "id": "test_webview",
       "html": "<script>alert('XSS');</script>"
     }
   }
   ```
3. Verify that the webview panel identified by “test_webview” updates its content to include the injected HTML.
4. Confirm that the script executes (e.g. an alert pops up), thereby demonstrating the successful injection of unsanitized HTML content.


### 6. Command Injection via `lldb.terminalPromptClear` setting

**Description:**
1. The `lldb.terminalPromptClear` setting allows users to configure a sequence of strings sent to the terminal to clear the command prompt.
2. This setting is intended to clear the terminal prompt in various shells.
3. However, the configured strings are directly passed to the terminal without proper sanitization or escaping.
4. A malicious user can craft a string that, when interpreted by the terminal, executes arbitrary commands.
5. To trigger this vulnerability, an attacker needs to convince a user to open a workspace with a malicious `lldb.terminalPromptClear` setting. This could be achieved by sharing a project with a crafted `.vscode/settings.json` file.
6. Once the workspace is opened and a debug session starts that involves terminal interaction (e.g., using "integrated" or "external" terminal for debuggee stdio), the malicious command in `lldb.terminalPromptClear` will be executed.

**Impact:**
- **Critical**. Arbitrary command execution on the user's machine with the privileges of the VSCode process. This can lead to data theft, malware installation, or complete system compromise.

**Vulnerability Rank:** Critical

**Currently implemented mitigations:**
- None. The setting is directly used to send commands to the terminal.

**Missing mitigations:**
- Input sanitization and escaping of the `lldb.terminalPromptClear` setting.
- Restricting the characters allowed in the `lldb.terminalPromptClear` setting to only control characters or escape sequences intended for terminal prompt clearing.
- Display a warning to the user when a workspace with a non-default `lldb.terminalPromptClear` setting is opened.

**Preconditions:**
- User opens a workspace containing a malicious `.vscode/settings.json` file with a crafted `lldb.terminalPromptClear` setting.
- A debug session is started that uses "integrated" or "external" terminal for debuggee stdio.

**Source code analysis:**
- File: `/code/extension/adapterSettings.ts`
- Function: `getAdapterSettings`
- The `terminalPromptClear` setting is retrieved using `config.get('terminalPromptClear')`.
- This `AdapterSettings` object is then passed to the debug adapter.
- The vulnerability lies in the debug adapter itself (`codelldb` executable, not provided in PROJECT FILES) which is expected to use `terminalPromptClear` setting to execute commands in the terminal without sanitization.

**Security test case:**
1. Create a new VSCode workspace.
2. Create a `.vscode` folder in the workspace root.
3. Create a `settings.json` file inside `.vscode` folder with the following content:
   ```json
   {
       "lldb.terminalPromptClear": ["$(touch /tmp/codelldb_pwned)"]
   }
   ```
4. Create a simple C++ or Rust project in the workspace. A basic "Hello, World!" program is sufficient.
5. Create a launch configuration in `launch.json` that uses "integrated" or "external" terminal for stdio.
6. Build the debuggee executable.
7. Start debugging the program using the created launch configuration.
8. After the debug session starts and terminal is initialized, check if the file `/tmp/codelldb_pwned` exists. If the file exists, the command injection was successful.


### 7. Unsafe YAML parsing in "launch/config" URI endpoint

**Description:**
1. CodeLLDB allows starting debug sessions from outside VSCode using specially formatted URIs, including `vscode://vadimcn.vscode-lldb/launch/config?<yaml>`.
2. This endpoint parses the YAML snippet provided in the URI to configure the debug session.
3. If the YAML parser is not configured to prevent unsafe deserialization, a malicious user could craft a YAML payload that, when parsed, executes arbitrary code on the user's machine.
4. To trigger this vulnerability, an attacker needs to create a malicious URI with a YAML payload that exploits a known YAML deserialization vulnerability (e.g., using `!!python/object/new:object:subprocess.Popen`).
5. The attacker would then need to convince the user to open this malicious URI.
6. When VSCode opens the URI, CodeLLDB will parse the YAML payload, potentially leading to arbitrary code execution.

**Impact:**
- **Critical**. Arbitrary command execution on the user's machine with the privileges of the VSCode process. This can lead to data theft, malware installation, or complete system compromise.

**Vulnerability Rank:** Critical

**Currently implemented mitigations:**
- Unknown. It's not clear from the provided files if safe YAML parsing is enforced.

**Missing mitigations:**
- Use a safe YAML parsing library or configure the current YAML parser to disable unsafe deserialization features (like `!!python/object/new` in PyYAML).
- Input validation of the YAML payload to prevent injection of malicious YAML constructs.

**Preconditions:**
- User opens a malicious URI of the format `vscode://vadimcn.vscode-lldb/launch/config?<yaml>`.
- The YAML payload contains malicious code exploiting unsafe YAML deserialization.

**Source code analysis:**
- File: `/code/extension/externalLaunch.ts`
- Class: `UriLaunchServer`
- Function: `handleUri`
- For the path `/launch/config`, the code `Object.assign(debugConfig, YAML.parse(query));` is used.
- `YAML.parse` from the `yaml` library is used to parse the URI query.
- By default, `YAML.parse` might not be safe against deserialization vulnerabilities. If the library is used without options to enforce safe loading, it is vulnerable.
- There is no visible sanitization or validation of the YAML input before parsing.

**Security test case:**
1. Create a malicious YAML payload that executes a simple command (e.g., `touch /tmp/codelldb_yaml_pwned`). A Python-specific payload for PyYAML could be: `!!python/object/new:object:subprocess.Popen ['touch /tmp/codelldb_yaml_pwned', shell=True, close_fds=True]`.  (Note: This payload might need adjustments depending on the actual YAML library used and the environment).
2. Construct a malicious URI using the crafted YAML payload, properly URI-encoded. For example: `vscode://vadimcn.vscode-lldb/launch/config?!!python/object/new:object:subprocess.Popen%20%5B'touch%20/tmp/codelldb_yaml_pwned',%20shell=True,%20close_fds=True%5D`
3. Open the malicious URI using `code --open-url "<malicious_uri>"`.
4. Check if the file `/tmp/codelldb_yaml_pwned` exists after VSCode processes the URI. If the file exists, the unsafe YAML parsing vulnerability is confirmed.


### 8. Command Injection in `pickProcess` Command via `initCommands` Option

**Description:**
1. The `lldb.pickProcess` and `lldb.pickMyProcess` commands, exposed to VSCode's command palette and launch configurations, utilize the `pickProcess` function in `/code/extension/pickProcess.ts` to display a list of processes for users to attach to.
2. The `pickProcess` function accepts an optional `options` argument of type `PickProcessOptions`, which includes an `initCommands` array.
3. The `initCommands` array is intended to allow users to specify LLDB commands to be executed when fetching the process list. However, these commands are executed via `cp.exec` without sufficient sanitization.
4. A malicious user can craft a launch configuration that uses `${command:lldb.pickProcess}` or `${command:lldb.pickMyProcess}` and inject arbitrary LLDB commands through the `initCommands` option.
5. These commands, when executed by `pickProcess`, can lead to arbitrary code execution within the LLDB context, and potentially on the host system.

**Impact:**
- **High**. Arbitrary command execution within the LLDB context, potentially leading to arbitrary code execution on the user's machine with the privileges of the VSCode process. Attackers can potentially bypass security restrictions, access sensitive data, or compromise the user's system.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
- None. The `initCommands` are passed to `cp.exec` without sanitization or validation.

**Missing mitigations:**
- Sanitize or strictly validate the `initCommands` passed to `pickProcess` to prevent command injection.
- Ideally, avoid using `cp.exec` with user-controlled input for executing LLDB commands. If execution of LLDB commands is necessary, use a safer method that does not involve shell execution or carefully sanitize inputs to prevent injection.
- Consider removing the `initCommands` option altogether if it's not essential and poses a significant security risk.

**Preconditions:**
- User opens a workspace containing a malicious launch configuration that utilizes `${command:lldb.pickProcess}` or `${command:lldb.pickMyProcess}` with a crafted `initCommands` option.
- User attempts to use the malicious launch configuration, triggering the `pickProcess` command.

**Source code analysis:**
- File: `/code/extension/pickProcess.ts`
- Function: `pickProcess` and `getProcessList`
- Inside `getProcessList` function, `initArgs` is constructed from `options.initCommands` by directly concatenating the commands into a string.
- This `initArgs` is then directly embedded into the `command` string that is executed via `cp.exec`:
  ```typescript
  let command = `${lldbPath} --batch --no-lldbinit ${initArgs} --one-line "${processListCommand}"`;
  let stdout = await new Promise<string>((resolve, reject) => {
      cp.exec(command, { env: env }, (error, stdout) => { ... });
  });
  ```
- The code directly uses string concatenation to build the command and passes it to `cp.exec`, making it vulnerable to command injection if `options.initCommands` is attacker-controlled.

**Security test case:**
1. Create a new VSCode workspace.
2. Create a `.vscode` folder in the workspace root.
3. Create a `launch.json` file inside `.vscode` folder with the following content:
   ```json
   {
       "version": "0.2.0",
       "configurations": [
           {
               "type": "lldb",
               "request": "attach",
               "name": "Attach Malicious Process Picker",
               "pid": "${command:lldb.pickProcess, {\"initCommands\": [\"script import os; os.system('touch /tmp/codelldb_pickprocess_pwned')\"]}}"
           }
       ]
   }
   ```
4. Open the Debug view in VSCode and select "Attach Malicious Process Picker" configuration.
5. Start debugging. VSCode will attempt to resolve the `${command:lldb.pickProcess, ...}`.
6. Check if the file `/tmp/codelldb_pickprocess_pwned` exists. If the file exists, the command injection via `initCommands` in `pickProcess` is confirmed.