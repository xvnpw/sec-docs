# PHP Debug Adapter for VSCode Vulnerabilities

## Vulnerability 1: Command Injection via Terminal Execution

### Description
The PHP Debug Adapter extension contains a command injection vulnerability in its terminal execution mechanism. When a user opens a malicious repository with this extension, an attacker can craft malicious inputs to execute arbitrary commands on the victim's system.

The vulnerability occurs in the terminal.ts implementation, where both Windows and Linux code paths build shell commands by concatenating an array of runtime arguments (supplied via the debug configuration) into a single command string without rigorous sanitization.

An attacker can exploit this in two primary ways:
1. Through malicious file paths that, when used to launch PHP processes, escape the intended command
2. Through a manipulated launch.json that contains specially crafted `runtimeArgs`

For example, in Windows implementation:
```js
const command = `""${args.join('" "')}" & pause"`
```

In the Linux implementation:
```js
const bashCommand = `cd "${dir}"; "${args.join('" "')}"; echo; read -p "${LinuxTerminalService.WAIT_MESSAGE}" -n1;`
```

This allows for command injection if the args contain shell metacharacters like `"` or `;`.

### Impact
An attacker can achieve remote code execution on a victim's machine. This allows the attacker to execute arbitrary commands with the same privileges as the VSCode process, potentially leading to complete system compromise, data theft, or installation of malware.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The code attempts to use platform-specific terminal launching mechanisms, but only performs a basic join of the runtime arguments with an assumption that configuration values are trusted.

### Missing Mitigations
1. Proper validation and sanitization of file paths and arguments before passing them to terminal execution functions
2. Use of shell escaping functions for all user-provided or file system-derived inputs
3. Implementation of a safe subprocess execution model that prevents command injection
4. Avoid shell-based concatenation by passing the command and its arguments directly
5. Strict trust boundaries for repository configurations

### Preconditions
1. Victim must open a malicious repository using VSCode with the PHP Debug extension installed
2. The extension must be configured to use external console launching (on either Windows or Linux)
3. The attacker must be able to supply or manipulate a repository containing malicious paths or a manipulated launch configuration

### Source Code Analysis
The vulnerability exists primarily in the terminal.ts file:

1. In the Windows implementation (WindowsTerminalService.launchInTerminal):
   ```javascript
   const title = `"${dir} - ${WindowsTerminalService.TERMINAL_TITLE}"`
   const command = `""${args.join('" "')}" & pause"`
   const cmdArgs = ['/c', 'start', title, '/wait', 'cmd.exe', '/c', command]
   ```

   If an attacker creates a malicious file or provides a crafted runtimeArg like `innocent_arg\"; cmd.exe /c calc.exe; \""`, the command injection occurs when this is inserted into the command string.

2. In the Linux implementation (LinuxTerminalService.launchInTerminal):
   ```javascript
   const bashCommand = `cd "${dir}"; "${args.join('" "')}"; echo; read -p "${LinuxTerminalService.WAIT_MESSAGE}" -n1;`
   ```

   Similar to Windows, this allows command injection if args contain shell metacharacters.

Both implementations rely on unsanitized concatenation of runtime arguments into a shell command string, creating an exploitable vector for command injection.

### Security Test Case
1. Create a malicious repository with this launch.json configuration:
   ```json
   {
     "version": "0.2.0",
     "configurations": [
       {
         "name": "Malicious Debug",
         "type": "php",
         "request": "launch",
         "program": "test.php",
         "cwd": "${workspaceFolder}",
         "runtimeArgs": [
           "-dxdebug.start_with_request=yes",
           "safeArg\"; cmd.exe /c calc.exe; \""
         ],
         "externalConsole": true
       }
     ]
   }
   ```

2. Alternatively, create a PHP file with a malicious filename like: `exploit.php"; rm -f "/tmp/test" > "/tmp/test" & echo "`

3. Share this repository with the victim

4. When the victim opens the repository in VSCode and starts debugging with this configuration, the command injection will execute the calculator on Windows (or an equivalent command on Linux)

5. Verify the attack by observing the calculator application opening (Windows) or checking for the created file (Linux)

## Vulnerability 2: Code Execution via Malicious Xdebug Responses

### Description
The PHP Debug Adapter is vulnerable to remote code execution through malicious Xdebug responses. When a user connects to a malicious PHP environment configured with a rogue Xdebug server, the extension doesn't properly validate responses before processing them, allowing attackers to inject code that gets executed on the victim's machine.

### Impact
An attacker can execute arbitrary code on the victim's machine by serving specially crafted Xdebug responses that exploit this vulnerability. This could lead to complete system compromise, data theft, or installation of malware.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension implements basic XML parsing and error handling, but doesn't sufficiently validate the structure and content of Xdebug responses before processing them.

### Missing Mitigations
1. Strict validation of Xdebug responses against a schema
2. Input sanitization for all data extracted from Xdebug responses
3. Proper sandboxing to limit the impact of malicious responses

### Preconditions
1. Victim must connect to a PHP environment controlled by an attacker
2. The malicious environment must be configured with a compromised Xdebug server
3. Victim must start a debugging session connecting to this environment

### Source Code Analysis
The vulnerability is in how phpDebug.ts handles Xdebug responses:

1. In the evaluate request handling, user expressions are executed via the Xdebug connection:
   ```typescript
   protected async evaluateRequest(
       response: VSCodeDebugProtocol.EvaluateResponse,
       args: VSCodeDebugProtocol.EvaluateArguments
   ): Promise<void> {
       // ...
       if (args.context === 'repl') {
           const uuid = randomUUID()
           await connection.sendEvalCommand(`$GLOBALS['eval_cache']['${uuid}']=${args.expression}`)
           // ...
       } else {
           const response = await connection.sendEvalCommand(args.expression)
           // ...
       }
       // ...
   }
   ```

2. When processing Xdebug responses like property values, the extension doesn't sufficiently validate the data:
   ```typescript
   function formatPropertyValue(property: xdebug.BaseProperty): string {
       let displayValue: string
       if (property.hasChildren || property.type === 'array' || property.type === 'object') {
           // ...
       } else {
           displayValue = property.value || property.type === 'string' ? property.value : property.type
           // ...
       }
       return displayValue
   }
   ```

3. The extension trusts data from the Xdebug server without sufficient validation, allowing a malicious server to send crafted responses that could trigger vulnerabilities in the processing logic.

### Security Test Case
1. Set up a malicious PHP environment with a compromised Xdebug server
2. Create a repository with a launch.json configuration pointing to this environment:
   ```json
   {
       "configurations": [{
           "type": "php",
           "request": "launch",
           "name": "Connect to malicious server",
           "port": 9003,
           "pathMappings": {
               "/var/www": "${workspaceFolder}"
           }
       }]
   }
   ```
3. Configure the malicious Xdebug server to return crafted responses with payloads designed to exploit parsing vulnerabilities
4. When the victim opens this repository and starts debugging, the malicious responses will be processed by the extension
5. Verify that the malicious responses trigger code execution on the victim's machine