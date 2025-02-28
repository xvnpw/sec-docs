# Vulnerabilities in VSCode Deno Extension

## 1. Malicious Deno Path Injection Leading to Remote Code Execution

**Description:**  
The extension obtains the Deno executable's location from the workspace setting "deno.path" (via a call in `getWorkspaceConfigDenoExePath`) and, if not absolute, resolves it relative to each workspace folder. No verification is performed to check whether the file at that path is indeed the authentic Deno CLI. An attacker can supply a workspace configuration (for example, via a malicious repository's `.vscode/settings.json`) that sets `"deno.path": "./malicious_executable"`. Furthermore, the attacker can package a malicious executable within the repository. When the victim opens the repository in VS Code, the extension will resolve the relative path, detect that the file exists, and then launch it (with arguments such as `["lsp"]`).

**Impact:**  
Arbitrary code execution on the victim's machine. If the malicious executable is run in place of the expected Deno binary, the payload may run with the same privileges as the victim's user, leading to a full compromise of the system.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**  
• The extension checks for the existence of the file via a call to `fileExists` before using it.

**Missing Mitigations:**  
• No validation is done to verify that the "deno.path" setting points to a genuine Deno CLI executable (for example, by checking its version output or digital signature).  
• No restrictions are applied on accepting relative paths from the workspace.

**Preconditions:**  
• The attacker must supply a repository that includes a malicious `.vscode/settings.json` file with a "deno.path" key pointing to a malicious executable (possibly included in the repository itself).  
• The victim must open this repository in VS Code with the extension activated so that the configuration is read and applied.

**Source Code Analysis:**  
• In `client/src/util.ts`, the function `getDenoCommandPath` calls `getWorkspaceConfigDenoExePath` which retrieves the "deno.path" value directly from the workspace configuration.  
• If the path is relative, the function iterates the workspace folders and uses `path.resolve` to obtain an absolute path. The only check is via asynchronous `fileExists` (using `fs.stat`) to confirm the file exists.  
• Later in `client/src/extension.ts`, the language server is started using the returned path as the executable (via `ProcessExecution` with the argument `["lsp"]`). No further sanity checks are performed on the resolved executable.

**Security Test Case:**  
1. Create a test repository that includes a file `.vscode/settings.json` with the following content:  
   ```json
   {
     "deno.path": "./malicious_executable"
   }
   ```  
2. Include in the repository an executable file named "malicious_executable" that, when run, performs a visible action (for example, launching an unexpected application or writing to a known file to simulate a payload).  
3. Open the repository in VS Code with the Deno extension enabled.  
4. Observe that the extension calls `getDenoCommandPath`, resolves the relative path, and then launches the malicious executable rather than the expected Deno binary.  
5. Verify that the payload runs (e.g., the unexpected application opens, or the marker file is created).

## 2. Malicious Environment Variable Injection via Deno Extension Configuration Leading to Remote Code Execution

**Description:**  
The extension merges user‐provided environment variables from the workspace configuration (read via settings such as "deno.env") into the environment passed to spawned processes (for example, when launching the language server or executing tasks). Because the settings are read directly from configuration files (which can be distributed in a repository) and no sanitization or filtering is applied, an attacker can supply dangerous environment variables such as `LD_PRELOAD` (on Linux) or its counterparts on other platforms. When the extension launches the external process (e.g. the Deno CLI with "lsp" or during task execution), these malicious environment variables are inherited by the child process and may cause dynamic libraries to be preloaded or otherwise alter the process behavior in a manner that leads to arbitrary code execution.

**Impact:**  
The attacker can force the spawned Deno process to load an arbitrary (malicious) shared library or otherwise tamper with its runtime behavior—resulting in remote code execution under the victim's user account.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**  
• The extension merely merges the "env" settings from the configuration (in files such as `.vscode/settings.json`) using methods like `Object.assign`; it does not perform any sanitization.

**Missing Mitigations:**  
• No validation is carried out to filter out risky environment variable keys (for example, those known to alter dynamic linking such as `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, etc.).  
• There is no check to confirm that the environment variables provided by the workspace configuration are benign.

**Preconditions:**  
• The attacker must supply a repository that includes a `.vscode/settings.json` file with an "env" property containing one or more dangerous environment variables (for example:  
   ```json
   {
     "env": {
       "LD_PRELOAD": "./malicious.so"
     }
   }
   ```  
   ).  
• The attacker must also supply the malicious shared library (e.g. "malicious.so") within the repository.  
• The victim must open the repository in VS Code so that the configuration is loaded.

**Source Code Analysis:**  
• In `client/src/upgrade.ts` as well as in `client/src/testing.ts`, the extension calls  
   ```js
   const denoEnv = config.get<Record<string, string>>("env");
   if (denoEnv) {
     Object.assign(env, denoEnv);
   }
   ```  
   This code merges user‐provided environment variables into the environment object that is passed to the Deno process via ProcessExecution.  
• No filtering or sanitization is applied to the keys or values of the "env" object.

**Security Test Case:**  
1. Create a test repository that includes a `.vscode/settings.json` file with the following content:  
   ```json
   {
     "env": {
       "LD_PRELOAD": "./malicious.so"
     }
   }
   ```  
2. Include in the repository a file "malicious.so" that (for testing purposes) performs an observable action when preloaded (for example, logging a message or causing a visible change on the system).  
3. Open the repository in VS Code with the Deno extension enabled—and trigger an action that causes the extension to spawn the Deno language server or run an upgrade/test task.  
4. Monitor the spawned process to verify that it receives the dangerous environment variable and that the payload provided by "malicious.so" executes.  
5. Confirm that this leads to the anticipated code execution (for example, by verifying the appearance of the marker action defined by the malicious library).