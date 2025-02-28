# Vulnerabilities

## Unsafe Workspace Runtime Configuration Leading to Remote Code Execution

**Description:**  
A threat actor can supply a manipulated repository (for example, via a malicious pull or cloned workspace) that includes a customized VSCode workspace configuration (such as in a `.vscode/settings.json` file) where the key `"intelephense.runtime"` is set to a malicious value (for example, the path to an attacker‑controlled executable). When the extension activates, it reads this unvalidated configuration value and passes it directly into the language server launch process. Because the runtime value is used without any additional sanitization or whitelisting, an attacker–supplied value can cause the language server process to execute under a malicious runtime or even be substituted with a custom binary that executes arbitrary commands.

**Impact:**  
If exploited, this vulnerability would allow a remote attacker (via a malicious repository) to force the extension to spawn a child process with a runtime of the attacker's choosing. This, in effect, constitutes remote code execution (RCE) on the victim's machine under the permissions of the user running VSCode. The attacker could, for example, execute arbitrary shell commands, modify files, or further compromise the host.

**Vulnerability Rank:**  
High

**Currently Implemented Mitigations:**  
• The extension reads configuration using `workspace.getConfiguration('intelephense')` and uses the values directly.  
• There is no additional check or sanitization step against a whitelist of allowed runtime executables in the source code.

**Missing Mitigations:**  
• Validate the value of `"intelephense.runtime"` by:
  - Enforcing that only approved runtime executables (for example, only `node` or explicitly allowed paths) are accepted.
  - Ignoring or overriding workspace‑provided values in favor of user‑level (trusted) settings.
  - Sanitizing and rejecting unexpected characters or paths that could lead to command injection.
• Consider adding logging and warnings when a non‑default runtime is specified, so that the user is alerted to possible tampering via workspace settings.

**Preconditions:**  
• The victim opens a repository that contains a malicious `.vscode/settings.json` (or any workspace‑level configuration file) where `"intelephense.runtime"` is set to an attacker‑controlled value (for example, a path pointing to a malicious executable or script).  
• The extension is reloaded/activated and reads this configuration without any further user validation.

**Source Code Analysis:**  
1. In `extension.ts`, the function `createClient` retrieves extension configuration with:  
   ```ts
   let intelephenseConfig = workspace.getConfiguration('intelephense');
   let runtime = intelephenseConfig.get('runtime') as string | undefined;
   ```
   – At this point, the value of `"runtime"` is completely under the control of the workspace configuration (which can be checked in a repository).

2. Immediately after, the code does:
   ```ts
   if (runtime) {
       serverOptions.run.runtime = runtime;
       serverOptions.debug.runtime = runtime;
   }
   ```
   – Here the unvalidated `runtime` value is injected directly into the options used when spawning the language server process.
  
3. The language client (from the vscode-languageclient library) will use these options to start a new process:
   ```ts
   languageClient = new LanguageClient('intelephense', 'intelephense', serverOptions, clientOptions);
   ```
   – Because no sanitization or whitelisting is performed, an attacker can control which executable is run.

4. **Visualization:**  
   - **Step 1:** Attacker supplies a repository with a `.vscode/settings.json` that contains:
     ```json
     {
       "intelephense.runtime": "/tmp/malicious.sh"
     }
     ```
   - **Step 2:** On activation, the extension calls `workspace.getConfiguration('intelephense')` and retrieves the attacker‑controlled value.
   - **Step 3:** The extension passes this value directly to `serverOptions.run.runtime` (and its debug equivalent).
   - **Step 4:** When the language server spawns, it runs `/tmp/malicious.sh`, executing arbitrary code with the victim's privileges.

**Security Test Case:**  
1. **Setup a Malicious Repository:**  
   - Create or modify a `.vscode/settings.json` in a test repository with the following entry:
     ```json
     {
       "intelephense.runtime": "/path/to/a/script_that_logs_or_executes_commands.sh"
     }
     ```
   – Ensure that the test script (for example, `/path/to/a/script_that_logs_or_executes_commands.sh`) is accessible and, when executed, performs an observable action (such as creating a file or writing to a log).

2. **Open the Workspace in VSCode:**  
   - Open the test repository in VSCode so that the workspace settings are loaded.
  
3. **Activate the Extension:**  
   - Allow the Intelephense extension to activate (or manually trigger a re–activation by running the "Intelephense: Index Workspace" command).
  
4. **Observation:**  
   - Verify that the language server spawns using the malicious runtime. Check the victim machine for the expected evidence of the script execution (for example, a file created by the script or logs written).
  
5. **Validation:**  
   - Confirm that without mitigation the malicious executable is invoked.  
   - Then, apply a mitigation (such as enforcing a whitelist) and repeat the test to ensure the malicious value is rejected or ignored.