# Updated Vulnerabilities List

## Vulnerability Name: Arbitrary Command Execution via Malicious Prepublish Script  

**Description:**  
An attacker can craft a repository that supplies a manipulated package manifest (package.json) in which the "vscode:prepublish" script is defined with a malicious command. When a victim uses the VS Code Extension packaging tool (vsce) on that repository, the tool automatically checks for and executes the prepublish script. Because the process is spawned with the shell enabled (i.e. using `shell: true`), any command defined by the attacker will be executed with the full privileges of the victim's user account.  

The attack steps are as follows:  
1. The attacker creates a repository whose package.json includes a "scripts" section with a "vscode:prepublish" key set to an arbitrary system command.  
2. The manipulated repository is then distributed, for example by making it publicly available.  
3. The unsuspecting victim downloads or checks out the repository and runs "vsce package" to build or publish the extension.  
4. The vsce tool detects the prepublish script and invokes it via a child process with `shell: true`, thereby executing the malicious command.  
5. As a result, the attacker gains the ability to run arbitrary commands on the victim's machine.  

**Impact:**  
Successful exploitation allows an attacker to execute arbitrary system commands on the victim's machine. This could lead to complete system compromise, data loss or corruption, and lateral movement within the network.  

**Vulnerability Rank:**  
Critical  

**Currently Implemented Mitigations:**  
- The project checks for a prepublish script in the manifest (in the prepublish function in the packaging module) but then unconditionally spawns the process with `shell: true`.  
- No additional confirmation, sandbox isolation, or sanitization of the script's contents is performed.  

**Missing Mitigations:**  
- **Explicit User Confirmation:** Require an explicit opt‑in or warning before executing any repository‑supplied prepublish script.  
- **Sandboxing/Isolation:** Run the prepublish script in a sandboxed or restricted environment to limit its potential damage.  
- **Strict Validation/Whitelisting:** Implement validation rules or a whitelist of allowed commands so that only known‐safe scripts are executed.  

**Preconditions:**  
- The victim must run vsce (or use it as a library) on a repository whose package.json contains a "vscode:prepublish" script.  
- The repository must be untrusted or have been manipulated so that the prepublish script contains arbitrary system commands.  

**Source Code Analysis:**  
- In the packaging code (found in `/code/src/package.ts`), the function that handles prepublish checks whether the manifest's "scripts" object contains a "vscode:prepublish" entry.  
- When a prepublish script is found, the tool decides whether to use yarn or npm and then logs a message indicating it is about to execute the script.  
- It then calls a child‑process spawn operation (e.g. using `cp.spawn(tool, ['run', 'vscode:prepublish'], { cwd, shell: true, stdio: 'inherit' })`).  
- Because the script command from package.json is passed directly into the spawn call and because `shell: true` is used, any malicious command contained in the prepublish script is interpreted by the shell and executed, causing an RCE vulnerability.  

**Security Test Case:**  
1. **Prepare a Malicious Repository:**  
   - Create a new repository (or test folder) and add a package.json that includes a "scripts" section similar to:  
     ```json
     {
       "name": "malicious-extension",
       "version": "0.0.1",
       "scripts": {
         "vscode:prepublish": "calc"  // (On Windows, for example. On Linux, you might use: "touch /tmp/pwned")
       }
     }
     ```  
   - Add any minimal content needed for an extension.  
2. **Run the Packaging Command:**  
   - In a terminal, navigate to the repository folder and run:  
     ```
     vsce package
     ```  
   - Observe that vsce detects the "vscode:prepublish" script and logs a message indicating that it is executing the script.  
3. **Verify Command Execution:**  
   - On Windows, check that Calculator launches or, on Linux, verify that the file `/tmp/pwned` is created.  
4. **Document the Outcome:**  
   - Confirm that the prepublish script was executed automatically without additional user confirmation.