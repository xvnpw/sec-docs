---

**• Vulnerability Name:**  
Command Injection via Unquoted Argument Expansion in askpass.sh

**• Description:**  
When Git needs a user’s credentials the extension (via Git) invokes an askpass helper script to provide a password prompt. In the file `/code/src/askpass/askpass.sh`, the prompt arguments provided (via the shell’s positional parameters) are expanded using the unquoted `$*`. This means that if an attacker can influence the text of the prompt—by, for example, causing a Git operation to supply a malicious string containing shell metacharacters (such as a semicolon followed by an injected command)—the shell will perform word splitting and interpret the extra words as separate commands. In a step-by-step scenario, an attacker might:

1. **Manipulate the prompt:**  
   Influence the environment (for example, by providing a malicious remote URL or leveraging a man‑in-the-middle attack) so that when Git triggers a credentials request the prompt string includes shell metacharacters (e.g. a string like  
   `normal_prompt ; malicious_command`).

2. **Trigger the askpass script:**  
   Git calls the askpass script with the crafted prompt as its parameter. The script then expands the parameters using the unquoted `$*` in the command line:
   ```
   VSCODE_GIT_GRAPH_ASKPASS_PIPE=`mktemp`
   VSCODE_GIT_GRAPH_ASKPASS_PIPE="$VSCODE_GIT_GRAPH_ASKPASS_PIPE" "$VSCODE_GIT_GRAPH_ASKPASS_NODE" "$VSCODE_GIT_GRAPH_ASKPASS_MAIN" $*
   cat $VSCODE_GIT_GRAPH_ASKPASS_PIPE
   rm $VSCODE_GIT_GRAPH_ASKPASS_PIPE
   ```
   Because the `$*` is not quoted, any injected metacharacters (such as a semicolon) can break out of the intended argument context.

3. **Execute injected command:**  
   The shell interprets the injected semicolon as a command separator. This leads to the node-based command (expected to safely retrieve credentials) being terminated early, with the injected malicious command executed afterward.

**• Impact:**  
Exploitation of this vulnerability would allow an attacker to execute arbitrary commands with the privileges of the user running the Git Graph extension. This could lead to a full system compromise, data exfiltration, and severe loss of integrity.

**• Vulnerability Rank:**  
Critical

**• Currently Implemented Mitigations:**  
• There is no sanitization or proper quoting of the prompt arguments in the askpass helper script; the code relies entirely on external guarantees (i.e. that the prompt argument is benign).  
• The environment variables (`VSCODE_GIT_GRAPH_ASKPASS_NODE` and `VSCODE_GIT_GRAPH_ASKPASS_MAIN`) are assumed to hold safe paths, but no additional validation is performed.

**• Missing Mitigations:**  
• The script should use `"$@"` (which preserves argument boundaries) instead of the unquoted `$*` to prevent unwanted word splitting and interpretation of shell metacharacters.  
• Input received from any external source (even indirectly through Git’s prompt mechanism) should be validated and sanitized before being passed as parameters to another command.  
• Consider refactoring the command invocation so that the Node command is built using a safe API (or wrapper) that avoids shell interpretation of constructable strings.

**• Preconditions:**  
• The attacker must be able to influence the content of the prompt argument passed to the askpass script (for example via remote repository configuration manipulation or a man‑in‑the-middle attack on the Git client’s credential request).  
• The extension is configured to use this particular askpass script for handling Git credentials.

**• Source Code Analysis:**  
1. **Temporary File Creation:**  
   The script begins by creating a temporary file using:
   ```
   VSCODE_GIT_GRAPH_ASKPASS_PIPE=`mktemp`
   ```
   This file is intended to be used as a communication pipe.
2. **Command Execution with Unquoted Parameters:**  
   The very next line:
   ```
   VSCODE_GIT_GRAPH_ASKPASS_PIPE="$VSCODE_GIT_GRAPH_ASKPASS_PIPE" "$VSCODE_GIT_GRAPH_ASKPASS_NODE" "$VSCODE_GIT_GRAPH_ASKPASS_MAIN" $*
   ```
   sets an environment variable and then calls the command stored in `VSCODE_GIT_GRAPH_ASKPASS_NODE` with the main script and additional parameters. Notice that `$*` is unquoted—this causes the shell to perform word splitting on the incoming arguments. Should one of these arguments include a semicolon or other shell metacharacters (for example, injected via a manipulated Git prompt), they will be interpreted as additional commands.
3. **Output and Cleanup:**  
   The script then continues by using:
   ```
   cat $VSCODE_GIT_GRAPH_ASKPASS_PIPE
   rm $VSCODE_GIT_GRAPH_ASKPASS_PIPE
   ```
   If an attacker manages to inject an unwanted command after the semicolon, the shell would execute that before these cleanup commands.

**• Security Test Case:**  
1. **Preparation:**  
   • In a controlled test environment, set the environment variables `VSCODE_GIT_GRAPH_ASKPASS_NODE` (for example, point it to a benign executable or a test double) and `VSCODE_GIT_GRAPH_ASKPASS_MAIN` as needed.  
   • Ensure that the test does not affect a production system.
2. **Execution with Malicious Input:**  
   • Invoke the askpass script with a deliberately crafted prompt argument that contains a shell metacharacter injection. For example:
   ```
   ./askpass.sh "NormalPrompt" "; echo INJECTION_SUCCESS"
   ```
3. **Observation:**  
   • Monitor the output and system logs to check if the injected command (`echo INJECTION_SUCCESS`) is executed outside the intended Node command.  
   • Verify that with the current implementation the shell will treat the semicolon as a command separator.
4. **Remediation Verification:**  
   • Modify the script to use `"$@"` instead of unquoted `$*`. Re-run the test input to confirm that the injected command is no longer executed.

---