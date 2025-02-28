# Vulnerabilities Analysis

## Command Injection via Project Directory in open_workspace_with_editor

**Description:** 
The `open_workspace_with_editor` function in `src/common.ts` uses `cp.exec` with `shell: true` and directly inserts the `project_dir` into the command string without sanitization. If an attacker can trick a victim into opening a repository with a path containing shell metacharacters (like `;`, `&&`, `|`), they can execute arbitrary commands on the victim's system.

**Impact:** 
High - Allows remote code execution on the victim's system with the privileges of the VSCode process.

**Vulnerability rank:** High

**Currently implemented mitigations:** None

**Missing mitigations:** 
The code should either avoid using `shell: true` or properly sanitize the `project_dir` before inserting it into the command string.

**Preconditions:**
- The victim must open a malicious repository in VSCode with this extension installed.
- The repository path must contain shell metacharacters.

**Source code analysis:**
In `src/common.ts`, the `open_workspace_with_editor` function is defined as:

```typescript
export function open_workspace_with_editor(
  project_dir: string,
  editor_path: string
) {
  if (process.platform === "win32") {
    cp.exec(`"${editor_path}" --path "${project_dir}"`, { shell: true });
  } else {
    cp.exec(`"${editor_path}" --path "${project_dir}"`, { shell: true });
  }
}
```

This function is called when the user invokes the "godot.open-editor" command.

The vulnerability arises because:
1. `cp.exec` is called with `shell: true`, which means the command is executed in a shell.
2. `project_dir` is directly inserted into the command string without sanitization.
3. If `project_dir` contains shell metacharacters, they will be interpreted by the shell.

For example, if `project_dir` is `harmless" && calc.exe"`, the command executed on Windows would be:
`"[editor_path]" --path "harmless" && calc.exe"`, which would execute both the Godot editor and the calculator.

**Security test case:**
1. Create a repository with a path containing shell metacharacters, e.g., `/tmp/test";touch /tmp/pwned;"`.
2. Open this repository in VSCode with the Godot Tools extension installed.
3. Invoke the "Open in Godot Editor" command.
4. Verify that the command after the shell metacharacter (`touch /tmp/pwned` in this case) was executed.

## Command Injection via Project Directory in Language Server Process

**Description:** 
In `src/lsp.ts`, the language server process is spawned with `shell: true`, and the `workspace_path` is directly added to the arguments without sanitization. If an attacker can trick a victim into opening a repository with a path containing shell metacharacters, they can execute arbitrary commands on the victim's system.

**Impact:** 
High - Allows remote code execution on the victim's system with the privileges of the VSCode process.

**Vulnerability rank:** High

**Currently implemented mitigations:** None

**Missing mitigations:** 
The code should either avoid using `shell: true` or properly sanitize the `workspace_path` before adding it to the arguments.

**Preconditions:**
- The victim must open a malicious repository in VSCode with this extension installed.
- The repository path must contain shell metacharacters.

**Source code analysis:**
In `src/lsp.ts`, the language server process is spawned with:

```typescript
let server_options: ServerOptions = {
  run: {
    command: language_server_path,
    args: language_server_args,
    options: {
      env: process.env,
      shell: true,
    },
  },
  debug: {
    command: language_server_path,
    args: debug_args,
    options: {
      env: process.env,
      shell: true,
    },
  },
};
```

And `language_server_args` is constructed with:

```typescript
const language_server_args = [
  "--headless",
  "--script=" + language_script,
];

// ...

if (workspace_path) {
  language_server_args.push("--path");
  language_server_args.push(workspace_path);
}
```

The vulnerability arises because:
1. The language server process is spawned with `shell: true`.
2. `workspace_path` is directly added to the arguments without sanitization.
3. If `workspace_path` contains shell metacharacters, they will be interpreted by the shell.

For example, if `workspace_path` is `/malicious/path;evil_command`, the command executed would include `--path /malicious/path;evil_command`, which would execute both the intended command and `evil_command`.

**Security test case:**
1. Create a repository with a path containing shell metacharacters, e.g., `/tmp/test;touch /tmp/pwned`.
2. Open this repository in VSCode with the Godot Tools extension installed.
3. Verify that the language server is started.
4. Verify that the command after the shell metacharacter (`touch /tmp/pwned` in this case) was executed.

## Command Injection via Unsanitized Workspace/Project Paths in External Process Launch

**Description:**
The extension constructs a full shell command string used to launch the Godot editor by embedding several values obtained from the workspace (and/or from launch configuration values) without proper escaping or sanitization. In Godot 4's server controller, for example, the command is built using the Godot executable path (from settings or launch.json), the project path (from args.project) and later appended with additional information such as breakpoints. An attacker who provides a malicious repository (or launch configuration) may manipulate the folder name or project file path (for example by including embedded quotes and shell metacharacters) to inject extra commands.

**Step by step how to trigger:**
1. An attacker crafts a repository in which the folder name or the "project.godot" file path is manipulated to include a closing double-quote followed by extra shell commands (e.g.  
   ```
   MyProject" && malicious_command && echo "
   ```  
   ).  
2. The attacker distributes this repository (for example, via a public GitHub repo).  
3. When the victim opens the repository in VSCode, the extension (whether using Godot 3 or Godot 4 code paths) picks up the manipulated path and embeds it into the command string.  
4. The final command (for example,  
   ```
   "C:\Path\To\Godot.exe" --path "MyProject" && malicious_command && echo " --remote-debug "tcp://..."
   ```  
   ) is passed to a child process using an option with `shell: true`, and the injected command executes with the same privileges as VSCode.  

**Impact:**
This vulnerability permits arbitrary command execution on the victim's machine. An attacker may thus execute any command (or install malware) with the same permissions as the user running the editor.

**Vulnerability rank:** Critical

**Currently implemented mitigations:**
• The individual dynamic values (such as the Godot executable path and the project path) are wrapped in quotes when inserted into the command string.  
• No further escaping or validation is applied to these workspace-derived values.

**Missing mitigations:**
• Proper input validation and sanitization of any variable (e.g. workspace folder name, project file path) that is embedded in a shell command.  
• Use of APIs that allow passing arguments as an array (thereby avoiding shell interpolation) rather than building and invoking a full command string via the shell.

**Preconditions:**
• The victim must open a repository where one or more directory names (or the location of the "project.godot" file) have been maliciously crafted.  
• The user must trigger the command (either via "launch" or "debug" mode) that builds the external command string for the Godot editor.

**Source code analysis:**
In both `/code/src/debugger/godot3/server_controller.ts` and `/code/src/debugger/godot4/server_controller.ts` the functions that launch the game process construct a command string as follows:  
```ts
let command = `"${godotPath}" --path "${args.project}"`;
…  
if (args.additional_options) {
  command += ` ${args.additional_options}`;
}
```
and in the Godot 4 version the code also later handles a custom scene parameter. Because neither the project path nor its derived parts are further sanitized, an attacker can inject additional shell operators into the command string.

**Security test case:**
1. Create a test repository whose folder name (or whose "project.godot" file's directory) contains an injection payload such as:  
   ```
   TestProject" && echo INJECTED && sleep 5 && echo "
   ```  
2. Ensure the repository contains a valid "project.godot" file so that the extension uses the manipulated path.  
3. Open the repository in VSCode with the extension installed.  
4. Execute the command that launches the Godot editor.  
5. Monitor the spawned terminal; if the output displays the injected "echo INJECTED" (or if any other injected behavior is observed), command injection is confirmed.

## Command Injection via Unsanitized "Additional Options" in Debug Launch Configuration

**Description:**
When launching a debug session, the extension builds a shell command for starting the game process. It directly appends the content of a field named `"additional_options"` obtained from the launch configuration into the command string without any sanitization.

**Step by step how to trigger:**
1. An attacker commits a malicious `launch.json` file in a repository that includes a debug configuration.  
2. This configuration sets `"additional_options"` to a value containing shell metacharacters (for example:  
   ```json
   "additional_options": "; malicious_command && echo INJECTED &&"
   ```  
   ).  
3. The victim opens the repository in VSCode and starts a debug session which uses that configuration.  
4. During the launch sequence, the extension concatenates the unsanitized `"additional_options"` into the command.  
5. As the command string is executed by a new process with `shell: true`, the injected payload (here, `malicious_command` and the subsequent echo) is executed.

**Impact:**
This vulnerability allows an attacker to execute arbitrary commands with the privileges of the user running the debugger, which could lead to system compromise.

**Vulnerability rank:** Critical

**Currently implemented mitigations:**
• The code wraps other parts of the command string in quotes but does not apply any sanitization or validation to the value of `"additional_options"`.

**Missing mitigations:**
• Perform thorough validation and escaping of the `"additional_options"` field before concatenating it into the shell command, or better yet, pass arguments as an array to avoid shell interpretation.

**Preconditions:**
• The attacker must supply a malicious `launch.json` file that is included in the repository opened by the victim in VSCode.  
• The victim must then initiate a debug session using that corrupted configuration.

**Source code analysis:**
In both the Godot 3 and Godot 4 debugger server controllers (for example in `/code/src/debugger/godot3/server_controller.ts` and `/code/src/debugger/godot4/server_controller.ts`), after the base command is built the following check occurs:  
```ts
if (args.additional_options) {
  command += ` ${args.additional_options}`;
}
```  
No filtering or escaping is performed, so shell metacharacters are interpreted by the underlying shell when the command is executed using options such as `{ shell: true, detached: true }`.

**Security test case:**
1. Create a debug launch configuration in `launch.json` with the `"additional_options"` field set to a payload like:  
   ```json
   "additional_options": "; echo INJECTED && sleep 2 && echo \""
   ```  
2. Open the project with this configuration in VSCode.  
3. Start a debug session using the configuration.  
4. Observe the output in the debug terminal—if you see "INJECTED" printed (or any other outcome of the injected command), the vulnerability is successfully exploited.

## Command Injection via Unsanitized Scene Parameter in Game Launch Command (Godot 4)

**Description:**
In Godot 4's server controller, when launching the game process a custom scene parameter may be provided using the `"scene"` field in the launch configuration. If the value of `"scene"` is neither "main" nor a reserved keyword (like `"current"` or `"pinned"`), it is treated as a file path and is simply wrapped in quotes and appended to the launch command. However, because no further sanitization is performed, a malicious scene name containing embedded quotes and shell control characters can break out of the quoted context and inject arbitrary commands.

**Step by step how to trigger:**
1. An attacker creates a launch configuration (for example in `launch.json`) where the `"scene"` attribute is set to a crafted payload such as:  
   ```
   "scene": "malicious.tscn\" && echo INJECTED && sleep 5 && echo \""
   ```  
2. If the scene argument is not "current" or "pinned", the controller directly assigns this string to a local variable `filename` and later appends it to the command as follows:  
   ```ts
   command += ` "${filename}"`;
   ```  
3. When the victim opens the repository in VSCode and starts the game process, the manipulated scene value is embedded into the final command.  
4. The shell parses the command so that the injected commands are executed.

**Impact:**
This vulnerability permits an attacker to gain arbitrary code execution on the victim's machine by manipulating the scene file parameter. An attacker may use this to run arbitrary commands or malware, compromising the user's system.

**Vulnerability rank:** Critical

**Currently implemented mitigations:**
• The scene filename (whether taken directly from the `"scene"` field or derived from "current"/"pinned" values) is wrapped in double quotes before being added to the command, but no additional sanitization is done.

**Missing mitigations:**
• Implement input validation to ensure that the scene filename does not contain any dangerous characters (such as embedded quotes or shell metacharacters).  
• Use a method of launching the process in which parameters are passed as separate arguments (avoiding shell interpolation) or properly escape all dynamic values before concatenation.

**Preconditions:**
• The victim must open a repository whose launch configuration includes a malicious `"scene"` value, and that value must not be one of the special keywords that trigger alternate handling.  
• The victim then starts a game session using that configuration in VSCode.

**Source code analysis:**
In `/code/src/debugger/godot4/server_controller.ts`, the following code block handles the scene parameter:  
```ts
if (args.scene && args.scene !== "main") {
  log.info(`Custom scene argument provided: ${args.scene}`);
  let filename = args.scene;
  if (args.scene === "current") {
    // derive filename from the active editor …
  }
  if (args.scene === "pinned") {
    // derive filename from the pinned scene …
  }
  command += ` "${filename}"`;
}
```  
Here, the value of `args.scene` (or the derived filename) is embedded directly into the command without any sanitization. An attacker who controls the repository can provide a scene name that breaks out of the intended string context, thereby injecting additional shell commands.

**Security test case:**
1. Create a launch configuration in a test repository where the `"scene"` field is set to  
   ```
   malicious.tscn" && echo INJECTED && sleep 5 && echo "
   ```  
2. Ensure that this configuration is used to start a game session in Godot 4.  
3. Open the repository in VSCode and trigger the game launch command.  
4. Observe the output in the spawned terminal; if the injected command (e.g. an echo of "INJECTED") executes, the vulnerability is confirmed.