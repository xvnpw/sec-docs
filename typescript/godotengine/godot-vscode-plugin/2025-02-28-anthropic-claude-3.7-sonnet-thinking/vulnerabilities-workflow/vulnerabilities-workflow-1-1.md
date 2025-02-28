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