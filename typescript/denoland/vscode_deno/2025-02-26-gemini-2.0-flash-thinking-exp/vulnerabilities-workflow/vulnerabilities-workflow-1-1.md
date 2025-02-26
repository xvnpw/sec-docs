### Vulnerability List

- Vulnerability Name: Command Injection via `deno.codeLens.testArgs` in Test Code Lens
- Description:
    1. The VSCode extension allows users to configure additional arguments for test code lenses through the `deno.codeLens.testArgs` setting.
    2. When a user clicks "Run Test" code lens, the extension executes a Deno CLI command to run the test.
    3. The arguments specified in `deno.codeLens.testArgs` are directly passed to the `deno test` command without proper sanitization.
    4. A malicious user can inject arbitrary shell commands by crafting a malicious payload in the `deno.codeLens.testArgs` setting.
    5. When the "Run Test" code lens is executed, the injected commands will be executed by the system.
- Impact: Arbitrary command execution on the user's machine with the privileges of the VSCode process. This can lead to data exfiltration, malware installation, or complete system compromise.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The extension directly uses the configured arguments without any sanitization.
- Missing Mitigations:
    - Sanitize or validate user-provided arguments in `deno.codeLens.testArgs` to prevent command injection.
    - Avoid using shell execution for tasks and use safer alternatives if possible.
    - Display a warning to the user when using `deno.codeLens.testArgs` about the security implications.
- Preconditions:
    - The user must have the Deno VSCode extension installed and enabled.
    - The user must configure a malicious payload in the `deno.codeLens.testArgs` setting.
    - The user must click the "Run Test" code lens for a test in a Deno project.
- Source Code Analysis:
    1. Open `/code/client/src/commands.ts`.
    2. Examine the `test` function.
    3. Observe how `testArgs` is constructed:
        ```typescript
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []),
        ];
        ```
        This line retrieves the array of strings from the `deno.codeLens.testArgs` configuration setting and directly spreads it into the `testArgs` array. There is no sanitization or validation of these arguments.
    4. The `testArgs` array is then used to construct the command executed by `vscode.tasks.executeTask`:
        ```typescript
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args,
          env,
        };
        // ...
        const task = tasks.buildDenoTask(
          workspaceFolder,
          denoCommand,
          definition,
          `test "${name}"`,
          args,
          ["$deno-test"],
        );
        task.presentationOptions = { /* ... */ };
        task.group = vscode.TaskGroup.Test;
        const createdTask = await vscode.tasks.executeTask(task);
        ```
        The `args` array, which includes unsanitized `testArgs`, is passed to `tasks.buildDenoTask`.
    5. Open `/code/client/src/tasks.ts`.
    6. Examine the `buildDenoTask` function:
        ```typescript
        export function buildDenoTask(
          target: vscode.WorkspaceFolder,
          process: string,
          definition: DenoTaskDefinition,
          name: string,
          args: string[],
          problemMatchers: string[],
        ): vscode.Task {
          const exec = new vscode.ProcessExecution(
            process,
            args,
            definition,
          );

          return new vscode.Task(
            definition,
            target,
            name,
            TASK_SOURCE,
            exec,
            problemMatchers,
          );
        }
        ```
        The `args` parameter is directly passed to `vscode.ProcessExecution`. `ProcessExecution` executes the command using the system shell, which is vulnerable to command injection if arguments are not properly sanitized.

    7. **Visualization:**

    ```mermaid
    graph LR
        A[User configures deno.codeLens.testArgs] --> B(vscode.workspace.getConfiguration("deno").get("codeLens.testArgs"));
        B --> C{commands.test function};
        C --> D[Construct testArgs array with user input];
        D --> E[Construct args array for Deno CLI with testArgs];
        E --> F{tasks.buildDenoTask};
        F --> G(vscode.ProcessExecution with unsanitized args);
        G --> H[System Shell executes command with injected commands];
    ```
- Security Test Case:
    1. Open VSCode with the Deno extension installed and enabled.
    2. Open a Deno project or create a simple Deno project with a test file (e.g., `test.ts`):
        ```typescript
        import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

        Deno.test("simple test", () => {
          assertEquals(1, 1);
        });
        ```
    3. Open VSCode settings (Ctrl+, or Cmd+,).
    4. Go to Workspace Settings and search for "deno.codeLens.testArgs".
    5. Edit the `deno.codeLens.testArgs` setting and add a malicious payload. For example, to execute `calc.exe` on Windows or `gnome-calculator` on Linux, use:
        ```json
        "deno.codeLens.testArgs": [
            "--allow-all",
            "; calc.exe ;" // Windows example - replace with " ; gnome-calculator ;" for Linux/macOS
        ]
        ```
        or for a more harmful test, to create a file in the root of the workspace:
         ```json
        "deno.codeLens.testArgs": [
            "--allow-all",
            "; touch injected.txt ;"
        ]
        ```
    6. Save the settings.
    7. Open the `test.ts` file.
    8. Locate the "▶ Run Test" code lens above the `Deno.test` declaration.
    9. Click the "▶ Run Test" code lens.
    10. Observe that `calc.exe` (or `gnome-calculator` or `injected.txt` creation) is executed, demonstrating command injection.