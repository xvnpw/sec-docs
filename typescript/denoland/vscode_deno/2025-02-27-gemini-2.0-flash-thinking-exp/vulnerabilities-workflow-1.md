## Vulnerability List:

- Vulnerability Name: Command Injection in Deno CLI Tasks and Debugger Configuration

- Description:
    The Deno VSCode extension constructs command-line arguments for Deno CLI commands such as `upgrade`, `test`, and debug configurations based on user settings like `deno.unstable`, `deno.testArgs`, `deno.importMap`, and `deno.config`. If these settings are maliciously crafted, it's possible to inject additional command-line arguments leading to command injection. An attacker could potentially execute arbitrary code on the user's machine by manipulating these settings.

    Steps to trigger vulnerability:
    1.  Configure the `deno.codeLens.testArgs` setting in VSCode to include malicious command arguments. For example, set `deno.codeLens.testArgs` to `["--allow-all", "; touch /tmp/pwned ;"]`.
    2.  Open a Deno project in VSCode.
    3.  Run a test using the "Run Test" code lens.
    4.  The injected command `; touch /tmp/pwned ;` will be executed by the system, in addition to the intended Deno test command.

- Impact:
    Successful command injection can allow an attacker to execute arbitrary commands on the user's machine with the privileges of the VSCode process. This could lead to data exfiltration, installation of malware, or complete system compromise.

- Vulnerability Rank: critical

- Currently implemented mitigations:
    None. The extension directly uses user-provided settings to construct command-line arguments without proper sanitization or validation.

- Missing mitigations:
    - Input sanitization: All user-provided settings used to construct command-line arguments should be sanitized to prevent injection. Specifically, settings like `deno.codeLens.testArgs`, `deno.testing.args`, `deno.unstable` (list format), `deno.importMap`, and `deno.config` should be carefully validated and sanitized.
    - Argument quoting: When constructing command-line arguments, ensure that arguments are properly quoted to prevent shell interpretation of special characters.
    - Principle of least privilege: While not a direct mitigation for command injection, running Deno CLI processes with the least necessary privileges can limit the impact of a successful injection.

- Preconditions:
    - The user must have the Deno VSCode extension installed and enabled.
    - The user must open a workspace where Deno is enabled.
    - The attacker needs to be able to influence VSCode settings, either by directly modifying the workspace settings file (if the attacker has write access to the workspace) or by convincing the user to import malicious settings (e.g., through a malicious workspace or project).

- Source code analysis:

    1. **`test` command injection:**
        - File: `/code/client/src/commands.ts`
        - Function: `test`
        - Code snippet:
          ```typescript
          const testArgs: string[] = [
            ...(config.get<string[]>("codeLens.testArgs") ?? []),
          ];
          const unstable = config.get("unstable") as string[] ?? [];
          for (const unstableFeature of unstable) {
            const flag = `--unstable-${unstableFeature}`;
            if (!testArgs.includes(flag)) {
              testArgs.push(flag);
            }
          }
          // ...
          const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
          ```
          Visualization:
          ```
          User Setting "deno.codeLens.testArgs" --> config.get("codeLens.testArgs") --> testArgs array --> ...testArgs in args array --> ProcessExecution args
          ```
          The `testArgs` array is directly populated from the `deno.codeLens.testArgs` user setting. This array is then spread into the `args` array for `ProcessExecution` without any sanitization. An attacker can inject arbitrary command arguments via `deno.codeLens.testArgs`.

    2. **`upgrade` command injection:**
        - File: `/code/client/src/upgrade.ts`
        - Function: `denoUpgradePromptAndExecute`
        - Code snippet:
          ```typescript
          const args = ["upgrade"];
          const unstable = config.get("unstable") as string[] ?? [];
          for (const unstableFeature of unstable) {
            args.push(`--unstable-${unstableFeature}`);
          }
          if (isCanary) {
            args.push("--canary");
          }
          args.push("--version");
          args.push(latestVersion);
          // ...
          const definition: tasks.DenoTaskDefinition = {
            type: tasks.TASK_TYPE,
            command: "upgrade",
            args, // args array is used here
            env,
          };
          ```
          Visualization:
          ```
          User Setting "deno.unstable" --> config.get("unstable") --> unstable array --> args.push(`--unstable-${unstableFeature}`) --> args array --> definition.args --> buildDenoTask args
          ```
          Similar to the `test` command, the `args` array for the `upgrade` command is constructed using the `deno.unstable` user setting without sanitization, leading to potential command injection.

    3. **Debug Configuration Command Injection:**
        - File: `/code/client/src/debug_config_provider.ts`
        - Function: `#getAdditionalRuntimeArgs` and `provideDebugConfigurations`
        - Code Snippet:
          ```typescript
          #getAdditionalRuntimeArgs() {
            const args: string[] = [];
            const settings = this.#extensionContext.clientOptions
              .initializationOptions();
            if (settings.unstable) { // settings.unstable comes from "deno.unstable" setting
              args.push("--unstable");
            }
            if (settings.importMap) { // settings.importMap comes from "deno.importMap" setting
              args.push("--import-map");
              args.push(settings.importMap.trim());
            }
            if (settings.config) { // settings.config comes from "deno.config" setting
              args.push("--config");
              args.push(settings.config.trim());
            }
            return args;
          }

          async provideDebugConfigurations(): Promise<vscode.DebugConfiguration[]> {
            // ...
            runtimeArgs: [
              "run",
              ...this.#getAdditionalRuntimeArgs(), // args from user settings
              this.#getInspectArg(),
              "--allow-all",
            ],
            // ...
          }
          ```
          Visualization:
          ```
          User Settings "deno.unstable", "deno.importMap", "deno.config" --> settings object --> #getAdditionalRuntimeArgs() --> args array --> runtimeArgs in debug configuration
          ```
          The debug configuration's `runtimeArgs` are constructed using user settings `deno.unstable`, `deno.importMap`, and `deno.config` without sanitization, making it vulnerable to command injection.

- Security test case:

    1. **Test Command Injection:**
        - Open VSCode with the Deno extension installed and enabled.
        - Create a new workspace or open an existing one. Enable Deno for this workspace if it's not already enabled.
        - Open the workspace settings (File -> Preferences -> Settings or Code -> Settings -> Settings).
        - In the settings search bar, type "deno.codeLens.testArgs".
        - Edit the `deno.codeLens.testArgs` setting and add a malicious command injection payload. For example, set it to `["--allow-all", "; touch /tmp/pwned_test_injection ;"]` (on Linux/macOS) or `["--allow-all", "& echo pwned_test_injection > C:\\pwned_test_injection.txt &"]` (on Windows).
        - Create a simple Deno test file (e.g., `test.ts`) in your workspace:
          ```typescript
          import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

          Deno.test("simple test", () => {
            assertEquals(1, 1);
          });
          ```
        - Open the `test.ts` file in the editor.
        - Observe the "▶ Run Test" code lens above the `Deno.test` declaration.
        - Click on "▶ Run Test".
        - After the test execution (which should succeed), check if the injected command has been executed. For example, check if the file `/tmp/pwned_test_injection` exists on Linux/macOS or if `C:\pwned_test_injection.txt` exists and contains "pwned_test_injection" on Windows. If the file is created, the command injection is successful.

    2. **Upgrade Command Injection:**
        - Open VSCode with the Deno extension installed and enabled.
        - Open the workspace settings.
        - In the settings search bar, type "deno.unstable".
        - Change `deno.unstable` to a list of strings, and add a malicious command injection payload to the list. For example, set it to `["sloppy-imports", "; touch /tmp/pwned_upgrade_injection ;"]` (Linux/macOS) or `["sloppy-imports", "& echo pwned_upgrade_injection > C:\\pwned_upgrade_injection.txt &"]` (Windows).
        - In VSCode command palette (Ctrl+Shift+P or Cmd+Shift+P), type and execute "Deno: Upgrade".
        - After the upgrade process, check if the injected command has been executed. For example, check if the file `/tmp/pwned_upgrade_injection` exists on Linux/macOS or if `C:\pwned_upgrade_injection.txt` exists and contains "pwned_upgrade_injection" on Windows. If the file is created, the command injection is successful.

    3. **Debug Configuration Command Injection:**
        - Open VSCode with the Deno extension installed and enabled.
        - Open the workspace settings.
        - In the settings search bar, type "deno.importMap".
        - Set `deno.importMap` to a malicious value that injects a command. For example, set it to `; touch /tmp/pwned_debug_injection ;` (Linux/macOS) or `& echo pwned_debug_injection > C:\\pwned_debug_injection.txt &` (Windows).
        - Create or open a Deno file (e.g., `main.ts`).
        - Create a debug configuration for Deno (Run and Debug -> Create Configuration -> Deno: Launch Program).
        - Start debugging.
        - After the debugger starts (or fails to start due to the injected command), check if the injected command has been executed. For example, check if the file `/tmp/pwned_debug_injection` exists on Linux/macOS or if `C:\pwned_debug_injection.txt` exists and contains "pwned_debug_injection" on Windows. If the file is created, the command injection is successful.