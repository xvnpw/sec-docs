- vulnerability name: Command Injection in Debug Configurations via Program Arguments
- description: |
  The Dart debug adapter, specifically in `dart_debug_impl.ts`, allows users to define program arguments in debug configurations (`launch.json`). These arguments are passed directly to the Dart VM or Flutter command execution via `safeSpawn`. If a malicious workspace provides a crafted debug configuration with malicious arguments, it could lead to command injection when the user starts debugging with that configuration. This vulnerability is similar to "Command Injection in Flutter Task Provider via Task Arguments", but in the context of VS Code Debug Configurations.

  Step-by-step trigger:
  1. An attacker creates a malicious Dart/Flutter project.
  2. The attacker crafts a malicious debug configuration in `.vscode/launch.json` within the project. This debug configuration targets a Dart or Flutter launch type and injects malicious commands into the `args` array within the configuration. For example, for a Dart launch configuration:
     ```json
     {
         "version": "0.2.0",
         "configurations": [
             {
                 "name": "Dart-Code-Pwned",
                 "type": "dart",
                 "request": "launch",
                 "program": "bin/main.dart",
                 "args": [
                     "&& touch /tmp/dartcode_debug_pwned.txt"
                 ]
             }
         ]
     }
     ```
  3. The attacker distributes this malicious project (e.g., via a public repository or by tricking a user into downloading it).
  4. A victim user opens the malicious Dart/Flutter project in VSCode with the Dart Code extension installed.
  5. The victim user opens the Run and Debug view in VSCode (e.g., by clicking on the Run and Debug icon in the Activity Bar).
  6. The victim user selects the malicious debug configuration (e.g., "Dart-Code-Pwned") from the dropdown.
  7. The victim user starts debugging by clicking the "Start Debugging" button (or pressing F5).
  8. The Dart Code extension's debug adapter executes the Dart VM or Flutter command with the attacker-controlled arguments without proper sanitization.
  9. The injected commands (e.g., `&& touch /tmp/dartcode_debug_pwned.txt`) are executed on the victim's machine with the privileges of the VSCode process.
- impact: Arbitrary code execution on the machine running VSCode with the Dart Code extension. This could lead to full system compromise, data exfiltration, installation of malware, or any other malicious actions the attacker desires.
- vulnerability rank: critical
- currently implemented mitigations: None. The code directly uses the provided debug configuration arguments without any sanitization.
- missing mitigations:
  - Input sanitization: Implement robust input sanitization for program arguments in debug configurations in `DartDebugSession` and `FlutterDebugSession`. This should prevent the injection of shell commands or any potentially harmful characters.
  - Workspace Trust: Leverage VSCode's Workspace Trust feature to restrict the execution of debug configurations from untrusted workspaces. VSCode should prompt users to explicitly trust workspaces before allowing the execution of debug configurations defined within them.
  - User Confirmation: Before executing any debug configuration with custom program arguments, especially those defined in workspace configurations, display a prompt to the user, clearly warning about the potential security risks and asking for explicit confirmation to proceed.
  - Principle of Least Privilege: If custom debug configurations are absolutely necessary, consider running the debuggee in a sandboxed environment with restricted privileges to minimize the potential damage from malicious scripts.
- preconditions: |
  - The user must open a workspace that contains a malicious `.vscode/launch.json` file that defines a malicious debug configuration with command injection in the arguments or the user manually configures a debug configuration with malicious arguments.
  - The user must execute this malicious debug configuration through VSCode's debug system.
- source code analysis: |
  - `/code/src/debug/dart_debug_impl.ts`: The `launchRequest` method in `DartDebugSession` (and similarly in `FlutterDebugSession` and `WebDebugSession`) calls `spawnProcess` or `spawnRemoteEditorProcess` to start the debuggee process.
  - `/code/src/debug/dart_debug_impl.ts`: The `buildExecutionInfo` method is responsible for constructing the command line arguments for the spawned process. It takes arguments from `DartLaunchArgs`, including `args.args` which is derived from the `launch.json` configuration.
  - `/code/src/shared/processes.ts`: The `safeSpawn` function executes the command with the provided arguments. There is no sanitization of the arguments before being passed to `safeSpawn`.
  ```typescript
  // /code/src/debug/dart_debug_impl.ts
  protected async spawnProcess(args: DartLaunchArgs): Promise<SpawnedProcess> {
      let dartPath = path.join(args.dartSdkPath, dartVMPath);
      const execution = this.buildExecutionInfo(dartPath, args);
      dartPath = execution.executable;
      const appArgs = execution.args; // appArgs is constructed with user-controlled args

      this.log(`Spawning ${dartPath} with args ${JSON.stringify(appArgs)}`);
      if (args.cwd)
          this.log(`..  in ${args.cwd}`);
      const env = Object.assign({}, args.toolEnv, args.env);
      const process = safeSpawn(args.cwd, dartPath, appArgs, env); // Vulnerability: appArgs is not sanitized

      this.log(`    PID: ${process.pid}`);

      return process;
  }

  // /code/src/debug/dart_debug_impl.ts
  private buildExecutionInfo(binPath: string, args: DartLaunchArgs): ExecutionInfo {
      let allArgs: string[] = [];

      if (args.vmAdditionalArgs)
          allArgs = allArgs.concat(args.vmAdditionalArgs);

      // ... other args ...

      if (args.args) // Vulnerability: args.args from launch.json is used directly
          allArgs = allArgs.concat(args.args);

      return {
          args: allArgs,
          executable: execution.executable,
      };
  }
  ```
- security test case: |
  1. Create a malicious Dart project (e.g., `flutter create malicious_debug_project` or `dart create malicious_debug_project`).
  2. Navigate to the newly created project directory in your terminal.
  3. Create a `.vscode` directory inside the project root if it doesn't exist: `mkdir .vscode`
  4. Create a `launch.json` file inside the `.vscode` directory and add the following configuration for Dart project (for Flutter project change "type" to "flutter" and "program" to "lib/main.dart"):
  ```json
  {
      "version": "0.2.0",
      "configurations": [
          {
              "name": "Dart-Code-Pwned",
              "type": "dart",
              "request": "launch",
              "program": "bin/main.dart",
              "args": [
                  "&& touch /tmp/dartcode_debug_pwned.txt"
              ]
          }
      ]
  }
  ```
  5. Open the `malicious_debug_project` in VSCode with the Dart Code extension installed.
  6. Open the Run and Debug view in VSCode. You should see the "Dart-Code-Pwned" configuration.
  7. Select the "Dart-Code-Pwned" configuration and start debugging.
  8. After the debug session starts (and likely fails to run the actual program due to command injection), check if the file `/tmp/dartcode_debug_pwned.txt` has been created.
  9. If the file exists, the command injection vulnerability is confirmed. The malicious arguments in `launch.json` were successfully executed by the Dart Code extension when starting the debug session.

- vulnerability name: Command Injection in Flutter Task Provider via Task Arguments
- description: |
  The Flutter Task Provider in `flutter_task_provider.ts` allows users to define Flutter tasks with custom arguments. These arguments are passed directly to the `flutter` command execution. If a malicious workspace provides a crafted task definition with malicious arguments, it could lead to command injection when the user executes the task. This is similar to the "Command Injection via Custom Debug Scripts" vulnerability, but in the context of VS Code Tasks.

  Step-by-step trigger:
  1. An attacker creates a malicious Dart/Flutter project.
  2. The attacker crafts a malicious task definition in `.vscode/tasks.json` within the project. This task definition targets the `flutter` task type and injects malicious commands into the `args` array. For example:
     ```json
     {
        "version": "2.0.0",
        "tasks": [
            {
                "type": "flutter",
                "command": "flutter",
                "args": [
                    "build",
                    "apk",
                    "&& touch /tmp/dartcode_task_pwned.txt"
                ],
                "problemMatcher": []
            }
        ]
     }
     ```
  3. The attacker distributes this malicious project (e.g., via a public repository or by tricking a user into downloading it).
  4. A victim user opens the malicious Dart/Flutter project in VSCode with the Dart Code extension installed.
  5. The victim user opens the Tasks explorer in VSCode (e.g., by running "Tasks: Run Task").
  6. The victim user executes the malicious Flutter task defined in `.vscode/tasks.json`.
  7. The Dart Code extension's `FlutterTaskProvider` executes the `flutter` command with the attacker-controlled arguments without proper sanitization.
  8. The injected commands (e.g., `&& touch /tmp/dartcode_task_pwned.txt`) are executed on the victim's machine with the privileges of the VSCode process.
- impact: Arbitrary code execution on the machine running VSCode with the Dart Code extension. This could lead to full system compromise, data exfiltration, installation of malware, or any other malicious actions the attacker desires.
- vulnerability rank: critical
- currently implemented mitigations: None. The code directly uses the provided task arguments without any sanitization.
- missing mitigations:
  - Input sanitization: Implement robust input sanitization for task arguments in `FlutterTaskProvider`. This should prevent the injection of shell commands or any potentially harmful characters.
  - Workspace Trust: Leverage VSCode's Workspace Trust feature to restrict the execution of tasks from untrusted workspaces. VSCode should prompt users to explicitly trust workspaces before allowing the execution of tasks defined within them.
  - User Confirmation: Before executing any Flutter task with custom arguments, especially those defined in workspace tasks, display a prompt to the user, clearly warning about the potential security risks and asking for explicit confirmation to proceed.
  - Principle of Least Privilege: If custom tasks are absolutely necessary, consider running them in a sandboxed environment with restricted privileges to minimize the potential damage from malicious scripts.
- preconditions: |
  - The user must open a workspace that contains a malicious `.vscode/tasks.json` file that defines a malicious Flutter task with command injection in the arguments or the user manually configures a task with malicious arguments.
  - The user must execute this malicious Flutter task through VSCode's task system.
- source code analysis: |
  - `/code/src/extension/flutter/flutter_task_provider.ts`: The `createTask` method in `BaseTaskProvider` (extended by `FlutterTaskProvider`) is responsible for creating VS Code tasks. It takes arguments directly from the task definition and passes them to the `flutter` command.
  - `/code/src/extension/dart/dart_task_provider.ts`: The `createTask` function in `BaseTaskProvider` directly uses the provided `definition.args` to construct the `ProcessExecution`. There is no sanitization of these arguments.
  ```typescript
  // /code/src/extension/dart/dart_task_provider.ts
  protected createTask(workspaceFolder: vs.WorkspaceFolder, projectFolder: vs.Uri, command: string, args: string[], definition?: DartTaskDefinition): vs.Task {
      definition = definition || {
          args,
          command,
          projectPath: fsPath(projectFolder),
          type: this.type,
          workspaceFolder: workspaceFolder.name,
      };

      const task = new vs.Task(
          definition,
          workspaceFolder,
          definition.command,
          FlutterTaskProvider.type, // Incorrect, should be this.type, but not critical for vuln
          new vs.ProcessExecution(definition.command, definition.args, { // Vulnerability here: definition.args is not sanitized
              cwd: fsPath(projectFolder),
              env: this.getEnvVars(definition),
          }),
          definition.problemMatcher,
      );
      task.group = vs.TaskGroup.Build;
      return task;
  }
  ```
  - The `provideTasks` method in `FlutterTaskProvider` uses `createTask` to generate tasks based on predefined commands and arguments. However, if a user were to define their own tasks in `tasks.json` with type "flutter", these tasks would also be created using `createTask` and be vulnerable if malicious arguments are provided.
- security test case: |
  1. Create a malicious Flutter project (e.g., `flutter create malicious_flutter_task_project`).
  2. Navigate to the newly created project directory in your terminal.
  3. Create a `.vscode` directory inside the project root if it doesn't exist: `mkdir .vscode`
  4. Create a `tasks.json` file inside the `.vscode` directory and add the following configuration:
  ```json
  {
      "version": "2.0.0",
      "tasks": [
          {
              "type": "flutter",
              "command": "flutter",
              "args": [
                  "build",
                  "apk",
                  "&& touch /tmp/dartcode_task_pwned.txt"
              ],
              "problemMatcher": []
          }
      ]
  }
  ```
  5. Open the `malicious_flutter_task_project` in VSCode with the Dart Code extension installed.
  6. Open the Tasks explorer in VSCode (e.g., by running "Tasks: Run Task"). You should see a task named "flutter".
  7. Run the "flutter" task.
  8. After the task execution completes, check if the file `/tmp/dartcode_task_pwned.txt` has been created.
  9. If the file exists, the command injection vulnerability is confirmed. The malicious arguments in `tasks.json` were successfully executed by the Dart Code extension when running the Flutter task.