# Docker Extension Security Vulnerabilities

## 1. Command Injection via Certificate Paths in .NET Debugging

- **Description**: The extension processes certificate paths from project files without proper sanitization when launching debugging sessions for .NET applications. An attacker can craft a malicious project file with certificate paths containing command injection payloads.
  
- **Impact**: Remote code execution on the victim's machine. An attacker can execute arbitrary system commands with the privileges of the VSCode process.

- **Vulnerability Rank**: Critical

- **Currently Implemented Mitigations**: None identified in the codebase.

- **Missing Mitigations**: Input validation and sanitization for certificate paths before they're used in command construction.

- **Preconditions**: Victim must open a malicious repository containing crafted project files and attempt to debug a .NET application with the Docker extension.

- **Source Code Analysis**: In the debugging process for .NET applications, the extension reads certificate paths from project files and passes them to command construction without proper sanitization. When a user opens a malicious repository and starts debugging, the extension reads the certificate path from the project file, constructs a command with this path, and executes it. Since the certificate path is not sanitized, if it contains shell metacharacters like `; rm -rf /` or `$(malicious command)`, these will be executed by the shell when the command is run.

- **Security Test Case**: 
  1. Create a malicious repository with a .NET project file
  2. Edit the project file to include a certificate path with command injection payload like `cert.pfx;calc.exe`
  3. Push the repository to a public Git hosting service
  4. Send the repository link to the victim
  5. When the victim opens the repository and attempts to debug the .NET application with Docker extension, the malicious command will execute on their machine

## 2. Command Injection via Unsanitized AppOutput in ASP.NET Core HTTPS Certificate Export

- **Description**: A malicious repository (for example, one with a manipulated .csproj file) can supply an unexpected value for the project's output directory. When the VS Code Docker extension is used to configure debugging for an ASP.NET Core application with HTTPS enabled, a helper function extracts the "appOutput" string from the project and then calls Node's path‑parsing utilities. That value is later interpolated into a shell command that invokes certificate export via the .NET CLI. If an attacker has injected shell metacharacters within the "appOutput" value, the constructed command may break out of its original quoting context, allowing execution of arbitrary OS commands under the privileges of the VS Code process.

- **Impact**: An attacker who embeds malicious content into a project file can force the VS Code extension to execute arbitrary commands on the host system with the VS Code process's privileges. This risk is especially serious in development environments where elevated privileges may be present.

- **Vulnerability Rank**: Critical

- **Currently Implemented Mitigations**:
  • Use of Node's built‑in path‑joining and parsing functions when processing the "appOutput" property.  
  • However, the final value is still directly interpolated into a shell command string without proper sanitization or safe argument passing.

- **Missing Mitigations**:
  • **Input Validation/Escaping:** The "appOutput" value should be strictly validated and/or sanitized to allow only expected directory name characters.  
  • **Safe Command Invocation:** Instead of building a full command string for execution in the shell, use an API such as child_process.spawn with an argument array.  
  • **Boundary Checking:** Enforce precise character and format restrictions, so that shell metacharacters are not passed through.

- **Preconditions**: The victim opens a repository that contains a malicious .csproj (or similar) file with a crafted "appOutput" property that includes shell metacharacters. The certificate export helper is invoked during the process of establishing HTTPS debugging for an ASP.NET Core application.

- **Source Code Analysis**: In the ASP.NET Core HTTPS debug helper, the "appOutput" property is read from the project file without additional validation. Although Node's path‑parsing functions are used, the value is later directly inserted into a shell command string used to run the .NET CLI for certificate export. As a result, any metacharacters present in "appOutput" are interpreted by the shell, enabling command injection.

- **Security Test Case**:
  1. **Create a Malicious Project File:**
     • Commit a .csproj file into a test repository whose "appOutput" property is set to a value such as:
       ```
       normalOutput"; echo "CERT_INJECTED"; #
       ```
       (During testing, use a harmless command like echo.)
  2. **Inject the Modified Project File:**
     • Ensure the repository contains the malicious .csproj file.
  3. **Open the Repository in VS Code:**
     • In a controlled environment, open the repository so the extension processes the project file.
  4. **Trigger Certificate Export:**
     • Start debugging (or otherwise trigger HTTPS certificate export).
  5. **Verify Execution:**
     • Monitor shell output or system logs for evidence (e.g. the output "CERT_INJECTED") that the injected command has been executed.

## 3. Remote Code Execution via Malicious Server Ready Action Pattern

- **Description**: The server ready action feature allows specifying regex patterns to detect when a server is ready by monitoring logs. An attacker can craft a pattern that uses regex capture groups to extract and execute dangerous content from the logs.

- **Impact**: Remote code execution. When logs containing crafted content are processed, the regex pattern can extract and execute malicious commands.

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**: None identified in the codebase.

- **Missing Mitigations**: Sanitization or validation of regex patterns used in server ready actions.

- **Preconditions**: Victim must open a malicious repository with a crafted debug configuration that includes a malicious server ready action pattern.

- **Source Code Analysis**: The serverReadyAction functionality in the extension allows for specifying patterns to detect when a server is ready. These patterns are processed as regex and can include capture groups. The extension extracts content matched by these capture groups and can use it in command execution contexts. An attacker can craft a pattern that specifically captures and executes malicious content from logs, leading to arbitrary code execution.

- **Security Test Case**:
  1. Create a malicious repository with a launch.json file containing a crafted debug configuration
  2. Include a serverReadyAction with a pattern designed to capture and execute code, such as one that triggers command execution via regex backreferences
  3. Push the repository to a public Git hosting service
  4. Send the repository link to the victim
  5. When the victim opens the repository and starts a debug session, the malicious pattern will process logs and potentially execute injected commands

## 4. Command Injection via Container File Path Manipulation

- **Description**: When accessing files in containers, the extension constructs commands using file paths without adequate sanitization. An attacker can create container files with names containing command injection payloads.

- **Impact**: Remote code execution on the victim's machine through the injection of malicious commands.

- **Vulnerability Rank**: Critical

- **Currently Implemented Mitigations**: None identified in the codebase.

- **Missing Mitigations**: Proper escaping and sanitization of file paths before using them in command construction.

- **Preconditions**: Victim must open a malicious repository containing a Docker configuration that references containers with specially crafted file paths.

- **Source Code Analysis**: The extension uses file paths from containers to construct commands that are executed on the host system. These file paths are not properly sanitized before being included in command strings. An attacker can create files with names containing command injection payloads (e.g., "; rm -rf / #") inside a container. When the victim interacts with these files through the extension, the malicious commands embedded in the filename will be executed.

- **Security Test Case**:
  1. Create a malicious Docker image that contains files with names designed for command injection
  2. Create a repository with Docker configurations that reference this malicious image
  3. Include files in the container with names like `file;calc.exe;.txt`
  4. Push the repository to a public Git hosting service
  5. Send the repository link to the victim
  6. When the victim opens the repository and interacts with the container files through the extension, the malicious commands will execute on their system

## 5. Command Injection via Malicious .NET Project File Path in Dotnet Build Command

- **Description**: The extension uses a helper function (exported in the module for .NET SDK tasks) to retrieve project properties—such as when updating Blazor static web assets. In this function (see *netCoreUtils.ts*), a dotnet build command is dynamically constructed by interpolating several parameters, including the absolute file path of the detected project (obtained via user selection or auto‑detection). If an attacker supplies a repository containing a .csproj (or .fsproj) file with a malicious name (for example, one embedding double quotes, semicolons, or other shell metacharacters), the unsanitized file path is interpolated into a command string of the form:
  ```
  dotnet build /r:false /t:GetProjectProperties … "${project}"
  ```
  Because the file path is only wrapped in quotes without proper escaping, a crafted file name can break out of the intended quoting context and inject arbitrary commands into the shell command.

- **Impact**: Exploitation of this vulnerability results in remote code execution on the host machine with the privileges of the VS Code extension process. An attacker could execute arbitrary shell commands which might lead to data compromise, lateral movement, or privilege escalation.

- **Vulnerability Rank**: Critical

- **Currently Implemented Mitigations**:
  • Most command inputs (e.g. target, output file, and additional properties) are wrapped in quotes.
  • However, the project file path is interpolated directly (without proper sanitization or escaping) into the command string.

- **Missing Mitigations**:
  • **Input Sanitization/Escaping:** Ensure that the project file path is cleansed of dangerous characters (such as quotes, semicolons, ampersands, etc.) prior to insertion into the command.
  • **Safe Command Execution:** Use APIs (e.g. child_process.spawn with an argument array) that pass arguments safely to avoid shell interpretation.
  • **Whitelist Validation:** Restrict file names to expected safe characters (alphanumerics, periods, dashes, underscores).

- **Preconditions**: An attacker commits a repository with a maliciously named .csproj (or .fsproj) file that contains shell metacharacters. The victim opens that repository in VS Code so that the extension auto‑detects or the user manually selects the malicious project file. An operation (such as retrieving project properties to update the Blazor manifest) is triggered, leading to execution of the dotnet build command.

- **Source Code Analysis**: In *netCoreUtils.ts*, the command string is built as:
  ```
  const command = `dotnet build /r:false /t:${target} /p:CustomAfterMicrosoftCommonTargets="${targetsFile}" /p:CustomAfterMicrosoftCommonCrossTargetingTargets="${targetsFile}" /p:InfoOutputPath="${outputFile}" ${additionalProperties || ''} "${project}"`;
  ```
  The variable `project` is obtained (via helper functions such as NetCoreTaskHelper.inferAppProject) based on user input or repository auto‑detection, and is not sanitized. Because the file name is directly inserted into the command string and executed with `execAsync` (using shell: true), any embedded shell metacharacters are interpreted, permitting command injection.

- **Security Test Case**:
  1. **Prepare a Malicious Repository:**
     • In a test repository, create (or rename) a .csproj (or .fsproj) file so that its absolute file name includes a payload. For example, name it as:
       ```
       testProject"; echo "INJECTED_PAYLOAD"; sleep 1; echo "
       ```
       (Use a benign command like echo during testing.)
  2. **Open the Repository in VS Code:**
     • Launch VS Code and open the repository so that the extension auto‑detects/selects the malicious project file.
  3. **Trigger the Affected Operation:**
     • Perform an action (for example, starting a debugging session that leads to updating the Blazor manifest) that invokes the dotnet build command.
  4. **Monitor the Command Output:**
     • Check the terminal or extension logs for evidence that the injected command (e.g. `echo "INJECTED_PAYLOAD"`) was executed.
  5. **Confirm Exploitation:**
     • The appearance of the test output confirms that the malicious file name led to command injection.