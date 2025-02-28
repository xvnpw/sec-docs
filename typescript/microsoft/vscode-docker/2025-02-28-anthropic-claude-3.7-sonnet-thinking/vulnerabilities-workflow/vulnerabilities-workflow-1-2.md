# High-Risk Command Injection Vulnerabilities

## Command Injection via Unsanitized AppOutput in ASP.NET Core HTTPS Certificate Export

- **Vulnerability Name:**  
  Command Injection via Unsanitized AppOutput in ASP.NET Core HTTPS Certificate Export

- **Description:**  
  A malicious repository (for example, one with a manipulated .csproj file) can supply an unexpected value for the project's output directory. When the VS Code Docker extension is used to configure debugging for an ASP.NET Core application with HTTPS enabled, a helper function extracts the "appOutput" string from the project and then calls Node's path‑parsing utilities. That value is later interpolated into a shell command that invokes certificate export via the .NET CLI. If an attacker has injected shell metacharacters within the "appOutput" value, the constructed command may break out of its original quoting context, allowing execution of arbitrary OS commands under the privileges of the VS Code process.

- **Impact:**  
  An attacker who embeds malicious content into a project file can force the VS Code extension to execute arbitrary commands on the host system with the VS Code process's privileges. This risk is especially serious in development environments where elevated privileges may be present.

- **Vulnerability Rank:**  
  Critical

- **Currently Implemented Mitigations:**  
  • Use of Node's built‑in path‑joining and parsing functions when processing the "appOutput" property.  
  • However, the final value is still directly interpolated into a shell command string without proper sanitization or safe argument passing.

- **Missing Mitigations:**  
  • **Input Validation/Escaping:** The "appOutput" value should be strictly validated and/or sanitized to allow only expected directory name characters.  
  • **Safe Command Invocation:** Instead of building a full command string for execution in the shell, use an API such as child_process.spawn with an argument array.  
  • **Boundary Checking:** Enforce precise character and format restrictions, so that shell metacharacters are not passed through.

- **Preconditions:**  
  • The victim opens a repository that contains a malicious .csproj (or similar) file with a crafted "appOutput" property that includes shell metacharacters.  
  • The certificate export helper is invoked during the process of establishing HTTPS debugging for an ASP.NET Core application.

- **Source Code Analysis:**  
  • In the ASP.NET Core HTTPS debug helper, the "appOutput" property is read from the project file without additional validation.  
  • Although Node's path‑parsing functions are used, the value is later directly inserted into a shell command string used to run the .NET CLI for certificate export.  
  • As a result, any metacharacters present in "appOutput" are interpreted by the shell, enabling command injection.

- **Security Test Case:**  
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

## Command Injection via Malicious .NET Project File Path in Dotnet Build Command

- **Vulnerability Name:**  
  Command Injection via Malicious .NET Project File Path in Dotnet Build Command

- **Description:**  
  The extension uses a helper function (exported in the module for .NET SDK tasks) to retrieve project properties—such as when updating Blazor static web assets. In this function (see *netCoreUtils.ts*), a dotnet build command is dynamically constructed by interpolating several parameters, including the absolute file path of the detected project (obtained via user selection or auto‑detection). If an attacker supplies a repository containing a .csproj (or .fsproj) file with a malicious name (for example, one embedding double quotes, semicolons, or other shell metacharacters), the unsanitized file path is interpolated into a command string of the form:  
  ```
  dotnet build /r:false /t:GetProjectProperties … "${project}"
  ```  
  Because the file path is only wrapped in quotes without proper escaping, a crafted file name can break out of the intended quoting context and inject arbitrary commands into the shell command.

- **Impact:**  
  Exploitation of this vulnerability results in remote code execution on the host machine with the privileges of the VS Code extension process. An attacker could execute arbitrary shell commands which might lead to data compromise, lateral movement, or privilege escalation.

- **Vulnerability Rank:**  
  Critical

- **Currently Implemented Mitigations:**  
  • Most command inputs (e.g. target, output file, and additional properties) are wrapped in quotes.  
  • However, the project file path is interpolated directly (without proper sanitization or escaping) into the command string.

- **Missing Mitigations:**  
  • **Input Sanitization/Escaping:** Ensure that the project file path is cleansed of dangerous characters (such as quotes, semicolons, ampersands, etc.) prior to insertion into the command.  
  • **Safe Command Execution:** Use APIs (e.g. child_process.spawn with an argument array) that pass arguments safely to avoid shell interpretation.  
  • **Whitelist Validation:** Restrict file names to expected safe characters (alphanumerics, periods, dashes, underscores).

- **Preconditions:**  
  • An attacker commits a repository with a maliciously named .csproj (or .fsproj) file that contains shell metacharacters.  
  • The victim opens that repository in VS Code so that the extension auto‑detects or the user manually selects the malicious project file.  
  • An operation (such as retrieving project properties to update the Blazor manifest) is triggered, leading to execution of the dotnet build command.

- **Source Code Analysis:**  
  • In *netCoreUtils.ts*, the command string is built as:  
    ```
    const command = `dotnet build /r:false /t:${target} /p:CustomAfterMicrosoftCommonTargets="${targetsFile}" /p:CustomAfterMicrosoftCommonCrossTargetingTargets="${targetsFile}" /p:InfoOutputPath="${outputFile}" ${additionalProperties || ''} "${project}"`;
    ```  
  • The variable `project` is obtained (via helper functions such as NetCoreTaskHelper.inferAppProject) based on user input or repository auto‑detection, and is not sanitized.  
  • Because the file name is directly inserted into the command string and executed with `execAsync` (using shell: true), any embedded shell metacharacters are interpreted, permitting command injection.

- **Security Test Case:**  
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