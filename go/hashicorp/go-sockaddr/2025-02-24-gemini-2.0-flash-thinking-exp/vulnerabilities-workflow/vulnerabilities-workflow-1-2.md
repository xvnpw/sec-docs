- **Vulnerability Name**: Unvalidated Environment PATH in Windows Route Lookup
  - **Description**:
    The Windows‑specific route‐lookup code (in file `route_info_windows.go`) calls external commands using unsanitized command names. In particular, the cmds map defines entries such as:
    - `"defaultInterface": {"powershell", "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | select -ExpandProperty InterfaceAlias"}`
    - `"netstat": {"netstat", "-rn"}`
    - `"ipconfig": {"ipconfig"}`
    When the application calls the function `GetDefaultInterfaceName()`, it invokes
    ```go
    exec.Command(cmds["defaultInterface"][0], cmds["defaultInterface"][1:]...).Output()
    ```
    which uses the system’s PATH to locate executables such as “powershell” (or in fallback, “netstat” and “ipconfig”). An attacker who can influence the PATH (for example, in a mis‑configured or shared/containerized environment) may cause a malicious binary (with the same file name) to be found and executed.
    **Step by step how to trigger it**:
    1. The attacker arranges for the process environment to include a PATH value whose first directory is under attacker control.
    2. In that directory the attacker plants an executable named “powershell.exe” (or “netstat.exe”/“ipconfig.exe”) that performs a malicious action (for example, spawning a shell or exfiltrating data).
    3. When the Windows‑specific route lookup is triggered (for example, via the CLI command or API call that calls `GetDefaultInterfaceName()`), the malicious binary is invoked instead of the trusted system binary.
    4. This results in arbitrary code execution within the context of the running process.

  - **Impact**:
    Arbitrary code execution (and thereby complete process/system compromise) is possible on Windows whenever the application relies on route lookup functionality without securely setting its execution environment. This is especially dangerous if the application runs with elevated privileges.

  - **Vulnerability Rank**: Critical

  - **Currently Implemented Mitigations**:
    The cmds map uses fixed command‐line arguments; however, the names of the executables (e.g. “powershell”, “netstat”, “ipconfig”) are not provided as absolute paths and are therefore subject to PATH search.

  - **Missing Mitigations**:
    - Specify absolute paths to the binaries instead of relying on PATH (for example, use `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` on Windows).
    - Alternatively, clear, sanitize, or explicitly override the PATH environment variable before calling `exec.Command()`.
    - Optionally, verify the signature or ownership of the located binary before execution.

  - **Preconditions**:
    - The application runs on a Windows system where the PATH environment variable is not securely managed.
    - An attacker is able to influence (or has misconfigured) the process’s environment (for example, via a container or compromised startup script).
    - The route‐lookup functionality (for example, via the “rfc” or “tech-support” commands) is invoked.

  - **Source Code Analysis**:
    - In **route_info_windows.go** the commands are defined without absolute paths. For instance:
      ```go
      var cmds map[string][]string = map[string][]string{
         "defaultInterface": {"powershell", "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | select -ExpandProperty InterfaceAlias"},
         "netstat":  {"netstat", "-rn"},
         "ipconfig": {"ipconfig"},
      }
      ```
    - The call to `exec.Command(cmds["defaultInterface"][0], cmds["defaultInterface"][1:]...).Output()` relies on the PATH to resolve “powershell”.
    - There is no sanitization or overwriting of the calling environment’s PATH variable before this call.

  - **Security Test Case**:
    1. In a controlled Windows test environment, create a temporary directory (e.g. `C:\temp\malicious_bin`) and place a benign “malicious” executable named exactly “powershell.exe” that, for test purposes, writes a distinctive marker file (or outputs a unique string) to a predictable location.
    2. Prepend this directory to the PATH environment variable for the process (for example, by setting `PATH=C:\temp\malicious_bin;...` before launching the application).
    3. Invoke the route lookup functionality (for instance, run the command that calls `GetDefaultInterfaceName()` either via the “rfc” command or “tech-support” command).
    4. Verify that the output or side‑effect comes from the malicious “powershell.exe” rather than the genuine system binary.
    5. Confirm that this behavior demonstrates arbitrary command execution due to unsanitized PATH lookup.

- **Vulnerability Name**: Unrestricted Template Evaluation Leading to Information Disclosure
  - **Description**:
    The library’s template package (in `template/template.go`) provides an evaluation function (via `Parse` and `ParseIfAddrsTemplate`) to allow dynamic extraction and formatting of network interface information. The function maps registered with the template engine include sensitive data–retrieval functions such as:
    - `GetAllInterfaces`
    - `GetDefaultInterfaces`
    - `GetPrivateInterfaces`
    - `GetPublicInterfaces`

    If an attacker is able to supply an arbitrary template string (for example, through an exposed “eval” API or CLI endpoint), they can invoke these functions to output detailed internal network configuration including IP addresses, interface names, and possibly hardware addresses.

    **Step by step how to trigger it**:
    1. The attacker submits a malicious template string such as:
       ```
       {{ GetAllInterfaces }}
       ```
       or a more crafted template that extracts and joins specific attributes from the available interfaces.
    2. The template evaluation function (e.g. the `eval` command implemented in `cmd/sockaddr/command/eval.go`) wraps the input (unless the raw mode is specified) and passes it to the `text/template` engine along with a data set generated by calling `GetAllInterfaces()`.
    3. The constructed template is executed, and because the allowed function map is not restricted, it returns detailed network‐related information that was not intended for public disclosure.
    4. The attacker receives this output, thereby gaining sensitive information about the host’s network configuration.

  - **Impact**:
    Unauthorized disclosure of sensitive network configuration data can occur. An attacker can learn the IP addresses and interface details of the host, which may facilitate further internal network reconnaissance or lateral movement.

  - **Vulnerability Rank**: High

  - **Currently Implemented Mitigations**:
    - The library uses Go’s built‑in `text/template` package with the option `missingkey=error`, which prevents accidental consumption of undefined data.
    - However, the supplied function maps (including SourceFuncs, SortFuncs, FilterFuncs, and HelperFuncs) expose functions that return comprehensive network interface data.
    - There is no built‑in restriction with respect to who may supply the template input.

  - **Missing Mitigations**:
    - Restrict the function map available for template evaluation when the input originates from untrusted sources (for example, remove or limit access to functions that return sensitive network information).
    - Authenticate and authorize any endpoint or CLI option that exposes template evaluation.
    - Validate or sanitize template input to ensure that only expected or low‑sensitivity expressions are processed.

  - **Preconditions**:
    - The application (or a service using this library) exposes the template evaluation functionality (for example, via the “eval” command or a web/API endpoint) to untrusted users.
    - An attacker is able to supply arbitrary template input.

  - **Source Code Analysis**:
    - In **template/template.go**, the `Parse` function calls:
      ```go
      tmpl, err := tmplIn.Option("missingkey=error").
          Funcs(SourceFuncs).
          Funcs(SortFuncs).
          Funcs(FilterFuncs).
          Funcs(HelperFuncs).
          Parse(input)
      ```
    - The function map `SourceFuncs` includes functions that retrieve complete network interface details (e.g. `GetAllInterfaces`).
    - There is no check or sanitization on the template string to block the use of sensitive functions.

  - **Security Test Case**:
    1. Set up a test instance of the application (or a minimal program using the template package) that calls `template.Parse` with the function map provided by the library.
    2. Supply a template string such as:
       ```
       {{ GetAllInterfaces }}
       ```
       or a more refined expression that extracts, for instance, interface names and addresses.
    3. Execute the template evaluation and capture the output.
    4. Verify that the output reveals sensitive network interface details (e.g. IP addresses, netmasks, interface names).
    5. Confirm that without additional input validation or restrictions the template injection leads to unauthenticated disclosure of host network configuration.