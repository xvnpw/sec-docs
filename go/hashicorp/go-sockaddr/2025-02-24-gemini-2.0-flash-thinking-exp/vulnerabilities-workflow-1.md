Here is the combined list of vulnerabilities, formatted as markdown:

## Combined Vulnerability List for go-sockaddr Project

This document consolidates identified vulnerabilities in the go-sockaddr project, combining information from multiple reports and removing duplicates. Each vulnerability is described in detail, including its potential impact, rank, mitigation status, and steps for verification.

### 1. Template Injection in `sockaddr eval` command

- **Vulnerability Name:** Template Injection in `sockaddr eval` command
- **Description:**
    The `sockaddr` CLI utility provides an `eval` command that evaluates "sockaddr templates". This command takes user-provided input as a template argument and processes it using Go's built-in `text/template` library via the `go-sockaddr/template` package. The `eval` command directly parses user-provided input as a Go template without any sanitization or input validation. If an attacker can control the template input, they can inject malicious template code that will be executed by the template engine.

    **Step by step how to trigger it:**
    1. **Attacker crafts a malicious template payload:** This payload can range from simple expressions to access environment variables (e.g., `{{ .Env.HOME }}`) to more complex payloads attempting to execute arbitrary system commands (e.g., `{{ syscall "os/exec".Command "whoami" }}`).
    2. **Attacker executes the `sockaddr eval` command:** The attacker provides the malicious template as an argument to the `sockaddr eval` command. For example: `sockaddr eval "{{ .Env.HOME }}"` or `sockaddr eval '{{ `whoami` }}'`.  Alternatively, if reading from stdin in raw mode: `echo '{{ `whoami` }}' | sockaddr eval -r -`.
    3. **Template parsing and evaluation:** The `eval` command parses the command-line arguments. Unless the `-r` flag is used, it wraps each argument with `{{` and `}}` to ensure it is treated as a template. This template string is then passed to `template.Parse` function from the `go-sockaddr/template` package.
    4. **Malicious code execution:** The `text/template` engine evaluates the crafted template. If the template is malicious, the injected code will be executed within the context of the `sockaddr` application.
    5. **Output and information disclosure:** The output of the template evaluation, which can include sensitive information (like environment variables, file contents, or command outputs) or the result of arbitrary code execution, is printed to the attacker's terminal.

- **Impact:**
    Successful template injection can lead to severe security breaches. Potential impacts include:
    - **Arbitrary Code Execution:** An attacker could potentially execute arbitrary commands on the server running `sockaddr`, gaining full control of the system.
    - **Information Disclosure:** Sensitive information such as environment variables (e.g., `HOME`, `PATH`, API keys, database credentials), internal network configurations, and even file contents could be disclosed to the attacker.
    - **Lateral Movement:** By gaining code execution or information about the network configuration, an attacker can potentially use this vulnerability as a stepping stone to further compromise the system or the internal network.

- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    There are no explicit mitigations implemented in the `cmd/sockaddr/command/eval.go` code or the `go-sockaddr/template` package to prevent template injection. The `eval` command directly passes user-provided input to the `template.Parse` function without any sanitization, validation, or output encoding. The security relies entirely on the inherent security of the `text/template` library when used with untrusted input, which is known to be vulnerable if not handled carefully.
- **Missing Mitigations:**
    - **Input Sanitization and Validation:** Implement robust input sanitization and validation for the template string provided to `sockaddr eval`. A whitelist approach for allowed template functions and variables would be the most secure mitigation. Consider escaping or removing potentially dangerous template directives and functions.
    - **Secure Template Engine Configuration:** Ensure that the template engine is configured securely. Consider using a sandboxed template engine or restrict the available functions within the template context to only those that are absolutely necessary and safe.
    - **Principle of Least Privilege:** Run the `sockaddr` command, and any application using the `go-sockaddr` library, with the least privileges necessary to minimize the impact of potential vulnerabilities.
    - **Output Encoding:**  Encode or sanitize template output to prevent unintended execution or interpretation of the output in downstream systems, although this is less relevant for template injection itself but good practice in general.

- **Preconditions:**
    - The `sockaddr` CLI utility must be installed and accessible to the attacker.
    - The attacker must be able to execute the `sockaddr eval` command with arbitrary template arguments. This is typically the case if the attacker has shell access to the system or if a higher-level application exposes the `sockaddr eval` functionality (directly or indirectly) to external users.

- **Source Code Analysis:**
    - **File: `/code/cmd/sockaddr/command/eval.go`**:
        ```go
        func (c *EvalCommand) Run(args []string) int {
            // ...
            tmpls, err := c.parseOpts(args) // args are from command line
            // ...
            for i, in := range tmpls {
                // ...
                if !rawInput {
                    in = `{{` + in + `}}` // wraps input with delimiters unless -r is used
                    inputs[i] = in
                }

                out, err := template.Parse(in) // Calls template.Parse with user input 'in'
                if err != nil {
                    c.Ui.Error(fmt.Sprintf("ERROR[%d] in: %q\n[%d] msg: %v\n", i, in, i, err))
                    return 1
                }
                outputs[i] = out
            }
            // ...
        }
        ```
        This code snippet from `eval.go` clearly demonstrates that the `Run` function takes command-line arguments (`args`) as input and processes them as templates.  The crucial point is the direct call to `template.Parse(in)` with the user-controlled input `in` without any preceding sanitization or validation. The code wraps the input in `{{ }}` delimiters unless the `-r` flag is used, further emphasizing that user input is intended to be treated as a template.

    - **File: `/code/template/template.go`**:
        ```go
        func ParseIfAddrsTemplate(input string) (*TemplateSet, error) {
            tmpl, err := template.New("ifaddrs").Option("missingkey=error").
                Funcs(SourceFuncs).
                Funcs(SortFuncs).
                Funcs(FilterFuncs).
                Funcs(HelperFuncs).
                Parse(input)
            if err != nil {
                return nil, err
            }
            return &TemplateSet{tmpl: tmpl}, nil
        }
        ```
        This code from `template.go` shows that the `go-sockaddr/template` package utilizes Go's built-in `text/template` library. The `ParseIfAddrsTemplate` function, and likely the `Parse` function used in `eval.go` (though not shown here directly, it's implied to use a similar setup), parses the input string as a template using `template.New().Parse(input)`. The `Funcs` calls add a set of functions (`SourceFuncs`, `SortFuncs`, `FilterFuncs`, `HelperFuncs`) to the template's function map, which are then accessible within the templates.  While these functions themselves might be internally safe, the core vulnerability lies in the `text/template` engine's susceptibility to injection when parsing untrusted input, and the `eval` command exposes this directly.

- **Security Test Case:**
    1. **Pre-requisite:** Install the `sockaddr` CLI utility.
    2. **Step 1: Craft a malicious template to leak the HOME environment variable:**
        ```
        {{ .Env.HOME }}
        ```
    3. **Step 2: Execute the `sockaddr eval` command with the crafted template:**
        ```bash
        sockaddr eval "{{ .Env.HOME }}"
        ```
    4. **Step 3: Observe the output:**
        - **Vulnerable:** If the output contains the path to the current user's home directory, it confirms successful template injection and environment variable access.
        - **Not Vulnerable (or Mitigated):** If the command fails, returns an error, or does not print the home directory, it suggests that template injection might be mitigated or not exploitable in this specific way. However, further testing with other payloads is recommended to confirm.
    5. **Step 4: (If Step 3 indicates vulnerability) Attempt command execution (Example payload, might require specific syntax depending on template engine and available functions):**
        ```bash
        sockaddr eval '{{ syscall "os/exec".Command "whoami" }}'
        ```
    6. **Step 5: Observe the output again:**
        - **Vulnerable (Critical):** If the output contains the result of the `whoami` command (e.g., the username), it indicates critical template injection leading to command execution.
        - **Vulnerable (Information Disclosure only):** If command execution fails but environment variable access worked, the vulnerability is still high risk for information disclosure.
        - **Not Vulnerable (or Mitigated):** If both attempts fail, further deeper analysis is needed to confirm security.

---

### 2. Unvalidated Environment PATH in Windows Route Lookup

- **Vulnerability Name**: Unvalidated Environment PATH in Windows Route Lookup
- **Description**:
    The Windows‑specific route lookup code in `route_info_windows.go` calls external commands using command names resolved via the system's PATH environment variable.  Specifically, the code uses `exec.Command` with commands like "powershell", "netstat", and "ipconfig" without specifying absolute paths.  If an attacker can influence the PATH environment variable, they can plant a malicious executable with the same name in a directory that appears earlier in the PATH, leading to the execution of the attacker's binary instead of the intended system utility.

    **Step by step how to trigger it**:
    1. **Attacker manipulates the PATH environment variable:** The attacker arranges for the process's environment to include a PATH value where the first directory is under their control. This might be achieved in misconfigured systems, shared environments, or containerized setups.
    2. **Attacker plants a malicious executable:** In the attacker-controlled directory, they place an executable file named "powershell.exe", "netstat.exe", or "ipconfig.exe". This malicious binary is designed to perform an action chosen by the attacker, such as spawning a reverse shell, exfiltrating data, or simply demonstrating arbitrary code execution with a marker output.
    3. **Route lookup functionality is triggered:** When the application invokes the Windows-specific route lookup, for example, by calling `GetDefaultInterfaceName()` (which could be triggered by CLI commands like "rfc" or "tech-support" or an API call), it executes one of the commands from the `cmds` map.
    4. **Malicious binary execution:** Due to the manipulated PATH, the system resolves the command name (e.g., "powershell") to the attacker's malicious executable instead of the legitimate system binary.
    5. **Arbitrary code execution:** The malicious binary is executed with the privileges of the `go-sockaddr` process, potentially leading to complete process or system compromise, especially if the application runs with elevated privileges.

- **Impact**:
    Arbitrary code execution, potentially leading to complete process and system compromise on Windows systems. This vulnerability is critical if the application relies on route lookup functionality without a secure execution environment and is particularly dangerous if the application runs with elevated privileges.

- **Vulnerability Rank**: Critical

- **Currently Implemented Mitigations**:
    The code uses fixed command-line arguments for the external commands. However, it relies on PATH lookup for the executable names ("powershell", "netstat", "ipconfig"), making it vulnerable to PATH hijacking. There are no mitigations in place to ensure the execution of the intended system binaries.

- **Missing Mitigations**:
    - **Use Absolute Paths:** Specify absolute paths to the system binaries (e.g., `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` for PowerShell on Windows) instead of relying on PATH lookup. This ensures that the correct system binaries are executed, regardless of the PATH environment variable.
    - **Sanitize or Override PATH:** Before calling `exec.Command()`, clear, sanitize, or explicitly override the PATH environment variable to a known safe value. This can prevent attackers from injecting malicious directories into the PATH.
    - **Binary Verification (Optional):** For enhanced security, consider verifying the digital signature or ownership of the located binary before execution to ensure its authenticity and integrity.

- **Preconditions**:
    - The application must be running on a Windows system.
    - The PATH environment variable of the process must be modifiable or already insecurely configured, allowing an attacker to insert a directory under their control at the beginning of the PATH.
    - The attacker must be able to place a malicious executable in the attacker-controlled directory.
    - The route lookup functionality within `go-sockaddr` must be invoked.

- **Source Code Analysis**:
    - **File: `/code/route_info_windows.go`**:
        ```go
        var cmds map[string][]string = map[string][]string{
           "defaultInterface": {"powershell", "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | select -ExpandProperty InterfaceAlias"},
           "netstat":  {"netstat", "-rn"},
           "ipconfig": {"ipconfig"},
        }
        ```
        The `cmds` map defines the commands used for route lookup. Notice that the command names ("powershell", "netstat", "ipconfig") are specified without absolute paths.

        ```go
        func GetDefaultInterfaceName() (string, error) {
            // ...
            out, err := exec.Command(cmds["defaultInterface"][0], cmds["defaultInterface"][1:]...).Output()
            if err == nil {
                return strings.TrimSpace(string(out)), nil
            }
            // ... fallback to netstat and ipconfig
        }
        ```
        The `GetDefaultInterfaceName()` function uses `exec.Command` to execute "powershell" (and potentially "netstat" or "ipconfig" in fallback scenarios) by looking up the command name in the `cmds` map. This call to `exec.Command` relies on the system's PATH environment variable to locate the executables. There is no sanitization or modification of the PATH environment before this call, making it vulnerable to PATH hijacking.

- **Security Test Case**:
    1. **Controlled Windows Test Environment:** Set up a controlled Windows test environment where you can modify environment variables and create files.
    2. **Create Malicious Executable Directory:** Create a temporary directory, for example, `C:\temp\malicious_bin`.
    3. **Place Malicious "powershell.exe":** Inside `C:\temp\malicious_bin`, create a benign "malicious" executable named `powershell.exe`. For testing purposes, this executable can simply write a distinctive marker to a file (e.g., `echo "Malicious PowerShell executed" > C:\temp\malicious_execution.txt`) or output a unique string to stdout.
    4. **Prepend to PATH Environment Variable:** Before running the `sockaddr` application or test program, prepend `C:\temp\malicious_bin` to the PATH environment variable. You can do this in the command prompt before launching the application: `set PATH=C:\temp\malicious_bin;%PATH%`.
    5. **Invoke Route Lookup Functionality:** Execute the `sockaddr` application or a minimal test program that calls the `GetDefaultInterfaceName()` function (e.g., using the "rfc" or "tech-support" commands if they trigger this function).
    6. **Verify Malicious Execution:** Check for the marker file (e.g., `C:\temp\malicious_execution.txt`) or examine the output of the `sockaddr` command. If the marker file exists or the output indicates the execution of the malicious script, it confirms that the malicious "powershell.exe" was executed instead of the system's PowerShell.
    7. **Confirm Arbitrary Command Execution:** This test demonstrates arbitrary command execution due to the unsanitized PATH lookup vulnerability.

---

### 3. Unrestricted Template Evaluation Leading to Information Disclosure

- **Vulnerability Name**: Unrestricted Template Evaluation Leading to Information Disclosure
- **Description**:
    The `go-sockaddr/template` package provides template evaluation functionality to dynamically extract and format network interface information.  The template engine is configured with a function map that includes functions capable of retrieving sensitive network configuration data, such as `GetAllInterfaces`, `GetDefaultInterfaces`, `GetPrivateInterfaces`, and `GetPublicInterfaces`. If an attacker can supply an arbitrary template string to be evaluated, they can leverage these functions to disclose detailed internal network configuration, including IP addresses, interface names, and potentially hardware addresses. This is particularly concerning if the template evaluation is exposed through an API or CLI endpoint without proper authorization or input validation.

    **Step by step how to trigger it**:
    1. **Attacker crafts a malicious template:** The attacker creates a template string designed to extract sensitive network information. Examples include `{{ GetAllInterfaces }}` to retrieve all interface details or more specific templates to target particular attributes.
    2. **Attacker submits the template for evaluation:** The attacker provides the malicious template string to an endpoint or command that performs template evaluation. In the context of `go-sockaddr`, this could be via the `eval` command.
    3. **Template evaluation with sensitive functions:** The template evaluation function (e.g., `Parse` or `ParseIfAddrsTemplate` in `template/template.go`, used by `eval` command) processes the attacker's template. This evaluation uses a function map that includes functions like `GetAllInterfaces`, which directly retrieve sensitive network data.
    4. **Information disclosure:** The template engine executes the template, invoking the data-retrieval functions. The output of the template evaluation, containing the sensitive network configuration information, is returned to the attacker.
    5. **Attacker gains sensitive network information:** The attacker receives the output, gaining unauthorized access to sensitive network configuration details of the host.

- **Impact**:
    Unauthorized disclosure of sensitive network configuration data. An attacker can learn detailed information about the host's network interfaces, including IP addresses, netmasks, interface names, and potentially hardware addresses. This information can be used for further reconnaissance, network mapping, and potentially to facilitate lateral movement within the network.

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**:
    The `go-sockaddr/template` package uses Go's built-in `text/template` package with the `missingkey=error` option, which helps prevent accidental errors due to undefined data in templates. However, this does not restrict access to sensitive functions within the template context. The function maps (`SourceFuncs`, `SortFuncs`, `FilterFuncs`, `HelperFuncs`) by default include functions that expose comprehensive network interface data. There are no built-in restrictions on who can supply the template input or which functions can be used within the template.

- **Missing Mitigations**:
    - **Restrict Function Map for Untrusted Input:** When template evaluation is performed on input from untrusted sources, restrict the function map available to the template engine. Remove or limit access to functions that return sensitive network information. Create a separate, restricted function map for untrusted templates.
    - **Authentication and Authorization:** Implement authentication and authorization for any endpoints or CLI options that expose template evaluation functionality. Ensure that only authorized users or services can trigger template evaluation, especially with the default, unrestricted function map.
    - **Template Input Validation and Sanitization:** Validate and sanitize template input to ensure that only expected or low-sensitivity expressions are processed. Implement a whitelist of allowed template constructs or use a parser to analyze the template and reject templates that use sensitive functions or exceed complexity limits.

- **Preconditions**:
    - The application or service using the `go-sockaddr` library exposes the template evaluation functionality to untrusted users. This could be through the `eval` command in the `sockaddr` CLI or via a web API endpoint.
    - An attacker must be able to supply arbitrary template input to this exposed functionality.

- **Source Code Analysis**:
    - **File: `/code/template/template.go`**:
        ```go
        func ParseIfAddrsTemplate(input string) (*TemplateSet, error) {
            tmpl, err := template.New("ifaddrs").Option("missingkey=error").
                Funcs(SourceFuncs).
                Funcs(SortFuncs).
                Funcs(FilterFuncs).
                Funcs(HelperFuncs).
                Parse(input)
            if err != nil {
                return nil, err
            }
            return &TemplateSet{tmpl: tmpl}, nil
        }
        ```
        The `ParseIfAddrsTemplate` function (and similarly `Parse`) configures the `text/template` engine with a set of function maps (`Funcs`). The `SourceFuncs` map is particularly relevant as it includes functions like `GetAllInterfaces`, `GetDefaultInterfaces`, etc., which retrieve detailed network interface information. The code does not include any checks or sanitization of the input template string to prevent the use of these sensitive functions.

- **Security Test Case**:
    1. **Test Instance Setup:** Set up a test instance of the application or a minimal program that utilizes the `go-sockaddr/template` package and calls `template.Parse` (or `ParseIfAddrsTemplate`) with the library-provided function maps. If testing the `sockaddr` CLI, ensure it is installed and accessible.
    2. **Craft Information Disclosure Template:** Create a template string designed to disclose network interface information, for example: `{{ GetAllInterfaces }}` or a more specific template like `{{ range GetAllInterfaces }}{{ .Name }}: {{ .Addrs }}{{ end }}` to list interface names and addresses.
    3. **Execute Template Evaluation:** Supply the crafted template string to the template evaluation mechanism. For the `sockaddr` CLI, use: `sockaddr eval '{{ GetAllInterfaces }}'`. For a programmatic test, pass the template string to the `template.Parse` function.
    4. **Capture and Verify Output:** Capture the output of the template evaluation.
    5. **Analyze Output for Sensitive Data:** Examine the output and verify that it reveals sensitive network interface details, such as IP addresses, netmasks, interface names, hardware addresses (if included in the output by default functions).
    6. **Confirm Unauthenticated Information Disclosure:** Verify that without any authentication or input validation, the template injection leads to the disclosure of sensitive host network configuration information.