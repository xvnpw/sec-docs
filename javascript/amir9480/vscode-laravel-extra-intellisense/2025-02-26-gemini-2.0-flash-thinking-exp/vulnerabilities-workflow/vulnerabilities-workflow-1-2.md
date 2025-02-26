- **Vulnerability Name:** Unintended Execution of Sensitive Laravel Application Code
  - **Description:**
    - The extension routinely “boots” the entire Laravel application (by including the autoloader and the bootstrap file) in order to pull configuration, routes, translations, views, and other data for autocompletion.
    - In doing so, it executes all service provider boot methods and any code included in the application’s initialization.
    - An attacker who can modify (or inject malicious code into) a Laravel service provider or bootstrap file can cause this code to run automatically when the extension triggers a lookup (for example, when opening a view file or editing a configuration file).
    - **Step by step:**
      1. The attacker (or a compromised package supply chain) injects malicious PHP code into one of the service providers or into bootstrap-related files in the Laravel application.
      2. When a developer uses the extension, one of its providers calls the helper method `runLaravel` (in `src/helpers.ts`), which builds a command that requires
         – the vendor autoloader, and
         – the `bootstrap/app.php` file, thereby bootstrapping the full application.
      3. The malicious code within the service provider is executed during this bootstrapping process.
  - **Impact:**
    - The inadvertent execution of sensitive or attacker‐controlled code can lead to arbitrary PHP code execution, leaking of sensitive application data, and unwanted side effects (such as writing files, making network calls, or modifying the application state).
    - In a publicly accessible or compromised Laravel application, this could be used to further compromise the system or exfiltrate confidential information.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    - A security note in the README warns users to “disable the extension temporarily” if they write sensitive code in service providers.
    - However, this is a documentation‑only mitigation and does not prevent the actual automatic bootstrapping.
  - **Missing Mitigations:**
    - No technical isolation or sandboxing is implemented when bootstrapping the Laravel application.
    - There is no runtime check to restrict service provider side effects or to prevent potentially dangerous code from being executed as a result of autocompletion lookups.
  - **Preconditions:**
    - The Laravel application must be vulnerable to code injection or have service providers that can be modified by an attacker (for example, via a compromised dependency, misconfigured file permissions, or a supply‐chain attack).
    - The extension is installed and actively invoking Laravel bootstrapping (via providers such as the Config, Route, and Translation providers).
  - **Source Code Analysis:**
    - In `Helpers.runLaravel` (in `src/helpers.ts`):
      - The method constructs a PHP command by concatenating (without isolation) a series of strings:
        - It starts by defining a constant (`LARAVEL_START`), and then requires the autoload file and the bootstrap file using:
          ```
          require_once '<projectPath>/vendor/autoload.php';
          $app = require_once '<projectPath>/bootstrap/app.php';
          ```
        - It registers a temporary service provider (which does not sanitize or restrict what gets executed during bootstrapping) and then calls the kernel to handle a (dummy) command.
      - This full bootstrap procedure results in execution of every service provider’s boot method—including any malicious code injected therein.
    - Multiple providers (for configs, routes, translations, etc.) call `runLaravel` without any sandboxing of the environment.
  - **Security Test Case:**
    1. In a test Laravel application, insert (or modify a service provider to include) a simple malicious payload (for example, code that writes a file such as `/tmp/hacked.txt` or echoes a unique string).
    2. Enable the Laravel Extra Intellisense extension in VSCode and open a file (such as a Blade template) that will trigger an autocompletion lookup.
    3. Verify that the malicious payload is executed—for example, check that `/tmp/hacked.txt` is created or that the injected output appears in the extension’s output channel.
    4. Finally, disable the extension and confirm that the payload is no longer executed during normal Laravel operations.

- **Vulnerability Name:** Command Injection via Unsanitized `phpCommand` Configuration
  - **Description:**
    - The extension uses a configurable command template (defined in the setting `LaravelExtraIntellisense.phpCommand`) to run PHP code via the shell.
    - This setting is read by the helper method `runPhp` (in `src/helpers.ts`) and is used to interpolate a placeholder (`{code}`) with PHP code before passing the result to Node’s `cp.exec` function.
    - Since no explicit sanitization or validation is applied to the configuration value or to the interpolated PHP code, an attacker who can modify the workspace configuration can inject additional shell commands.
    - **Step by step:**
      1. An attacker (for example, via a malicious pull request or by compromising a shared configuration file such as `.vscode/settings.json`) changes the value of `phpCommand` to a string that includes extra shell commands.
         – For example, setting it to:
           `php -r "{code}" && echo INJECTED`
      2. When the extension later calls `Helpers.runPhp` to execute a PHP snippet (such as fetching Laravel configuration), it performs a simple string replacement of `{code}` with the PHP code.
      3. The resulting command (now containing the injected `&& echo INJECTED`) is passed to `cp.exec` and is run as a shell command.
  - **Impact:**
    - The injected commands would execute with the privileges of the user running VSCode.
    - This could lead to arbitrary command execution, data loss, modification of files, or further compromise of the developer machine.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    - The extension uses a default safe configuration value for `phpCommand` (i.e. `"php -r \"{code}\""`).
    - However, there is no runtime check to enforce that the configuration remains unaltered or that it does not contain injection payloads.
  - **Missing Mitigations:**
    - No sanitization or strict validation is applied to the `phpCommand` string before it is used for constructing the shell command.
    - A safer approach (for example, using parameterized execution or proper escaping of substitutions) is not implemented.
  - **Preconditions:**
    - The attacker must be able to modify the workspace configuration (for example, in a shared or compromised development environment or via a malicious pull request that updates settings).
    - The extension must be operating with a modified `phpCommand` value in which extra shell commands have been injected.
  - **Source Code Analysis:**
    - In `Helpers.runPhp` (in `src/helpers.ts`):
      - The command template is retrieved with:
        ```js
        let commandTemplate = vscode.workspace
          .getConfiguration("LaravelExtraIntellisense")
          .get<string>('phpCommand') ?? "php -r \"{code}\"";
        ```
      - Then the code simply performs:
        ```js
        let command = commandTemplate.replace("{code}", code);
        ```
      - No further escaping or checking is done on either the configuration string or the PHP code.
      - Finally, the command is executed with `cp.exec(command, ...)` meaning that any injected extra shell tokens will be interpreted by the shell.
    - This unsanitized interpolation creates a risk of command injection if an attacker-controlled configuration is used.
  - **Security Test Case:**
    1. In a test workspace, modify (or create) the settings file (e.g. `.vscode/settings.json`) so that `"LaravelExtraIntellisense.phpCommand"` is set to a value that appends an extra command. For example:
       ```json
       {
         "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" && echo INJECTED"
       }
       ```
    2. Open a file that triggers an autocompletion lookup (for instance, one that causes the Config or Validation provider to call `runPhp`).
    3. Observe the extension’s output (or log channel) for the string “INJECTED”.
    4. The appearance of “INJECTED” confirms that the extra portion of the command was executed—demonstrating a command injection vulnerability.
    5. Restore the safe default and verify that the injected output no longer appears.