# High-Risk Code Execution Vulnerabilities

## 1. Untrusted Laravel Bootstrap and Autoload Execution  
**Description**:  
• The extension periodically calls the helper function `Helpers.runLaravel()` in order to boot the Laravel application and extract data (such as routes, models, and middlewares).  
• In doing so, it constructs a PHP command that automatically requires both `vendor/autoload.php` and `bootstrap/app.php` using paths computed by `Helpers.projectPath()`.  
• An attacker supplying a malicious repository can modify these Laravel core files (or include extra code among them) so that when they are required by PHP, arbitrary PHP code will run.  

**Impact**:  
• Arbitrary PHP code execution on the victim's machine with the same privilege as the PHP process. This could lead to system compromise (data theft, file modification, command execution, etc.).  

**Vulnerability Rank**: High  

**Currently Implemented Mitigations**:  
• A security note warns users to disable the extension if sensitive code (such as in service providers) is being written. This note is advisory only.  

**Missing Mitigations**:  
• No runtime code integrity checks (for example, cryptographic signature verification of critical files).  
• Lack of sandboxing or isolation when booting the Laravel application from the repository.  

**Preconditions**:  
• The victim opens a repository that has been manipulated by an attacker so that its `vendor/autoload.php` and/or `bootstrap/app.php` (or related bootstrap files) contain malicious PHP code.  

**Source Code Analysis**:  
• In `Helpers.runLaravel()` the PHP command is built as:  

```
"define('LARAVEL_START', microtime(true));" +
"require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
"$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" + 
// additional code follows …
```
• Because the file paths come directly from the workspace (or via a relative configured "basePath"), no checks or sanitization of these core files are performed.  

**Security Test Case**:  
• Prepare a test repository in which you deliberately replace or inject additional PHP code into `bootstrap/app.php` (for example, having it execute a payload such as writing a known marker file).  
• Open that repository in VSCode with the extension enabled and trigger a function that calls `Helpers.runLaravel()` (for example, by forcing a route or model refresh).  
• Verify that the injected payload executes (the marker file appears, or log messages indicate execution of unexpected commands).

## 2. PHP Code Injection via Malicious "modelsPaths" Configuration  
**Description**:  
• In `EloquentProvider.loadModels()`, the extension reads the workspace configuration value for `LaravelExtraIntellisense.modelsPaths`.  
• This value (an array of directory paths) is concatenated directly into a PHP code string with no escaping. For example, the code is built as follows:  

```
"foreach (['" +
  vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') +
"'] as $modelPath) { … }"
```  
• An attacker who is able to control the workspace settings (for instance, via a malicious .vscode/settings.json file packaged with the repository) can supply a string containing a single quote and additional PHP commands.  

**Impact**:  
• This may result in arbitrary PHP code injection and execution when the extension queries for Eloquent models.  

**Vulnerability Rank**: High  

**Currently Implemented Mitigations**:  
• There is no additional sanitization or proper escaping applied to the configuration values before they are embedded into the PHP command string.  

**Missing Mitigations**:  
• Sanitization and proper escaping of configuration inputs before concatenation into executable code.  
• Use of parameterized methods or safe templating for building PHP code.  

**Preconditions**:  
• The attacker controls the workspace configuration (for example, via a committed .vscode/settings.json in the repository) and supplies a crafted value such as:  
`"app'; system('malicious_command'); //"`  

**Source Code Analysis**:  
• In `EloquentProvider.loadModels()`, the line  
```
"foreach (['" + <modelsPaths array>.join('\', \'') + "'] as $modelPath) { … }"
```  
directly injects the configuration into a PHP array literal. If one of the strings contains an unescaped single quote, PHP will interpret it as the end of the literal and execute subsequent injected code.  

**Security Test Case**:  
• In a test repository, create a .vscode/settings.json that sets "LaravelExtraIntellisense.modelsPaths" to an array including an entry such as:  
`["app'; file_put_contents('pwned.txt', 'injected'); //", "app/Models"]`  
• Open this repository in VSCode and trigger a refresh (for example, by opening a PHP file that causes Eloquent provider to load).  
• Check for the presence of the file "pwned.txt" (or any evidence that the injected code was executed).

## 3. Command Injection via Malicious "phpCommand" Configuration  
**Description**:  
• The extension allows the PHP execution command to be configured through `LaravelExtraIntellisense.phpCommand` (the default being `php -r "{code}"`).  
• In `Helpers.runPhp()`, this configuration value is retrieved and then the special placeholder `{code}` is simply string–replaced with the (escaped) PHP code to run.  
• However, if the attacker supplies a malicious string through the workspace configuration (for example, via a committed .vscode/settings.json), they can modify the command template to append extra shell commands.  

**Impact**:  
• This can lead to arbitrary system commands being executed on the victim's machine under the privileges of the PHP process, resulting in full command–injection and loss of host control.  

**Vulnerability Rank**: High  

**Currently Implemented Mitigations**:  
• A basic replacement is performed and minimal escaping is done (double quotes are escaped, and on Unix systems the "$" character is also escaped).  
• However, these measures are not sufficient to nullify an intentionally crafted malicious command template.  

**Missing Mitigations**:  
• Thorough validation and sanitization of the user–supplied configuration value for "phpCommand" before it is used to build the shell command.  
• Ideally, the extension should enforce an allow–list of safe command formats or avoid using a configurable command that is interpreted by a shell.  

**Preconditions**:  
• The attacker controls the workspace configuration (for example, via a malicious .vscode/settings.json file) and sets "phpCommand" to a value such as:  
`php -r "{code}"; echo 'MALICIOUS_PAYLOAD'`  

**Source Code Analysis**:  
• In `Helpers.runPhp()`, the command is built as follows:  
```
let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
let command = commandTemplate.replace("{code}", code);
cp.exec(command, …);
```  
• No checks are made on the final value of "commandTemplate" to ensure that no rogue shell metacharacters or additional commands are present.  

**Security Test Case**:  
• In a controlled testing environment, add a .vscode/settings.json file with a "phpCommand" setting such as:  
`"phpCommand": "php -r \"{code}\"; echo 'INJECTED';"`  
• Trigger any functionality that calls `Helpers.runPhp()` (for example, loading route or model data).  
• Monitor the output or logs to confirm that the string "INJECTED" is printed, thereby demonstrating that the extra command was executed.