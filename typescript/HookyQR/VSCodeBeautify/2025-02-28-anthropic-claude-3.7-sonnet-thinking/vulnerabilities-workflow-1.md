# VSCodeBeautify Vulnerabilities Analysis

## Unsafe Loading of Remote Configuration via beautify.config Path Setting

### Description
This vulnerability allows loading configuration files from outside the workspace through path traversal. The extension's `beautify.config` setting can be manipulated to load arbitrary files on the file system.

### Impact
This vulnerability is limited to information disclosure and potential extension crashes. The loaded files are only parsed as JSON configuration and not executed as code, making it a security issue but not one that leads to direct code execution.

### Vulnerability Rank
Medium

### Currently Implemented Mitigations
The extension doesn't have proper validation of paths specified in the `beautify.config` setting.

### Missing Mitigations
- Path validation to ensure configurations are only loaded from within the workspace or safe locations
- Sandboxing of configuration loading mechanism
- Restrictions on accessed file locations

### Preconditions
A user must have the VSCodeBeautify extension installed and must open a malicious workspace or be tricked into configuring a dangerous path.

### Source Code Analysis
The extension directly uses file paths from settings without proper validation or sanitization, allowing paths like `../../../sensitive-file` to be specified and loaded.

### Security Test Case
1. Create a VSCode workspace
2. Set up a `.vscode/settings.json` file with `"beautify.config": "../../../etc/passwd"` (on Linux) or another sensitive file
3. Open a file in the workspace and try to beautify it
4. Observe that the extension attempts to load the specified file as configuration

## Insecure JSON Parsing of Configuration Files

### Description
The extension uses potentially exploitable regex patterns in the comment-stripping function when parsing configuration files. This could lead to bypassing validation checks during the parsing process.

### Impact
While the vulnerability could potentially allow a malicious configuration that bypasses validation, the primary impact would be unexpected behavior in the js-beautify library when processing files, rather than direct code execution.

### Vulnerability Rank
Medium

### Currently Implemented Mitigations
None specifically addressing the regex pattern vulnerabilities.

### Missing Mitigations
- Using a secure JSON parser that properly handles comments
- Improved validation of configuration content after parsing
- Safe handling of potentially malformed input

### Preconditions
An attacker must supply a maliciously crafted configuration file that exploits the regex patterns.

### Source Code Analysis
The extension uses regex to strip comments from JSON before parsing, which could be vulnerable to regex denial-of-service (ReDoS) attacks or could allow certain malformed inputs to be processed.

### Security Test Case
1. Create a malicious configuration file with carefully crafted comments designed to bypass the regex filtering
2. Open a project containing this configuration with VSCodeBeautify enabled
3. Attempt to beautify a file, triggering the configuration parsing
4. Observe unexpected behavior or parsing errors

## Prototype Pollution via Unsanitized ".jsbeautifyrc" Configuration Parsing

### Description
The extension loads beautifier configuration from a ".jsbeautifyrc" file found in the workspace (or in the user's home folder) and then passes that configuration object to js‑beautify. The merging function (`mergeOpts`) in "options.js" iterates over all keys from the parsed JSON file without checking for dangerous property names. This means an attacker who supplies a malicious repository (with a crafted ".jsbeautifyrc" file) can include keys such as "__proto__" so that when merged into the configuration object the object's prototype becomes polluted. If the polluted prototype is later used by js‑beautify (or any code relying on the configuration) in a sensitive context (for example, by implicitly invoking methods drawn from Object.prototype), this may be leveraged to achieve arbitrary code execution in the extension's process.

### Impact
Exploitation could result in a polluted Object prototype that affects all objects in the runtime. In a worst‑case scenario, if js‑beautify (or any other dependent code) uses a configuration property without proper safeguards, the attacker might be able to direct execution flow to malicious code. This may lead to remote code execution in the VS Code extension host and, eventually, compromise the victim's machine.

### Vulnerability Rank
High

### Currently Implemented Mitigations
• The extension simply parses the ".jsbeautifyrc" file with JSON.parse (after comment stripping) and merges its properties with no filtering.  
• There is no validation or sanitization of keys (for example, no check to reject "__proto__" or other special properties).

### Missing Mitigations
• Whitelisting or explicitly filtering out dangerous keys (such as "__proto__", "constructor", etc.) before merging the configuration.  
• Using a merger technique that does not allow prototype pollution (for example, creating a configuration object with a null prototype via `Object.create(null)`).  
• Additional validation on user‐supplied configuration to ensure that only expected, safe options are processed.

### Preconditions
• An attacker must supply a repository containing a malicious ".jsbeautifyrc" file with prototype‐polluting keys.  
• A victim must open the manipulated repository in VS Code with the js‑beautify extension enabled (so that the extension loads the tainted configuration).

### Source Code Analysis
1. In **options.js** the function `mergeOpts(opts, kind)` is defined as follows:
   ```js
   const mergeOpts = (opts, kind) => {
     const finOpts = {};
     for (let a in opts) {
       if (a !== 'js' && a !== 'html' && a !== 'css') {
         finOpts[a] = opts[a];
       }
     }
     // merge in the per‑type settings
     if (kind in opts) {
       for (let b in opts[kind]) {
         if (b === 'allowed_file_extensions') continue;
         finOpts[b] = opts[kind][b];
       }
     }
     return finOpts;
   };
   ```
2. Because the code iterates over all keys in the parsed ".jsbeautifyrc" JSON object without filtering, if the JSON contains:
   ```json
   { "__proto__": { "malicious": "executed" } }
   ```
   then the assignment `finOpts["__proto__"] = { "malicious": "executed" }` will effectively pollute `finOpts`'s prototype.  
3. The polluted configuration, once returned and passed to a beautifier function such as `beautify.js`, could be later used in sensitive operations. If the beautifier does not defensively copy or validate its options, the polluted prototype may lead to unexpected behavior—possibly tipping into arbitrary code execution.

### Security Test Case
1. In a controlled testing environment, create a test repository that contains a ".jsbeautifyrc" file with the following content:
   ```json
   { "__proto__": { "malicious": "executed" } }
   ```
2. Open a file from this repository in VS Code so that the extension locates and loads the ".jsbeautifyrc" file.  
3. Execute the Beautify command (for example, run "HookyQR.beautifyFile") and allow the extension to parse and merge the configuration.  
4. In a separate test script or via instrumentation, evaluate whether an ordinary object (e.g. `{}`) now contains the polluted property by checking if `({}).malicious === "executed"`.  
5. If the prototype is polluted, verify that polluted options are passed to js‑beautify by logging or debugging the configuration object at the point of its use.  
6. To explore the potential for RCE, simulate or inspect any behavior in js‑beautify that might inadvertently call a function derived from a property on the polluted prototype (this step may require additional instrumentation or review of js‑beautify internals).