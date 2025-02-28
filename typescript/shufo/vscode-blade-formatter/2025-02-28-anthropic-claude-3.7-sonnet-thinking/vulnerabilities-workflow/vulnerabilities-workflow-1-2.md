# Vulnerability List

## Vulnerability 1: Arbitrary Code Execution via Malicious Tailwind CSS Configuration Loading

### Description
The extension supports sorting Tailwind CSS classes by reading a Tailwind configuration file whose path can be specified via the runtime configuration (for example, in a ".bladeformatterrc.json" file using the key `tailwindcssConfigPath`). In the formatting provider (in `extension.ts`), if the option to sort Tailwind CSS classes is enabled, the extension resolves the config file path using the helper function `resolveTailwindConfig()`. It then calls the helper function `requireUncached()` with that path. Although `requireUncached()` merely reads and transforms the file (using Sucrase) without directly executing it, the resulting value (or simply the file path) is passed as part of the options into the underlying "blade-formatter" library. In many formatter libraries the configuration file is then loaded (using a normal `require()` or dynamic import) to drive class sorting. An attacker supplying a repository with a malicious Tailwind configuration file (for example, one that contains JavaScript payload code that spawns a shell command) can cause the vulnerable extension to load and execute that file when a Blade file is formatted.

### Impact
This flaw could allow an attacker to run arbitrary JavaScript code in the context of the victim's VS Code process. The resulting Remote Code Execution (RCE) can lead to full system compromise, data exfiltration, or further attacks on the development environment.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- The extension does parse runtime configuration using AJV and catches errors when attempting to load the Tailwind config. In case of an error during the call to `requireUncached()`, the code falls back to a default Tailwind configuration.

### Missing Mitigations
- There is no validation or sandboxing on the file pointed to by the `tailwindcssConfigPath` property.
- The runtime configuration (and in particular, the Tailwind config path) is accepted "as is" and later passed along to the underlying formatter library, which may load (and execute) the file without further checks.

### Preconditions
- The victim opens a repository that contains an attacker–controlled Tailwind configuration file with malicious payload code.
- The repository includes a runtime configuration (e.g. in a `.bladeformatterrc.json`) that sets `"sortTailwindcssClasses": true` and specifies a non–default value of `"tailwindcssConfigPath"`, resolved to the malicious file.

### Source Code Analysis
1. In `extension.ts`, the formatting provider checks if Tailwind CSS class sorting is enabled by testing  
   ```js
   if (runtimeConfig?.sortTailwindcssClasses || extConfig.sortTailwindcssClasses) { … }
   ```  
2. It calls the helper `resolveTailwindConfig(document.uri.fsPath, runtimeConfig?.tailwindcssConfigPath ?? "")` (see `tailwind.ts`) to determine the effective configuration file path. If the runtime configuration supplies a relative path, it is resolved relative to a configuration file found by the helper `findConfigFile()`.  
3. The resolved path is assigned to `tailwindConfig.tailwindcssConfigPath` and an attempt is made to load it with:
   ```js
   try {
     requireUncached(tailwindConfigPath);
   } catch (error) {
     tailwindConfig.tailwindcssConfigPath =
       __non_webpack_require__.resolve("tailwindcss/lib/public/default-config");
   }
   ```
4. The option object is then constructed by spreading the standard extension configuration, any runtime configuration, and the `tailwindConfig` object. This final object is passed to `new Formatter(options)` (from the imported "blade-formatter" library).  
5. If the underlying library later loads the configuration file specified by `tailwindcssConfigPath` by (for example) a normal dynamic import or require, the malicious code in that file will execute in the Node.js process running the extension.

### Security Test Case
1. Create a test repository that includes a file (e.g., `maliciousTailwind.config.js`) with a payload such as:
   ```js
   // maliciousTailwind.config.js
   console.log("Malicious code executed!");
   require('child_process').exec('touch /tmp/pwned');
   module.exports = { theme: {} };
   ```
2. In the repository root add a runtime configuration file (e.g. `.bladeformatterrc.json`) with content similar to:
   ```json
   {
     "sortTailwindcssClasses": true,
     "tailwindcssConfigPath": "./maliciousTailwind.config.js"
   }
   ```
3. Open the repository in VS Code with the blade-formatter extension installed.  
4. Open any Blade file (for example, an `.blade.php` file) to trigger the formatting provider.  
5. Observe whether the malicious payload is loaded (for example, verify the presence of the file `/tmp/pwned` or log output). Successful execution confirms that the extension ends up loading a repository–supplied configuration file that may contain arbitrary code.

## Vulnerability 2: Unvalidated Runtime Configuration Injection Leading to Potential Code Injection

### Description
The extension reads additional formatting settings from a runtime configuration file (either `.bladeformatterrc.json` or `.bladeformatterrc`) using the function `readRuntimeConfig()` in `runtimeConfig.ts`. Although standard options (such as `indentSize`, `wrapLineLength`, etc.) are defined in the AJV schema, the schema uses the option `additionalProperties: true`. This means that any extra keys not prescribed by the schema are accepted without further validation. Later in `extension.ts` these extra (and potentially attacker–controlled) properties are merged into the options passed to the underlying formatter by spreading the `runtimeConfig` object. If the underlying "blade-formatter" library is not designed to safely ignore unknown options and instead uses them directly—for example by incorporating them into dynamic function calls or template evaluations—this may allow an attacker to inject malicious code and trigger arbitrary execution.

### Impact
Exploitation could lead to arbitrary code injection within the formatter's runtime context. Although the immediate consequence depends on how the "blade-formatter" library makes use of these extra options, successful exploitation would allow a threat actor to execute arbitrary code in the victim's VS Code environment.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- The runtime configuration file is parsed as JSON and validated using a JSON schema (via AJV), which ensures that known properties have the expected types.

### Missing Mitigations
- The schema permits additional properties via `additionalProperties: true` without any further checks, so there is no whitelist enforcement to block unexpected keys.
- There is no explicit filtering or sanitization step for extra keys before they are merged into the options object sent to the Formatter.
- If the underlying "blade-formatter" library does not securely handle extra configuration keys, this may lead to code injection.

### Preconditions
- The victim opens a repository that includes a custom runtime configuration file (e.g. `.bladeformatterrc.json`) embedded with extra properties (beyond those expected by the schema).
- The underlying "blade-formatter" library uses the combined options in an unsafe (for example, evaluated) manner.

### Source Code Analysis
1. In `runtimeConfig.ts`, the function `readRuntimeConfig()` is declared. It loads a configuration file (if one is found by `findConfigFile()`) and converts it to a string.  
2. The AJV JTD schema is defined with its `optionalProperties` for standard options but explicitly sets `additionalProperties: true`, meaning that any keys not defined in the schema are retained.  
3. In `extension.ts`, after loading both the extension setting and the runtime configuration, the two are merged into one options object using the spread operator:
   ```js
   const options = {
     …,
     ...runtimeConfig, // override all settings by runtime config
     …tailwindConfig,
   };
   ```
4. This merged options object is passed into the Formatter constructor (`new Formatter(options)`). If the underlying "blade-formatter" uses any of these extra options (for example, if it constructs dynamic logic based on the keys present), an attacker supplying additional properties could trigger unsafe code paths.

### Security Test Case
1. In a test repository, create a runtime configuration file (e.g. `.bladeformatterrc.json`) containing both valid options and an extra, unexpected property. For example:
   ```json
   {
     "indentSize": 4,
     "sortTailwindcssClasses": false,
     "maliciousKey": "console.log(require('child_process').execSync('touch /tmp/injected'));"
   }
   ```
2. Open the repository in VS Code with the blade-formatter extension installed.  
3. Trigger formatting (for instance by running the "Blade: Format Document" command).  
4. Monitor whether the extra property "maliciousKey" is used in any dynamic evaluation (e.g. by checking if a file such as `/tmp/injected` is unexpectedly created or if console output occurs).  
5. Such behavior would confirm that unsanitized additional properties from the runtime configuration can affect the formatting process, potentially leading to arbitrary code execution.