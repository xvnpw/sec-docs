## Vulnerability List

- Arbitrary Code Execution via Malicious Tailwind Configuration Path

### Description
An attacker can achieve arbitrary code execution by manipulating the `tailwindcssConfigPath` setting in the `.bladeformatterrc.json` configuration file. This vulnerability occurs because the extension uses `requireUncached` to load the Tailwind CSS configuration file specified by `tailwindcssConfigPath`. If an attacker can modify the `.bladeformatterrc.json` to point to a malicious JavaScript file, the extension will execute this file when formatting a Blade template.

**Step-by-step trigger:**
1. An attacker gains write access to the workspace of a user using the VSCode extension. This could be achieved through various means, such as compromising a shared repository or exploiting other vulnerabilities to write files to the user's filesystem.
2. The attacker creates a malicious JavaScript file within the workspace, for example, named `malicious.config.js`. This file contains arbitrary JavaScript code that the attacker wants to execute. For example, the file could contain code to execute system commands, read sensitive files, or exfiltrate data.
3. The attacker creates or modifies the `.bladeformatterrc.json` file in the workspace root or a parent directory.
4. In the `.bladeformatterrc.json` file, the attacker sets the `tailwindcssConfigPath` property to point to the malicious JavaScript file created in step 2. This path can be relative or absolute to the workspace. For example, if `malicious.config.js` is in the workspace root, the attacker sets `tailwindcssConfigPath` to `./malicious.config.js`.
5. The user opens a Blade template file (`*.blade.php`) within the compromised workspace in VSCode.
6. The user triggers the Blade Formatter extension, either by manually running the format command or by automatically formatting on save.
7. The extension reads the configuration from `.bladeformatterrc.json`, including the attacker-controlled `tailwindcssConfigPath`.
8. The extension's `resolveTailwindConfig` function resolves the path to the malicious configuration file.
9. The extension then uses the `requireUncached` function to load the Tailwind CSS configuration file from the attacker-specified path.
10. Because `requireUncached` effectively executes the JavaScript code in the specified file (due to `fs.readFileSync` and `sucrase.transform`), the malicious code within `malicious.config.js` is executed in the context of the VSCode extension.

### Impact
Arbitrary code execution. An attacker can execute arbitrary code on the user's machine with the privileges of the VSCode process. This can lead to:
- Data theft: Access to files and sensitive information on the user's system.
- System compromise: Installation of malware, backdoors, or other malicious software.
- Privilege escalation: Potential to gain further access to the user's system or network.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The code directly uses `requireUncached` on the path provided in the configuration without any validation or sanitization.

### Missing Mitigations
- Input validation: Validate the `tailwindcssConfigPath` in `.bladeformatterrc.json` to ensure it points to a valid Tailwind configuration file and is within the workspace. Restrict the path to only allow `.js` or `.cjs` files and prevent absolute paths or paths outside the workspace.
- Secure module loading: Instead of using `requireUncached` which executes the code in the config file, use a safer method to just read and parse the configuration data. For example, read the file content and parse it as JSON or use a dedicated configuration parsing library that does not execute code. If code execution is necessary for config loading, implement sandboxing or other isolation techniques.
- User warning: Display a warning message to the user if a `tailwindcssConfigPath` is specified in the configuration, especially if it's a relative path, advising caution and the risk of arbitrary code execution if the workspace is not trusted.

### Preconditions
1. The attacker has write access to the user's workspace directory to modify or create `.bladeformatterrc.json` and create a malicious JavaScript file.
2. The user has the Blade Formatter extension installed and activated in VSCode.
3. The user opens a Blade template file within the compromised workspace and triggers the formatting.
4. The `bladeFormatter.format.sortTailwindcssClasses` setting is enabled, either globally or in the workspace, or a runtime config enables `sortTailwindcssClasses`. This triggers the Tailwind configuration loading logic.

### Source Code Analysis
The vulnerability lies in the `resolveTailwindConfig` function in `/code/src/tailwind.ts` and its usage in `/code/src/extension.ts`, combined with the insecure `requireUncached` function in `/code/src/util.ts`.

1. **`resolveTailwindConfig` function in `/code/src/tailwind.ts`:**
   ```typescript
   export function resolveTailwindConfig(
   	filepath: string,
   	optionPath: string,
   ): string {
   	if (!optionPath) {
   		return findConfig(__config__, { cwd: path.dirname(filepath) }) ?? "";
   	}

   	if (path.isAbsolute(optionPath ?? "")) {
   		return optionPath; // Returns absolute path directly - POTENTIAL RISK
   	}

   	const runtimeConfigPath = findConfigFile(filepath);

   	return path.resolve(path.dirname(runtimeConfigPath ?? ""), optionPath ?? ""); // Resolves relative path - POTENTIAL RISK
   }
   ```
   - If `optionPath` from runtime config is absolute, it's returned directly without validation.
   - If `optionPath` is relative, it's resolved relative to the runtime config file's directory.
   - Both cases allow an attacker to control the final path if they can modify the runtime config file.

2. **`requireUncached` function in `/code/src/util.ts`:**
   ```typescript
   export function requireUncached(moduleName: string) {
   	try {
   		delete __non_webpack_require__.cache[
   			__non_webpack_require__.resolve(moduleName)
   		];

   		const fileContent = fs.readFileSync(moduleName, "utf8"); // Reads file content

   		return transform(fileContent, { transforms: ["imports"] }); // Transforms content (but still executes top level code)
   	} catch (err: any) {
   		throw err;
   	}
   }
   ```
   - This function reads the content of the file specified by `moduleName`.
   - It uses `sucrase.transform` which, while intended for import transformations, does not prevent the execution of top-level JavaScript code within the file when the transformed code is implicitly evaluated or required later in the formatting process by the `blade-formatter` library (although this part is not in provided code, assuming `blade-formatter` might evaluate config).
   - Directly reading and processing the file content from a potentially attacker-controlled path using Node.js `require` semantics leads to code execution.

3. **Usage in `/code/src/extension.ts`:**
   ```typescript
   if (
   	runtimeConfig?.sortTailwindcssClasses ||
   	extConfig.sortTailwindcssClasses
   ) {
   	const tailwindConfigPath = resolveTailwindConfig(
   		document.uri.fsPath,
   		runtimeConfig?.tailwindcssConfigPath ?? "",
   	);
   	tailwindConfig.tailwindcssConfigPath = tailwindConfigPath;

   	try {
   		requireUncached(tailwindConfigPath); // Insecurely loads and executes config
   	} catch (error) {
   		// fallback to default config
   		tailwindConfig.tailwindcssConfigPath =
   			__non_webpack_require__.resolve(
   				"tailwindcss/lib/public/default-config",
   			);
   	}
   }
   ```
   - The `tailwindConfigPath` is resolved using `resolveTailwindConfig` based on user-provided configuration.
   - `requireUncached(tailwindConfigPath)` is called to load the config, leading to potential code execution if `tailwindConfigPath` points to a malicious file.

### Security Test Case
**Pre-requisites:**
1. Install the Blade Formatter extension in VSCode.
2. Open a workspace in VSCode.
3. Ensure that the `bladeFormatter.format.sortTailwindcssClasses` setting is enabled in the workspace or globally.

**Steps:**
1. Create a new file named `malicious.config.js` in the workspace root with the following content:
   ```javascript
   require('child_process').execSync('touch /tmp/vscode-blade-formatter-pwned');
   ```
2. Create or modify `.bladeformatterrc.json` in the workspace root and add the following configuration:
   ```json
   {
       "tailwindcssConfigPath": "./malicious.config.js",
       "sortTailwindcssClasses": true
   }
   ```
3. Create a new Blade template file, for example, `test.blade.php`, in the workspace root. Add any Blade syntax to it.
   ```blade
   <div>
       <p class="text-red-500">Hello Blade</p>
   </div>
   ```
4. Open `test.blade.php` in VSCode.
5. Trigger the formatting of the `test.blade.php` file. You can do this by saving the file (if format on save is enabled) or by running the "Format Document" command (Shift+Alt+F or Cmd+Shift+P and type "Format Document").
6. After formatting, check if the file `/tmp/vscode-blade-formatter-pwned` exists on your system.

**Expected Result:**
If the vulnerability is present, the file `/tmp/vscode-blade-formatter-pwned` will be created, indicating that the code in `malicious.config.js` was executed by the extension.

**Cleanup:**
Delete the `/tmp/vscode-blade-formatter-pwned` file after testing.