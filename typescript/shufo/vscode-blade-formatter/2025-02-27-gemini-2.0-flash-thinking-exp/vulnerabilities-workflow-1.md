## Consolidated Vulnerability List

### Vulnerability 1: Arbitrary Code Execution via Malicious Tailwind Configuration

* **Description:**
    1. The VSCode extension reads configuration settings from `.bladeformatterrc.json` or `.bladeformatterrc` files within the workspace.
    2. These configuration files can specify a `tailwindcssConfigPath` setting, which dictates the location of the Tailwind CSS configuration file used for class sorting during formatting.
    3. The extension uses the `requireUncached` function to load and execute the JavaScript code within the specified Tailwind CSS configuration file.
    4. An attacker who can modify or create a `.bladeformatterrc.json` or `.bladeformatterrc` file in a user's workspace can set the `tailwindcssConfigPath` to point to a malicious JavaScript file.
    5. When the user formats a Blade file within this workspace, the extension will load and execute the attacker's malicious JavaScript file through `requireUncached`, leading to arbitrary code execution within the VSCode extension's context.

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

* **Impact:**
    Arbitrary code execution within the VSCode extension context. This can have severe consequences, potentially allowing an attacker to:
    - Steal sensitive data from the user's workspace or machine.
    - Install malware or backdoors on the user's system.
    - Modify files within the workspace.
    - Escalate privileges or perform other malicious actions, depending on the permissions of the VSCode process and the user's system.
    - Data theft: Access to files and sensitive information on the user's system.
    - System compromise: Installation of malware, backdoors, or other malicious software.
    - Privilege escalation: Potential to gain further access to the user's system or network.

* **Vulnerability Rank:** high

* **Currently implemented mitigations:**
    None. The extension directly loads and executes the JavaScript file specified by the `tailwindcssConfigPath` without any validation or sanitization. The code directly uses `requireUncached` on the path provided in the configuration without any validation or sanitization.

* **Missing mitigations:**
    - **Input Validation and Sanitization:** The extension should validate the `tailwindcssConfigPath` to ensure it points to a legitimate Tailwind CSS configuration file and is within the workspace's boundaries. It should prevent loading files from outside the workspace or files with unexpected extensions. Validate the `tailwindcssConfigPath` in `.bladeformatterrc.json` to ensure it points to a valid Tailwind configuration file and is within the workspace. Restrict the path to only allow `.js` or `.cjs` files and prevent absolute paths or paths outside the workspace.
    - **Sandboxing or Isolation:** The process of loading and executing the Tailwind CSS configuration should be sandboxed or isolated to limit the potential damage from malicious code execution. Secure module loading: Instead of using `requireUncached` which executes the code in the config file, use a safer method to just read and parse the configuration data. For example, read the file content and parse it as JSON or use a dedicated configuration parsing library that does not execute code. If code execution is necessary for config loading, implement sandboxing or other isolation techniques.
    - **User Warning:**  The extension should warn users about the security risks of using configuration files from untrusted sources or workspaces and advise caution when opening workspaces from unknown origins. Display a warning message to the user if a `tailwindcssConfigPath` is specified in the configuration, especially if it's a relative path, advising caution and the risk of arbitrary code execution if the workspace is not trusted.

* **Preconditions:**
    1. **Attacker Workspace Access:** An attacker needs to gain the ability to modify or create a `.bladeformatterrc.json` or `.bladeformatterrc` file within the user's workspace. This could be achieved through various means, such as:
        - Compromising a project's repository and injecting a malicious configuration file.
        - Social engineering to trick a user into opening a workspace containing a malicious configuration file.
        - Exploiting other vulnerabilities on the user's system to gain file system access and modify workspace files.
        - The attacker has write access to the user's workspace directory to modify or create `.bladeformatterrc.json` and create a malicious JavaScript file.
    2. **User Action:** The user must open a Blade file within the compromised workspace and trigger the formatting action, either manually or automatically upon saving.
        - The user has the Blade Formatter extension installed and activated in VSCode.
        - The user opens a Blade template file within the compromised workspace and triggers the formatting.
    3. **`sortTailwindcssClasses` Enabled:** The `sortTailwindcssClasses` setting must be enabled, either globally or within the workspace configuration, for the Tailwind CSS configuration path to be considered and loaded.
        - The `bladeFormatter.format.sortTailwindcssClasses` setting is enabled, either globally or in the workspace, or a runtime config enables `sortTailwindcssClasses`. This triggers the Tailwind configuration loading logic.

* **Source code analysis:**
    1. **`src/runtimeConfig.ts:readRuntimeConfig()`**: This function reads and parses the configuration file (`.bladeformatterrc.json` or `.bladeformatterrc`). It defines `tailwindcssConfigPath` as a string within the `RuntimeConfig` interface.
    ```typescript
    export interface RuntimeConfig {
        ...
        tailwindcssConfigPath?: string;
        ...
    }
    ```
    2. **`src/tailwind.ts:resolveTailwindConfig()`**: This function resolves the absolute path to the Tailwind CSS configuration file. It takes the `filepath` of the current Blade file and the `optionPath` (which is `tailwindcssConfigPath` from the runtime config).
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
    The function checks for absolute paths but lacks validation to ensure the path is safe or points to a valid configuration file type.
    If `optionPath` from runtime config is absolute, it's returned directly without validation. If `optionPath` is relative, it's resolved relative to the runtime config file's directory. Both cases allow an attacker to control the final path if they can modify the runtime config file.
    3. **`src/extension.ts:provideDocumentFormattingEdits()`**: Inside the `provideDocumentFormattingEdits` function, the extension retrieves the `tailwindcssConfigPath` and uses `requireUncached` to load the configuration file.
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
            requireUncached(tailwindConfigPath); // Potential code execution - Insecurely loads and executes config
        } catch (error) {
            // fallback to default config
            tailwindConfig.tailwindcssConfigPath =
                __non_webpack_require__.resolve(
                    "tailwindcss/lib/public/default-config",
                );
        }
    }
    ```
    4. **`src/util.ts:requireUncached()`**: This utility function is used to load and execute JavaScript modules. It reads the file content using `fs.readFileSync` and transforms it using `sucrase` before returning the module.
    ```typescript
    export function requireUncached(moduleName: string) {
        try {
            delete __non_webpack_require__.cache[
                __non_webpack_require__.resolve(moduleName)
            ];

            const fileContent = fs.readFileSync(moduleName, "utf8"); // Reads file content

            return transform(fileContent, { transforms: ["imports"] }); // JavaScript code execution - Transforms content (but still executes top level code)
        } catch (err: any) {
            throw err;
        }
    }
    ```
    The `transform` function from `sucrase` will execute the JavaScript code within the file, making it vulnerable to code injection if `moduleName` (in this case, `tailwindConfigPath`) is controlled by an attacker. This function reads the content of the file specified by `moduleName`. It uses `sucrase.transform` which, while intended for import transformations, does not prevent the execution of top-level JavaScript code within the file when the transformed code is implicitly evaluated or required later in the formatting process by the `blade-formatter` library. Directly reading and processing the file content from a potentially attacker-controlled path using Node.js `require` semantics leads to code execution.

* **Security test case:**
    1. **Setup Malicious Workspace:** Create a new, empty workspace in VSCode.
    2. **Create Malicious Config File:** In the workspace root, create a JavaScript file named `malicious.config.js` with the following content. This code will attempt to write a file named `pwned.txt` to the workspace root to demonstrate code execution:
        ```javascript
        console.log("Malicious Tailwind config executing...");
        const fs = require('fs');
        fs.writeFileSync('pwned.txt', 'You have been PWNED by malicious Tailwind config!');
        module.exports = {
            theme: {
                extend: {},
            },
            plugins: [],
        };
        ```
    3. **Create Malicious Runtime Config:** Create a `.bladeformatterrc.json` file in the workspace root with the following content. This configuration sets `sortTailwindcssClasses` to `true` and `tailwindcssConfigPath` to the malicious file.
        ```json
        {
            "sortTailwindcssClasses": true,
            "tailwindcssConfigPath": "./malicious.config.js"
        }
        ```
    4. **Create Blade File:** Create a simple Blade file named `test.blade.php` in the workspace root. The content doesn't matter for triggering the vulnerability, but ensure it's a valid Blade file.
        ```blade
        <div>
            <p class="text-red-500">Hello, World!</p>
        </div>
        ```
    5. **Open Workspace and Blade File:** Open the newly created workspace in VSCode. Open the `test.blade.php` file.
    6. **Trigger Formatting:** Trigger the Blade formatter by running the "Format Document" command (e.g., `Shift + Alt + F` or through the command palette).
    7. **Verify Code Execution:** After formatting, check the workspace root for the file `pwned.txt`. If the file exists and contains the message "You have been PWNED by malicious Tailwind config!", it confirms that the malicious JavaScript code in `malicious.config.js` was executed by the extension. Also, observe the "Output" panel for the "BladeFormatter" output channel, where "Malicious Tailwind config executing..." should be logged.

    **Alternative Security Test Case:**

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

---

### Vulnerability 2: Prototype Pollution via Unsanitized Runtime Configuration

* **Description:**
  The extension loads runtime configuration from files (".bladeformatterrc.json" or ".bladeformatterrc") via a JSON schema defined in `src/runtimeConfig.ts`. Although the schema defines a list of expected properties, it allows any additional properties (using `"additionalProperties": true`), so keys such as `"__proto__"` are not disallowed. When the parsed configuration is merged into the extension’s options (using the spread operator in `src/extension.ts`), an attacker‑controlled configuration file could inject a key like `"__proto__"`, thereby polluting the prototype of the options object. This pollution may “leak” into all objects created afterward, altering their default behavior and potentially paving the way for further exploitation (for example, if a dependent library relies on unmodified built‑in methods).

* **Impact:**
  Prototype pollution of core objects may lead to unexpected or insecure behavior in the extension as well as in any libraries that use the affected objects. In worst‑case scenarios, the polluted prototype could be leveraged to perform arbitrary code execution attacks or bypass security checks.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
  - The configuration file is parsed using Ajv against a predefined schema.
  - However, the schema explicitly allows extra properties by setting `"additionalProperties": true`.

* **Missing Mitigations:**
  - The schema should be tightened to disallow dangerous keys (e.g. `"__proto__"`, `"constructor"`) either by explicitly listing allowed keys only or by filtering the parsed object before merging.
  - Add sanitization logic on the runtime configuration so that any keys that could affect the object prototype are removed.

* **Preconditions:**
  - The attacker must be able to supply or influence the contents of the runtime configuration (for example, by contributing a malicious ".bladeformatterrc.json" file in a public repository).
  - The victim must open the compromised workspace in VS Code with this extension enabled.

* **Source Code Analysis:**
  - In **`src/runtimeConfig.ts`** the function `readRuntimeConfig` uses a JTDSchema that defines expected numeric or boolean properties but sets `"additionalProperties": true`. As a result, keys such as `"__proto__"` are accepted.
  - Then in **`src/extension.ts`** the options object is built as follows:
    ```ts
    const options = {
      vsctm: vsctmModule,
      oniguruma: onigurumaModule,
      indentSize: extConfig.indentSize,
      // …other known properties,
      ...runtimeConfig, // runtime config is merged without sanitization!
      ...tailwindConfig,
    };
    ```
    If `runtimeConfig` contains a `"__proto__"` key, the object spread ultimately causes that property to be copied and (via Object.assign‑like behavior) may pollute the prototype chain of plain objects.

* **Security Test Case:**
  - Prepare a test workspace that includes a file named **“.bladeformatterrc.json”** with the following contents:
    ```json
    {
      "__proto__": {
        "polluted": "yes"
      }
    }
    ```
  - Open a Blade file in this workspace so that the extension is activated and the runtime config is read.
  - In the VS Code developer console (or via a small test script), verify whether a new plain object now has the polluted property (for example, evaluate `({}).polluted` and see if it returns `"yes"`).
  - Observe and document any unexpected behavior in the formatting process that might stem from the polluted prototype.

---

### Vulnerability 3: Arbitrary File Read via Insecure Tailwind CSS Configuration Path

* **Description:**
  The extension allows users to override the Tailwind CSS configuration file path by supplying a value for the key `"tailwindcssConfigPath"` in the runtime configuration. In the module **`src/tailwind.ts`**, the function `resolveTailwindConfig` uses this value to construct an absolute file path without enforcing that the file stays within an expected (safe) directory. If an attacker inserts relative path traversal sequences or even an absolute path into the `"tailwindcssConfigPath"` setting, the extension will pass that path to the helper function `requireUncached` (in **`src/util.ts`**), which uses `fs.readFileSync` to read and then transform its contents. Even though the transformed code is not executed, error messages (or logging) may reveal details about the file or its contents.

* **Impact:**
  This vulnerability can allow an attacker who is able to control the workspace (for example, via a malicious repository) to force the extension to read files outside the intended configuration directory. Such arbitrary file reads might lead to unintended disclosure of sensitive information from the victim’s file system if error messages include file contents or path names.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
  - The extension wraps the call to `requireUncached` in a try‑catch block. If an error occurs (for example, when the loaded file is not a valid Tailwind config), it falls back to a default configuration.

* **Missing Mitigations:**
  - There is no check that the user‑provided `"tailwindcssConfigPath"` is located within the workspace or another safe directory.
  - The extension should sanitize and validate any custom path provided to ensure it does not traverse outside trusted boundaries.

* **Preconditions:**
  - The attacker must be able to provide a custom runtime configuration (via a ".bladeformatterrc.json" file in the workspace).
  - The victim must open this workspace in VS Code with the extension enabled (and with the Tailwind CSS sorting feature turned on).
  - The file targeted by the malicious `"tailwindcssConfigPath"` (for example, a file containing sensitive data) must exist and be accessible to the user running VS Code.

* **Source Code Analysis:**
  - In **`src/tailwind.ts`**, the function `resolveTailwindConfig` is defined as follows:
    ```ts
    export function resolveTailwindConfig(
      filepath: string,
      optionPath: string,
    ): string {
      if (!optionPath) {
        return findConfig(__config__, { cwd: path.dirname(filepath) }) ?? "";
      }

      if (path.isAbsolute(optionPath ?? "")) {
        return optionPath;
      }

      const runtimeConfigPath = findConfigFile(filepath);
      return path.resolve(path.dirname(runtimeConfigPath ?? ""), optionPath ?? "");
    }
    ```
    Notice that no checks are made to ensure that the resulting path does not “escape” the workspace (for example via `"../"`).
  - Then, in **`src/extension.ts`**, if the setting to sort Tailwind CSS classes is enabled, the resolved path is passed to:
    ```ts
    try {
      requireUncached(tailwindConfigPath);
    } catch (error) {
      // fallback to default config
      tailwindConfig.tailwindcssConfigPath =
        __non_webpack_require__.resolve("tailwindcss/lib/public/default-config");
    }
    ```
    Here the file is read (and transformed) without any further verification of its path.

* **Security Test Case:**
  - In a test workspace, create a file named **".bladeformatterrc.json"** with contents similar to:
    ```json
    {
      "sortTailwindcssClasses": true,
      "tailwindcssConfigPath": "../sensitive.txt"
    }
    ```
  - Ensure that a file called **"sensitive.txt"** exists outside the workspace (in a directory that the user can normally access) and contains known, sensitive information.
  - Open a Blade file from the workspace in VS Code and trigger the format command.
  - Observe the extension’s behavior. In particular, if `requireUncached` fails to process the file because it does not conform to a valid Tailwind config, the error message shown via `vscode.window.showErrorMessage` may include details (or a file path) from “sensitive.txt”.
  - Verify that the resolved path is not limited to the workspace directory. If the error message or logs reveal the arbitrary file’s path or contents, this confirms the vulnerability.