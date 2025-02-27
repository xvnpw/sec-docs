## Vulnerability List

### Vulnerability 1: Arbitrary Code Execution via Malicious Tailwind Configuration

* Description:
    1. The VSCode extension reads configuration settings from `.bladeformatterrc.json` or `.bladeformatterrc` files within the workspace.
    2. These configuration files can specify a `tailwindcssConfigPath` setting, which dictates the location of the Tailwind CSS configuration file used for class sorting during formatting.
    3. The extension uses the `requireUncached` function to load and execute the JavaScript code within the specified Tailwind CSS configuration file.
    4. An attacker who can modify or create a `.bladeformatterrc.json` or `.bladeformatterrc` file in a user's workspace can set the `tailwindcssConfigPath` to point to a malicious JavaScript file.
    5. When the user formats a Blade file within this workspace, the extension will load and execute the attacker's malicious JavaScript file through `requireUncached`, leading to arbitrary code execution within the VSCode extension's context.

* Impact:
    Arbitrary code execution within the VSCode extension context. This can have severe consequences, potentially allowing an attacker to:
    - Steal sensitive data from the user's workspace or machine.
    - Install malware or backdoors on the user's system.
    - Modify files within the workspace.
    - Escalate privileges or perform other malicious actions, depending on the permissions of the VSCode process and the user's system.

* Vulnerability Rank: high

* Currently implemented mitigations:
    None. The extension directly loads and executes the JavaScript file specified by the `tailwindcssConfigPath` without any validation or sanitization.

* Missing mitigations:
    - **Input Validation and Sanitization:** The extension should validate the `tailwindcssConfigPath` to ensure it points to a legitimate Tailwind CSS configuration file and is within the workspace's boundaries. It should prevent loading files from outside the workspace or files with unexpected extensions.
    - **Sandboxing or Isolation:** The process of loading and executing the Tailwind CSS configuration should be sandboxed or isolated to limit the potential damage from malicious code execution.
    - **User Warning:**  The extension should warn users about the security risks of using configuration files from untrusted sources or workspaces and advise caution when opening workspaces from unknown origins.

* Preconditions:
    1. **Attacker Workspace Access:** An attacker needs to gain the ability to modify or create a `.bladeformatterrc.json` or `.bladeformatterrc` file within the user's workspace. This could be achieved through various means, such as:
        - Compromising a project's repository and injecting a malicious configuration file.
        - Social engineering to trick a user into opening a workspace containing a malicious configuration file.
        - Exploiting other vulnerabilities on the user's system to gain file system access and modify workspace files.
    2. **User Action:** The user must open a Blade file within the compromised workspace and trigger the formatting action, either manually or automatically upon saving.
    3. **`sortTailwindcssClasses` Enabled:** The `sortTailwindcssClasses` setting must be enabled, either globally or within the workspace configuration, for the Tailwind CSS configuration path to be considered and loaded.

* Source code analysis:
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
            return optionPath;
        }

        const runtimeConfigPath = findConfigFile(filepath);

        return path.resolve(path.dirname(runtimeConfigPath ?? ""), optionPath ?? "");
    }
    ```
    The function checks for absolute paths but lacks validation to ensure the path is safe or points to a valid configuration file type.
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
            requireUncached(tailwindConfigPath); // Potential code execution
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

            const fileContent = fs.readFileSync(moduleName, "utf8");

            return transform(fileContent, { transforms: ["imports"] }); // JavaScript code execution
        } catch (err: any) {
            throw err;
        }
    }
    ```
    The `transform` function from `sucrase` will execute the JavaScript code within the file, making it vulnerable to code injection if `moduleName` (in this case, `tailwindConfigPath`) is controlled by an attacker.

* Security test case:
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