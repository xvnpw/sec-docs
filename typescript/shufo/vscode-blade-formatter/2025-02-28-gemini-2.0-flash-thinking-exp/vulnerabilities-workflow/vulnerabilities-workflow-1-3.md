### Vulnerability List

- Vulnerability Name: Arbitrary code execution via malicious Tailwind config file

- Description:
    1. An attacker crafts a malicious `.bladeformatterrc.json` or `.bladeformatterrc` configuration file.
    2. Within this configuration file, the attacker sets the `tailwindcssConfigPath` property to point to a malicious Javascript file they control, which can be located either within the project or at an external location accessible to the user's system.
    3. The attacker places this malicious configuration file in a project directory.
    4. A victim user opens this project directory in VSCode with the vscode-blade-formatter extension installed and enabled.
    5. When the user attempts to format a Blade file (either manually or on save), the extension reads the configuration file, including the attacker-controlled `tailwindcssConfigPath`.
    6. The extension's code, specifically within the `provideDocumentFormattingEdits` function in `extension.ts`, uses the `requireUncached` function from `util.ts` to load the Tailwind CSS configuration file specified by `tailwindcssConfigPath`.
    7. Due to the use of `requireUncached` and insufficient validation of the `tailwindcssConfigPath`, the extension executes the malicious Javascript file specified by the attacker. This results in arbitrary code execution within the context of the VSCode extension.

- Impact:
    Arbitrary code execution within the VSCode extension process. This can have severe consequences, including:
    - Data theft: The attacker can access sensitive information from the user's workspace or system.
    - System compromise: The attacker can gain control over the user's machine, potentially installing malware, creating backdoors, or performing other malicious actions.
    - Further attacks: The attacker can use the compromised extension context to launch attacks on other extensions or the VSCode environment itself.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    No mitigations are currently implemented in the project to prevent arbitrary code execution through malicious Tailwind configuration files. The code directly loads and executes Javascript files specified in the configuration without any validation or sandboxing.

- Missing Mitigations:
    - Input validation and sanitization: The extension should validate and sanitize the `tailwindcssConfigPath` to ensure it points to a file within the workspace and is a valid configuration file, preventing the loading of arbitrary Javascript files.
    - Sandboxing or isolation: The execution environment for the Tailwind CSS configuration file should be sandboxed or isolated to limit the impact of malicious code execution.
    - Secure module loading: Instead of using `requireUncached`, which allows arbitrary code execution, the extension should consider safer alternatives for loading and parsing configuration files, such as JSON parsing or using a more secure module loader that restricts code execution.
    - User warning: If loading a Tailwind configuration file from a custom path is necessary, the extension should display a warning to the user, especially if the path is outside the workspace or in user-writable locations, advising caution and potential security risks.

- Preconditions:
    - The vscode-blade-formatter extension must be installed and enabled in VSCode.
    - The attacker must be able to place a malicious `.bladeformatterrc.json` or `.bladeformatterrc` file within a project directory.
    - The victim user must open this project directory in VSCode and trigger the formatting of a Blade file.
    - The "Sort Tailwind CSS classes" option must be enabled, either through extension settings or the configuration file, as this feature triggers the loading of the Tailwind configuration.

- Source Code Analysis:
    1. **`src/runtimeConfig.ts`**: The `readRuntimeConfig` function parses `.bladeformatterrc.json` or `.bladeformatterrc` files, allowing users to configure extension settings via project-level files. The `RuntimeConfig` interface includes `tailwindcssConfigPath`, which can be set through these configuration files.
    ```typescript
    export interface RuntimeConfig {
        ...
        tailwindcssConfigPath?: string;
        ...
    }

    export function readRuntimeConfig(filePath: string): RuntimeConfig | undefined {
        ...
        const configFileContent = fs.readFileSync(configFilePath).toString();
        const schema: JTDSchemaType<RuntimeConfig> = {
            optionalProperties: {
                ...
                tailwindcssConfigPath: { type: "string" },
                ...
            },
            additionalProperties: true,
        };
        const parse = ajv.compileParser(schema);
        return parse(configFileContent);
    }
    ```
    2. **`src/tailwind.ts`**: The `resolveTailwindConfig` function resolves the path to the Tailwind CSS configuration file. It prioritizes the `tailwindcssConfigPath` from options (runtime config or extension settings). If `optionPath` is provided and absolute, it's used directly. If relative, it's resolved relative to the runtime config file's directory.
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
    3. **`src/extension.ts`**: In the `provideDocumentFormattingEdits` function, the extension reads runtime configuration and retrieves the `tailwindcssConfigPath`. It then calls `resolveTailwindConfig` to get the full path and subsequently uses `requireUncached` to load and execute the module.
    ```typescript
    provideDocumentFormattingEdits(
        document: vscode.TextDocument,
        vscodeOpts: vscode.FormattingOptions,
    ): any {
        ...
        const runtimeConfig = readRuntimeConfig(document.uri.fsPath);

        const tailwindConfig: TailwindConfig = {};

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
                requireUncached(tailwindConfigPath); // Vulnerable line: Executes arbitrary code from tailwindConfigPath
            } catch (error) {
                // fallback to default config
                ...
            }
        }
        ...
    }
    ```
    4. **`src/util.ts`**: The `requireUncached` function directly uses `__non_webpack_require__` to load and execute the module, which is the root cause of the vulnerability.
    ```typescript
    export function requireUncached(moduleName: string) {
        try {
            delete __non_webpack_require__.cache[
                __non_webpack_require__.resolve(moduleName)
            ];

            const fileContent = fs.readFileSync(moduleName, "utf8");

            return transform(fileContent, { transforms: ["imports"] }); // Transform content, but still executes via require
        } catch (err: any) {
            throw err;
        }
    }
    ```
    **Visualization:**

    ```mermaid
    graph LR
        A[Blade File Format Triggered] --> B(readRuntimeConfig);
        B --> C{Runtime Config File?};
        C -- Yes --> D(resolveTailwindConfig);
        C -- No --> D;
        D --> E(requireUncached(tailwindConfigPath));
        E --> F[Malicious Tailwind Config File Execution];
    ```

- Security Test Case:
    1. Create a file named `malicious-tailwind.config.js` in a temporary directory with the following content to verify code execution (e.g., by creating a file in `/tmp` or `$TEMP`):
    ```javascript
    fs = require('fs')
    fs.writeFileSync('/tmp/pwned.txt', 'PWNED!');
    module.exports = { theme: {} };
    ```
    2. Create a new directory, for example, `test-project`.
    3. Inside `test-project`, create a file named `.bladeformatterrc.json` with the following content, replacing `/path/to/tmp/` with the actual path to the temporary directory where you created `malicious-tailwind.config.js`:
    ```json
    {
        "sortTailwindcssClasses": true,
        "tailwindcssConfigPath": "/tmp/malicious-tailwind.config.js"
    }
    ```
    4. Also, inside `test-project`, create an empty Blade file, for example, `test.blade.php`.
    5. Open the `test-project` directory in VSCode.
    6. Open the `test.blade.php` file.
    7. Trigger document formatting by pressing Shift+Alt+F (or Cmd+Shift+P and selecting "Format Document").
    8. Check if the file `/tmp/pwned.txt` (or `$TEMP\\pwned.txt` on Windows) has been created. If it exists and contains "PWNED!", it confirms arbitrary code execution.