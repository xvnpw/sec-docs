## Vulnerability List for vscode-blade-formatter

### Vulnerability 1: Arbitrary File Read via Tailwind CSS Configuration Path Traversal

* Description:
    1. An attacker crafts a malicious `.bladeformatterrc.json` or `.bladeformatterrc` file.
    2. This configuration file is placed in a workspace that the victim user opens in VSCode.
    3. The malicious configuration file contains a `tailwindcssConfigPath` setting with a path traversal payload (e.g., `../../../../sensitive_file.txt`).
    4. When the user opens a Blade file within the workspace and triggers formatting (either manually or automatically on save), the `vscode-blade-formatter` extension reads the configuration.
    5. Due to insufficient sanitization, the extension's code, specifically in `src/tailwind.ts` and `src/util.ts`, resolves the attacker-controlled path.
    6. The `requireUncached` function in `src/util.ts` attempts to read the file specified by the manipulated path using `fs.readFileSync`.
    7. This allows the attacker to read arbitrary files on the user's file system, as the extension reads the content of the file specified by the path traversal payload.

* Impact:
    An external attacker can potentially read sensitive files from the user's system. This could include configuration files, source code, or any other file that the user has access to, depending on the file path used in the path traversal.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    None. The code directly resolves and reads the file path provided in the configuration without sanitization.

* Missing Mitigations:
    - Path sanitization: Implement validation and sanitization for the `tailwindcssConfigPath` in `src/tailwind.ts` to prevent path traversal. Ensure that the resolved path stays within the workspace or extension's expected directories.
    - Input validation: Validate the `tailwindcssConfigPath` against a whitelist of allowed paths or a strict format to prevent unexpected file paths.

* Preconditions:
    1. The victim user must have the `vscode-blade-formatter` extension installed.
    2. The attacker must be able to provide a malicious workspace to the victim user, containing a crafted `.bladeformatterrc.json` or `.bladeformatterrc` file.
    3. The user must open this workspace in VSCode and trigger formatting on a Blade file.
    4. The `Blade Formatter: Format › Sort Tailwind Css Classes` setting must be enabled, either globally or in the workspace, as this feature triggers the Tailwind configuration loading.

* Source Code Analysis:
    1. **`src/runtimeConfig.ts`:** `readRuntimeConfig` function reads the configuration file and returns `RuntimeConfig` object. It uses `ajv` for validation but `additionalProperties: true` allows extra properties and does not validate string format of `tailwindcssConfigPath`.
    2. **`src/tailwind.ts`:** `resolveTailwindConfig` function takes `optionPath` (from config) and `filepath`.
    ```typescript
    export function resolveTailwindConfig(
        filepath: string,
        optionPath: string,
    ): string {
        if (!optionPath) {
            return findConfig(__config__, { cwd: path.dirname(filepath) }) ?? "";
        }

        if (path.isAbsolute(optionPath ?? "")) {
            return optionPath; // Directly returns absolute path without validation
        }

        const runtimeConfigPath = findConfigFile(filepath);

        return path.resolve(path.dirname(runtimeConfigPath ?? ""), optionPath ?? ""); // Resolves relative path without sanitization
    }
    ```
    The function directly returns `optionPath` if it's absolute and uses `path.resolve` for relative paths which can be exploited for path traversal.
    3. **`src/extension.ts`:** In `provideDocumentFormattingEdits`, the `resolveTailwindConfig` function is called and the result `tailwindConfigPath` is passed to `requireUncached`.
    ```typescript
    const tailwindConfigPath = resolveTailwindConfig(
        document.uri.fsPath,
        runtimeConfig?.tailwindcssConfigPath ?? "",
    );
    tailwindConfig.tailwindcssConfigPath = tailwindConfigPath;

    try {
        requireUncached(tailwindConfigPath); // Calls requireUncached with potentially attacker-controlled path
    } catch (error) {
        // ...
    }
    ```
    4. **`src/util.ts`:** `requireUncached` function reads file content using `fs.readFileSync` based on the provided `moduleName`.
    ```typescript
    export function requireUncached(moduleName: string) {
        try {
            delete __non_webpack_require__.cache[
                __non_webpack_require__.resolve(moduleName)
            ];

            const fileContent = fs.readFileSync(moduleName, "utf8"); // Reads file using moduleName which can be path traversal payload
            // ...
        } catch (err: any) {
            throw err;
        }
    }
    ```

* Security Test Case:
    1. Create a new directory named `malicious-workspace`.
    2. Inside `malicious-workspace`, create a file named `.bladeformatterrc.json` with the following content:
    ```json
    {
        "sortTailwindcssClasses": true,
        "tailwindcssConfigPath": "../../../../../../../../../../../../../../../../../../../../../../../etc/passwd"
    }
    ```
    3. Inside `malicious-workspace`, create a file named `test.blade.php` with any Blade content, for example:
    ```blade
    <div></div>
    ```
    4. Open VSCode and open the `malicious-workspace` folder.
    5. Ensure that the `Blade Formatter: Format › Sort Tailwind Css Classes` setting is enabled.
    6. Open the `test.blade.php` file.
    7. Trigger document formatting by using the command palette (`Ctrl+Shift+P` or `Cmd+Shift+P`) and selecting "Format Document" or by saving the file if format on save is enabled.
    8. Observe if the extension throws an error related to reading `/etc/passwd` or any other indication that the extension attempted to access the file specified in `tailwindcssConfigPath`. You might need to check the extension's output logs (`View > Output`, then select "BladeFormatter" in the dropdown) for detailed error messages.  If the extension attempts to read `/etc/passwd`, this confirms the arbitrary file read vulnerability. A successful exploit will likely result in an error because `/etc/passwd` is probably not a valid javascript/json config file, but the attempt to read it is the vulnerability.

* Vulnerability Rank Justification:
    - High rank is justified because it allows an external attacker to read arbitrary files from the user's system, which can lead to exposure of sensitive information.
    - The precondition requires user interaction (opening a malicious workspace and triggering formatting), but social engineering to achieve this is often feasible.
    - The vulnerability is directly exploitable by manipulating a configuration file setting, making it relatively easy to trigger.