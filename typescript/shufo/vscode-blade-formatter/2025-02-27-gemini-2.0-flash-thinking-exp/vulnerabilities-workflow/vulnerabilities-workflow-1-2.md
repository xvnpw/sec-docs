- **Vulnerability Name:** Prototype Pollution via Unsanitized Runtime Configuration  
  **Description:**  
  The extension loads runtime configuration from files (".bladeformatterrc.json" or ".bladeformatterrc") via a JSON schema defined in `src/runtimeConfig.ts`. Although the schema defines a list of expected properties, it allows any additional properties (using `"additionalProperties": true`), so keys such as `"__proto__"` are not disallowed. When the parsed configuration is merged into the extension’s options (using the spread operator in `src/extension.ts`), an attacker‑controlled configuration file could inject a key like `"__proto__"`, thereby polluting the prototype of the options object. This pollution may “leak” into all objects created afterward, altering their default behavior and potentially paving the way for further exploitation (for example, if a dependent library relies on unmodified built‑in methods).  
  **Impact:**  
  Prototype pollution of core objects may lead to unexpected or insecure behavior in the extension as well as in any libraries that use the affected objects. In worst‑case scenarios, the polluted prototype could be leveraged to perform arbitrary code execution attacks or bypass security checks.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - The configuration file is parsed using Ajv against a predefined schema.  
  - However, the schema explicitly allows extra properties by setting `"additionalProperties": true`.  
  **Missing Mitigations:**  
  - The schema should be tightened to disallow dangerous keys (e.g. `"__proto__"`, `"constructor"`) either by explicitly listing allowed keys only or by filtering the parsed object before merging.  
  - Add sanitization logic on the runtime configuration so that any keys that could affect the object prototype are removed.  
  **Preconditions:**  
  - The attacker must be able to supply or influence the contents of the runtime configuration (for example, by contributing a malicious ".bladeformatterrc.json" file in a public repository).  
  - The victim must open the compromised workspace in VS Code with this extension enabled.  
  **Source Code Analysis:**  
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
  **Security Test Case:**  
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

- **Vulnerability Name:** Arbitrary File Read via Insecure Tailwind CSS Configuration Path  
  **Description:**  
  The extension allows users to override the Tailwind CSS configuration file path by supplying a value for the key `"tailwindcssConfigPath"` in the runtime configuration. In the module **`src/tailwind.ts`**, the function `resolveTailwindConfig` uses this value to construct an absolute file path without enforcing that the file stays within an expected (safe) directory. If an attacker inserts relative path traversal sequences or even an absolute path into the `"tailwindcssConfigPath"` setting, the extension will pass that path to the helper function `requireUncached` (in **`src/util.ts`**), which uses `fs.readFileSync` to read and then transform its contents. Even though the transformed code is not executed, error messages (or logging) may reveal details about the file or its contents.  
  **Impact:**  
  This vulnerability can allow an attacker who is able to control the workspace (for example, via a malicious repository) to force the extension to read files outside the intended configuration directory. Such arbitrary file reads might lead to unintended disclosure of sensitive information from the victim’s file system if error messages include file contents or path names.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - The extension wraps the call to `requireUncached` in a try‑catch block. If an error occurs (for example, when the loaded file is not a valid Tailwind config), it falls back to a default configuration.  
  **Missing Mitigations:**  
  - There is no check that the user‑provided `"tailwindcssConfigPath"` is located within the workspace or another safe directory.  
  - The extension should sanitize and validate any custom path provided to ensure it does not traverse outside trusted boundaries.  
  **Preconditions:**  
  - The attacker must be able to provide a custom runtime configuration (via a ".bladeformatterrc.json" file in the workspace).  
  - The victim must open this workspace in VS Code with the extension enabled (and with the Tailwind CSS sorting feature turned on).  
  - The file targeted by the malicious `"tailwindcssConfigPath"` (for example, a file containing sensitive data) must exist and be accessible to the user running VS Code.  
  **Source Code Analysis:**  
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
  **Security Test Case:**  
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