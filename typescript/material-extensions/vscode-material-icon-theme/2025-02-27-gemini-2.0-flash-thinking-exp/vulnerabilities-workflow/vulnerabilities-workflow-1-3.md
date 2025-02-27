* Vulnerability Name: Path Traversal in Custom SVG Icon Path Configuration
* Description:
    1. The Material Icon Theme extension allows users to specify custom SVG icons for files and folders through the `settings.json` configuration.
    2. Users can define custom file and folder associations and provide paths to custom SVG files relative to the extension's dist folder.
    3. An attacker can craft a malicious path within the `material-icon-theme.files.associations` or `material-icon-theme.folders.associations` settings in `settings.json` using path traversal sequences (e.g., `../../`).
    4. When VS Code attempts to display an icon for a file or folder matching the malicious association, the extension may attempt to load the SVG icon from the attacker-controlled path. This includes operations like reading the file content to apply saturation or opacity using functions like `setIconSaturation` and `setIconOpacity`.
    5. If the extension does not properly validate and sanitize the provided paths, it could lead to path traversal, allowing an attacker to potentially access files and directories outside of the intended scope (i.e., outside the extension's designated icons directory within `.vscode/extensions`).
    6. Code analysis of `code/src/core/generator/iconSaturation.ts` and `code/src/core/generator/iconOpacity.ts` shows that these functions use `getCustomIconPaths` to retrieve custom icon paths and then use functions like `readdir` and `readFile` with these paths, making them vulnerable to path traversal. The `getCustomIconPaths` function attempts to filter paths but the filter is insufficient.
* Impact:
    - Arbitrary File Read: A successful path traversal attack could allow an attacker to read arbitrary files on the user's file system that the VS Code process has access to. This could include sensitive data like configuration files, source code, or user documents, depending on the permissions of the VS Code process and the attacker's path.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - Based on the provided files, there is no clear indication of effective path traversal mitigation implemented in the project. The `getCustomIconPaths` function in `code/src/core/helpers/customIconPaths.ts` includes a filter `fileName.match(/^[.\/]+/)` which is intended to identify relative paths, but this filter is insufficient to prevent path traversal as it only checks if the path starts with `./` or `/` and does not block `../` sequences within the path.
* Missing Mitigations:
    - Path validation and sanitization: The extension should validate and sanitize user-provided paths for custom SVG icons to prevent path traversal vulnerabilities. This should include:
        - Restricting paths to be within a safe directory (e.g., the extension's icons directory within `.vscode/extensions`).
        - Preventing path traversal sequences like `..`, `./..`, or absolute paths.
        - Using secure path manipulation functions to resolve and normalize paths, ensuring they stay within the intended directory.
* Preconditions:
    - The attacker needs to be able to modify the user's `settings.json` file. This could be achieved through social engineering (tricking the user into manually modifying settings), or in combination with another vulnerability that allows settings modification.
* Source Code Analysis:
    - **`code/src/core/helpers/customIconPaths.ts`**: The function `getCustomIconPaths` is responsible for extracting custom icon paths from the user settings (`filesAssociations`). It uses a regex `fileName.match(/^[.\/]+/)` to identify potential relative paths.
    ```typescript
    export const getCustomIconPaths = (filesAssociations: IconAssociations): string[] => {
      if (!filesAssociations) return [];
      return Object.keys(filesAssociations)
        .map((fileName) => {
          const config = filesAssociations[fileName];
          const iconName = typeof config === 'string' ? config : config.icon;
          if (!iconName) return undefined;
          const isFile = typeof config === 'string' ? true : config.isFile;
          if (!isFile) return undefined;
          const customIconPath = fileName.match(/^[.\/]+/) // <- weak path check
            ? resolvePath(fileName) // using resolvePath which is vulnerable
            : fileName;
          return customIconPath;
        })
        .filter(Boolean) as string[];
    };
    ```
    - **`code/src/core/helpers/resolvePath.ts`**: The `resolvePath` function uses `path.join(__dirname, '..', '..', ...paths)`. `__dirname` points to the directory of `resolvePath.ts` within the `dist` folder after build. This function concatenates paths without sanitization, making it vulnerable to path traversal.
    ```typescript
    import { join } from 'node:path';

    /**
     * Resolves paths relative to the extension's dist folder.
     *
     * @param paths - Path segments to resolve.
     * @returns Resolved absolute path.
     */
    export const resolvePath = (...paths: string[]): string => {
      return join(__dirname, '..', '..', ...paths);
    };
    ```
    - **`code/src/core/generator/iconSaturation.ts` & `code/src/core/generator/iconOpacity.ts`**: Functions `setIconSaturation` and `setIconOpacity` use `getCustomIconPaths` to obtain custom icon paths and then perform file system operations. For example, in `setIconSaturation`:
    ```typescript
    export const setIconSaturation = async (
      saturation: number,
      filesAssociations: Record<string, string>
    ) => {
      // ...
      const customIconPaths = getCustomIconPaths(filesAssociations); // Get paths from user config
      for (const iconPath of customIconPaths) { // Iterate through custom paths
        const customIcons = await readdir(iconPath); // Read directory content from user-provided path
        for (const iconFileName of customIcons) {
          await processSVGFileForSaturation(iconPath, iconFileName, saturation); // Process each file in the user-provided path
        }
      }
      // ...
    };

    const processSVGFileForSaturation = async (
      iconPath: string,
      iconFileName: string,
      saturation: number
    ): Promise<void> => {
      const svgFilePath = join(iconPath, iconFileName);
      if (!(await lstat(svgFilePath)).isFile()) return;

      // Read SVG file
      const svg = await readFile(svgFilePath, 'utf-8'); // Read file content from user-provided path
      // ...
    };
    ```
    `setIconOpacity` has similar structure and uses `processSVGFile` which also calls `readFile` on user-controlled paths.
    - **`code/src/core/generator/renameIconFiles.ts`**: Function `renameIconFiles` also uses `getCustomIconPaths` and performs `readdirSync` and `renameSync` on these paths, demonstrating further usage of potentially attacker-controlled paths in file system operations.
* Security Test Case:
    1. **Setup:** Create a test environment with VS Code and the Material Icon Theme extension installed. Create a directory structure like this within your user profile: `.vscode/extensions/my-extension/icons/malicious.svg` (place a simple SVG file as `malicious.svg`). Also, create a sensitive file outside of this directory for testing purposes, e.g., `sensitive_test_file.txt` in your home directory.
    2. **Modify settings.json:** Open VS Code settings (JSON) and add a custom file association that uses a path traversal sequence to point to the sensitive file. For example:
        ```json
        "material-icon-theme.files.associations": {
            "test.sensitive": "../../../../../sensitive_test_file.txt"
        }
        ```
        (Adjust the `..` sequence based on the relative location of your `.vscode/extensions` directory and the sensitive file).
    3. **Trigger Icon Processing:** Trigger a configuration change or a theme reload in VS Code to force the extension to re-read the configuration and process the icons. A reliable way to do this is to ensure that either icon saturation or opacity is set to a non-default value in `settings.json`. If they are at default values, change them to a non-default value (e.g., set opacity to `0.9`). Then, toggle any Material Icon Theme setting (e.g., switch to a different icon pack and back). This will cause `detectConfigChanges` to be called, which leads to icon processing including saturation and opacity adjustments, and thus triggering the vulnerable code path if opacity or saturation is not at default values.
    4. **Create test file:** Create a file named `test.sensitive` in a workspace opened in VS Code.
    5. **Observe:** Observe if VS Code attempts to load an icon when `test.sensitive` is opened or displayed in the explorer.
    6. **Verification (Manual):** If the vulnerability exists, you might observe an error in the console indicating a failure to load the SVG (because it's likely expecting an SVG and getting a text file). Use developer tools in VS Code (Help -> Toggle Developer Tools) and check the console for errors related to file loading when `test.sensitive` file is created or when theme settings are changed.
    7. **Verification (Automated - Requires Code Access):** With access to the extension's source code, a test could be written to:
        - Mock the VS Code API and settings retrieval.
        - Programmatically set the malicious file association in the configuration.
        - Trigger the icon loading mechanism (e.g., by programmatically calling `setIconOpacity` or `setIconSaturation` with a configuration containing the malicious path).
        - Assert that the file access attempts to go beyond the allowed icon directory or that an error is thrown due to invalid file type or path.