## Vulnerability Report: Npm Intellisense Extension

### Vulnerability 1: Path Traversal in Package Subfolder Intellisense

* Vulnerability Name: Path Traversal in Package Subfolder Intellisense
* Description:
    1. The Npm Intellisense extension, when the `packageSubfoldersIntellisense` feature is enabled, allows path traversal when resolving module subfolders.
    2. When a user types an import statement like `import something from 'module-name/subfolder'`, the extension attempts to provide autocompletion for subfolders within the specified module in `node_modules`.
    3. The extension constructs a file path by joining the workspace root, 'node_modules', and the user-provided module path fragment.
    4. If the user-provided path fragment contains path traversal sequences like `..`, it's possible to traverse out of the intended `node_modules` directory and access files and directories within the workspace.
    5. The `readDir` function is used to list files in the constructed path. While `readDir` is meant for directories, path traversal allows to list content of directories outside of `node_modules` but within workspace.
* Impact:
    - Information Disclosure: An attacker can potentially list directories and check for the existence of files within the workspace directory structure, outside of the `node_modules` folder. This could expose sensitive project structure information, configuration files, or source code file names.
    - Limited Arbitrary File Read: While the vulnerability uses `readDir` which is intended for directories, and might fail if traversal leads to a file, it still might be possible to trigger errors or side-effects by pointing to specific files using traversal.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The code directly uses user-provided path fragments in `path.join` without sanitization or validation for path traversal sequences.
* Missing Mitigations:
    - Input sanitization: Sanitize the `pkgFragmentSplit` array in `readModuleSubfolders` function to remove or reject path traversal sequences like `..`.
    - Path validation: After resolving the path using `path.join`, validate that the resolved path is still within the intended `node_modules` directory.
* Preconditions:
    - The `npm-intellisense.packageSubfoldersIntellisense` setting must be enabled in the user's VS Code settings.
    - The user must be working within a VS Code workspace that has a `node_modules` directory and at least one dependency installed.
    - The user must be in the process of typing an import statement that triggers the autocompletion.
* Source Code Analysis:
    - File: `/code/src/provide.ts`
    - Function: `readModuleSubFolders`
    ```typescript
    function readModuleSubFolders(dependencies: string[], state: State, fsf: FsFunctions) {
        const fragments: Array<string> = state.textCurrentLine.split('from ');
        const pkgFragment: string = fragments[fragments.length - 1].split(/['"]/)[1]; // User input from import statement
        const pkgFragmentSplit = pkgFragment.split('/'); // Split user input by '/'
        const packageName: string = pkgFragmentSplit[0];

        if (dependencies.filter(dep => dep === packageName).length) {
            const path = join(state.rootPath, 'node_modules', ...pkgFragmentSplit); // Vulnerable path construction - user input directly used in path.join
            // Todo: make the replace function work with other filetypes as well
            return fsf.readDir(path) // File system operation on potentially traversed path
                .then(files => files.map(file => pkgFragment + file.replace(/\.js$/, '')))
                .catch(err => ['']);
        }

        return Promise.resolve(dependencies);
    }
    ```
    - The vulnerability lies in the line `const path = join(state.rootPath, 'node_modules', ...pkgFragmentSplit);`. The `pkgFragmentSplit` array, derived from user input `pkgFragment`, is directly used in `path.join` without any validation. This allows path traversal sequences like `..` in `pkgFragment` to manipulate the final path and potentially escape the `node_modules` directory.
    - The function then uses `fsf.readDir(path)` to read the directory at the constructed path. If the path is successfully traversed outside `node_modules` but still within the workspace, `readDir` will list the files and directories in the traversed location.

* Security Test Case:
    1. Open VS Code and create a new workspace or open an existing Javascript/Typescript project.
    2. Ensure that the workspace root has a `package.json` file and run `npm install` to install dependencies (e.g., `lodash`).
    3. Enable the `npm-intellisense.packageSubfoldersIntellisense` setting by setting it to `true` in VS Code settings.
    4. Create a new Javascript or Typescript file (e.g., `test.js`) in the workspace root.
    5. In `test.js`, type the following import statement: `import _ from 'lodash/../../'` and place the cursor at the end of the line, after `//`.
    6. Wait for the autocompletion suggestions to appear.
    7. Observe the autocompletion list. If the list contains files and directories from the workspace root directory (e.g., `package.json`, `test.js`, `node_modules`, `src`, etc.), it confirms the path traversal vulnerability. The extension is listing the contents of the workspace root directory instead of subfolders within the `lodash` module inside `node_modules`.