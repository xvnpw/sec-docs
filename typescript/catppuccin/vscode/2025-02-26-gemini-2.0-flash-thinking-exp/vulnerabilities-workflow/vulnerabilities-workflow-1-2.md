- **Vulnerability Name:** Arbitrary File Overwrite via Symlink Race in Theme Build Script
  - **Description:**  
    The theme build process (triggered as part of the pre–packaging hook that generates theme JSON files) iterates over the target themes directory and deletes existing files before writing new theme files. No validation is performed to ensure that each file is a regular file. An external attacker who gains write access to the mutable installation (in non‑declarative installs) can create a malicious symbolic link inside the themes directory pointing to an arbitrary file on disk. When the build script runs, it will follow the symbolic link and end up deleting or overwriting files it did not intend to modify.
  - **Impact:**  
    Successful exploitation allows an attacker to force deletion or arbitrary modification of files outside the trusted themes folder. In the worst case, critical files used by the application or even the underlying system could be modified or deleted, thereby undermining overall system integrity.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**  
    • No runtime checks or file-type validations are performed by the theme generation hook when iterating over files (i.e. it does not check for symbolic links).
  - **Missing Mitigations:**  
    • Validate each file’s type before deletion by (a) resolving the true path and confirming it is within the trusted themes directory, and (b) ensuring that symbolic links are not followed.
  - **Preconditions:**  
    • The extension is installed in a mutable (non‑declarative) environment.  
    • A low–privileged attacker is able to write to the themes folder (for example, via local access to the installation).
  - **Source Code Analysis:**  
    1. In the theme–generation hook (see the file `hooks/generateThemes.ts`), the script creates the themes folder (using `mkdir`) and then iterates over all supported flavor names.
    2. For each flavor, it calls a function (e.g. `compileTheme`) and subsequently writes out the JSON file using a statement similar to:  
       `writeFile(path.join(repoRoot, 'themes', `${flavor}.json`), ...)`  
       without checking whether the target is a regular file.
    3. If an attacker-created symbolic link exists in the themes folder, the write operation will follow the link and overwrite or delete the file at the linked destination.
  - **Security Test Case:**  
    1. In an environment where the extension is installed non‑declaratively (i.e. the themes folder is mutable), manually create a symbolic link inside the themes folder (for example, name it `malicious.json`) that points to an arbitrary file outside of the themes folder (such as a sensitive system file).
    2. Run the theme build process so that the theme generation hook is triggered.
    3. Verify that the file pointed to by the symbolic link is either deleted or overwritten.
    4. Confirm that no checks were performed to validate the file type or its resolved safe path before deletion or modification.

---

- **Vulnerability Name:** Forced Global Icon Theme Override via Automatic Sync Mechanism
  - **Description:**  
    The extension implements a “sync” feature that automatically updates the user’s global icon theme based on the active Catppuccin color theme. In the `syncToIconPack()` function (located in `src/utils.ts`), the extension checks whether the Catppuccin icon pack extension is present and if the active color theme is one of the Catppuccin themes. If both conditions are met, it unconditionally updates the global `iconTheme` setting using a hard–coded mapping—without prompting the user or verifying consent.
  - **Impact:**  
    An attacker who introduces a malicious or unexpected workspace configuration (for example, via a workspace's `.vscode/settings.json` forcing the active color theme to a Catppuccin theme) can cause the extension to override the user’s global icon theme. This unauthorized configuration change may be abused for UI–spoofing or social–engineering attacks.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**  
    • The extension checks that the active UI theme is among the supported Catppuccin themes and verifies that the Catppuccin icon pack extension is installed before performing the global configuration update.
  - **Missing Mitigations:**  
    • The extension does not prompt the user for confirmation or provide a safeguard (e.g. a configuration override option) before changing the global setting. Additional validation of workspace configuration sources could also help.
  - **Preconditions:**  
    • The workspace contains a `.vscode/settings.json` that forces the `"workbench.colorTheme"` setting to one of the Catppuccin themes.  
    • The configuration setting `"catppuccin.syncWithIconPack"` is enabled.  
    • The Catppuccin icon pack extension is installed.
  - **Source Code Analysis:**  
    1. In `syncToIconPack()` (in `src/utils.ts`), the function retrieves the active UI theme by calling `getActiveTheme()`, which reads the global color theme (or uses a preferred theme when auto–detection is enabled).
    2. It then validates the active UI theme against a fixed mapping (for example, mapping `"Catppuccin Latte"` to `"catppuccin-latte"`).
    3. If the theme is mapped, the extension calls  
       `workspace.getConfiguration("workbench").update("iconTheme", iconTheme, ConfigurationTarget.Global)`  
       to update the global configuration without any user confirmation.
  - **Security Test Case:**  
    1. Prepare a workspace with a `.vscode/settings.json` that specifies a Catppuccin color theme (for example, `"workbench.colorTheme": "Catppuccin Mocha"`) and ensure that `"catppuccin.syncWithIconPack"` is enabled.
    2. Open the workspace in VSCode with both the Catppuccin theme extension and the Catppuccin icon pack extension installed.
    3. Observe that upon activation (or as a result of configuration change), the extension automatically updates the global `"iconTheme"` setting to the corresponding Catppuccin icon pack (for example, `"catppuccin-mocha"`).
    4. Verify that the update occurs without any user notification or confirmation prompt.