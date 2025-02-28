# Vulnerabilities in prettier-vscode Extension

## Vulnerability Name: Arbitrary Code Execution via Malicious Prettier Configuration Files

- **Description:**  
  When a trusted workspace contains a JavaScript configuration file (for example, a ".prettierrc.js") the extension loads that file using Node's built‑in require(). An attacker who submits a repository with a malicious ".prettierrc.js" file may inject arbitrary JavaScript that is executed when the extension calls Prettier's resolveConfig function. In other words, by crafting a custom config file that executes payload code, the attacker forces the extension to run unintended commands.

- **Impact:**  
  An attacker may obtain remote code execution on the victim's machine with the privileges of the VS Code extension host. This could lead to data exfiltration, file system compromise, or other system-level actions.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  • The extension honors VS Code Workspace Trust. When a workspace is untrusted the extension falls back to using its bundled version of Prettier and disables loading of local configuration files, plugins, and modules.  

- **Missing Mitigations:**  
  • When a workspace is marked as trusted, no additional sandboxing or integrity verification of the loaded ".prettierrc" file is performed.  
  • There is no inspection, validation, or sandboxing of configuration files even in trusted workspaces.

- **Preconditions:**  
  • The attacker must supply a repository that the user opens and (mistakenly) trusts.  
  • The repository includes a malicious JavaScript configuration file (e.g. ".prettierrc.js") that executes an attack payload.

- **Source Code Analysis:**  
  • In `ModuleResolver.ts` (method `resolveConfig`), the extension calls  
  `prettierInstance.resolveConfigFile(...)` and then uses the result in  
  `prettierInstance.resolveConfig(fileName, resolveConfigOptions)`.  
  • Prettier's own implementation (invoked via require on a ".prettierrc.js" file) executes the file's contents with full Node privileges.  
  • No additional checks are performed on the configuration file's content before execution.

- **Security Test Case:**  
  1. Create a test repository that includes a ".prettierrc.js" file with a payload that—for example—writes a marker file to disk or logs a network request indicating code execution.  
  2. Open the repository in VS Code and mark the workspace as trusted.  
  3. Trigger the formatting command (e.g. "Format Document") so that the extension calls Prettier's configuration resolver.  
  4. Verify that the payload executes (e.g. by detecting the marker file or monitoring the network call), thereby confirming arbitrary code execution.

## Vulnerability Name: Arbitrary Code Execution via Malicious Local Dependency Resolution

- **Description:**  
  The extension searches for and loads the local "prettier" module from the workspace if one is declared in the repository's package.json. An attacker who controls the repository can include a manipulated package.json along with a malicious "prettier" module (or substitute an attacker‑crafted module in node_modules). When the extension finds and loads the "prettier" module using require (either in the main thread or via a worker thread), the malicious code is executed.

- **Impact:**  
  Arbitrary code execution with full privileges of the extension host process is possible. This could lead to execution of unwanted shell commands, modification of local files, or further compromise of the system.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  • The extension checks whether the workspace is trusted. If not trusted, it uses the bundled Prettier instead of a local module.  

- **Missing Mitigations:**  
  • No integrity or signature verification is performed on the local "prettier" module loaded from the workspace.  
  • In a trusted workspace the extension automatically uses the locally resolved module without further validation.

- **Preconditions:**  
  • The user must open a repository (and mark it as trusted) that has a manipulated package.json and/or node_modules containing a malicious "prettier" (or a module purporting to be "prettier").  
  • The attacker must control the repository content so that the resolution function (see `findPkg` in ModuleResolver.ts) returns an attacker‑controlled module path.

- **Source Code Analysis:**  
  • In `ModuleResolver.ts`, the function `getPrettierInstance` uses `this.findPkg(fileName, "prettier")` to locate the module based on the repository's package.json and node_modules hierarchy.  
  • Once resolved, it loads the module via require (either in `PrettierMainThreadInstance.ts` or by creating a new Worker instance in `PrettierWorkerInstance.ts`).  
  • No checks are performed on the module's integrity, allowing an attacker who controls package.json and the module file to inject arbitrary code.

- **Security Test Case:**  
  1. Prepare a test repository with a package.json that lists "prettier" as a dependency, and supply a crafted malicious "prettier" module in the node_modules folder (for example, a module that on load spawns a benign marker process or writes to a file).  
  2. Open the repository in VS Code and mark it as trusted.  
  3. Trigger any Prettier-related command (for example, run "Format Document").  
  4. Observe that the malicious module is loaded and its payload executes (detectable via side effects such as a file or log entry), proving the vulnerability.

## Vulnerability Name: Arbitrary Code Execution via Malicious Prettier Plugins Injection

- **Description:**  
  Prettier supports plugins to extend its formatting capabilities. The extension obtains the list of plugins from the resolved configuration (see `getSelectors` in PrettierEditService.ts) and passes them along to Prettier's API. An attacker can supply a repository where the configuration (or package.json) specifies a malicious plugin (or a plugin path that resolves to an attacker‑controlled module). When the extension subsequently loads and calls methods from that plugin, the malicious code embedded in the plugin will be executed.

- **Impact:**  
  Execution of arbitrary code via a malicious Prettier plugin can lead to system compromise. This may allow the attacker to steal data, escalate privileges, or perform further malicious actions within the user's environment.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  • When a workspace is untrusted, the extension does not load plugins and falls back to the bundled version of Prettier.  

- **Missing Mitigations:**  
  • In trusted workspaces, there is no extra validation or sandboxing of plugins specified in configuration files.  
  • The extension blindly forwards plugin paths (or objects) to Prettier's API without checking their origin or integrity.

- **Preconditions:**  
  • The attacker must supply a repository that is marked as trusted where the configuration file or package.json specifies a malicious plugin.  
  • The malicious plugin must be crafted so that its execution (upon being loaded by Prettier) performs an unintended action.

- **Source Code Analysis:**  
  • In `PrettierEditService.ts` (within the `getSelectors` method), if the resolved configuration (obtained by calling `moduleResolver.resolveConfig`) contains a "plugins" property, these plugins are aggregated into the list that is later passed to `prettierInstance.getSupportInfo({ plugins })`.  
  • The helper function `resolveConfigPlugins` in `ModuleLoader.ts` attempts to resolve plugin paths using Node's resolve mechanism but no additional security checks (e.g. digital signatures) are applied.  
  • Thus, a malformed or malicious plugin reference directly influences what code is loaded and executed.

- **Security Test Case:**  
  1. Create a repository that includes a malicious Prettier plugin (for example, a JavaScript file that exports a plugin with a "print" function that immediately executes a noticeable benign payload, such as writing a specific file).  
  2. Reference the malicious plugin in the repository's configuration (e.g. via a .prettierrc.js file or package.json).  
  3. Open the repository in VS Code and mark it as trusted.  
  4. Execute a formatting command to force the extension to load the plugin.  
  5. Verify that the payload from the malicious plugin executes (for example, by detecting the output file), which confirms the vulnerability.