Here is the combined list of vulnerabilities, formatted as markdown:

### Combined Vulnerability List

This document outlines identified vulnerabilities in the Infracost VS Code extension, combining information from provided lists and removing duplicates.

#### 1. Cross-Site Scripting (XSS) via Unsanitized Template Rendering in VS Code Webview

- **Description:**
    - The Infracost VS Code extension utilizes Handlebars templates to render cost breakdowns within webviews.
    - Data rendered in these templates originates from two potential sources: the output of the `infracost` CLI and the infracost configuration file (`infracost.yml`).
    - **Via Infracost CLI Output:** The `infracost` CLI output is parsed as JSON. If an attacker can influence this output, they could inject malicious HTML or JavaScript by crafting malicious resource names, cost component names, units, or prices. This is due to the Handlebars templates potentially not properly escaping HTML entities in these fields before rendering them in the webview.
    - **Via Unsanitized Template Usage:** Even if the data source is safe, if the Handlebars templates use triple-brace notation `{{{ }}}` for rendering any user-supplied data, it will bypass Handlebars' default HTML escaping. If attacker-controlled content (from CLI output or config file) is rendered using triple braces, arbitrary HTML or JavaScript injection is possible.

    - In both scenarios, an attacker could inject malicious content into the webview.

- **Impact:**
    - Successful exploitation of this XSS vulnerability allows arbitrary JavaScript execution within the VS Code webview context. This could lead to:
        - Stealing sensitive information from the VS Code workspace (e.g., environment variables, file contents, tokens, Terraform state files, cloud credentials if accessible).
        - Performing actions on behalf of the user within VS Code or other extensions.
        - Redirecting the user to malicious websites.
        - Displaying misleading information in the cost breakdown webview.
        - Phishing sensitive information from the user.
        - Manipulating the UI of the webview or launching further attacks within the host VS Code environment.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **Partial Mitigation:** Handlebars templates are compiled with auto-escaping enabled by default, which provides some protection against XSS by escaping HTML entities in double-brace `{{ }}` expressions.
    - **However**, the code uses CLI output directly in templates without explicit HTML escaping, and templates might inadvertently use triple-brace `{{{ }}}` expressions for user-controlled data.

- **Missing Mitigations:**
    - **Mandatory Mitigation:** Implement HTML escaping for *all* data originating from the Infracost CLI output and configuration files before rendering it in Handlebars templates.
        - Utilize Handlebars' built-in escaping mechanisms for all fields like resource names, cost component names, units, and prices, ensuring double-brace `{{ }}` syntax is consistently used for data from potentially untrusted sources.
    - **Mandatory Mitigation:** Audit all Handlebars templates (`src/templates/*.hbs`) to ensure that no user-supplied data is rendered using unsafe triple-brace `{{{ }}}` (unescaped) expressions. Replace any instances with double-brace `{{ }}` expressions and ensure proper escaping is applied where needed.
    - **Recommended Mitigation:** Consider adding an extra layer of sanitization for data rendered in webviews, even after Handlebars escaping.
    - **Recommended Mitigation:** Implement a strict Content Security Policy (CSP) for the webview to restrict the capabilities of injected scripts and further mitigate the impact of XSS.

- **Preconditions:**
    - **Attacker Data Injection:** An attacker needs to be able to influence data that is rendered in the webview templates. This can be achieved in two ways:
        - **CLI Output Manipulation:** By compromising the Infracost backend or CLI, or by crafting specific Terraform configurations that lead to malicious output from the `infracost` CLI (e.g., resource names containing malicious scripts).
        - **Malicious Config File:** By supplying a malicious `infracost.yml` configuration file that contains attacker-controlled data that is then rendered in the webview. This could be achieved through a malicious commit or pull request in a public repository.
    - **User Action:** A user must open a cost breakdown webview in VS Code to trigger the rendering of the template and potentially execute the injected script.

- **Source Code Analysis:**
    - **`src/cli.ts`:** Defines `CLI.exec` to execute the infracost CLI and parse JSON output (`infracostJSON.RootObject`). This is a potential source of attacker-controlled data if the CLI or its output is compromised.
    - **`src/workspace.ts`:** `Workspace.runConfigFile` reads and parses `infracost.yml` using `js-yaml.load()`, and processes project paths from the config file. This is another source of attacker-controlled data if a malicious config file is introduced.  `Workspace.runBreakdown` uses `CLI.exec` to run `infracost breakdown` and processes the JSON output.
    - **`src/block.ts`:** `Block.display()` is responsible for rendering webviews. It creates a webview panel and sets its HTML content using `this.template(this)`. The `this` object, passed as context to the template, contains data originating from the CLI output and potentially the config file.
    - **`src/template.ts`:** Compiles Handlebars templates from `.hbs` files.
    - **Templates in `src/templates/*.hbs` (e.g., `block-output.hbs`, `cost-component-row.hbs`):** Use Handlebars expressions like `{{resource.name}}`, `{{costComponent.name}}`, `{{costComponent.unit}}`, `{{costComponent.price}}` to display data.
        - **Vulnerability Point:** If these templates use triple-brace `{{{ }}}` expressions for rendering data from CLI output or config files, or if they rely on default escaping while data contains unescaped HTML, they are vulnerable to XSS. Even with double-brace `{{ }}` expressions, if the input data already contains HTML, it will be rendered as HTML after escaping the special characters, leading to potential XSS.
        - **Example Vulnerable Code (Hypothetical):**  `<div>Resource Name: {{{resource.name}}}</div>` in a template would be vulnerable if `resource.name` could be controlled by an attacker and contain malicious HTML.

- **Security Test Case:**
    1. **Modify CLI Output (for CLI Output Injection test):** In `src/cli.ts`, within `CLI.exec`, add a conditional block to simulate malicious CLI output when `args[0] === 'breakdown'`. This simulated output should include a malicious resource name containing JavaScript code, like `<img src='x' onerror='alert("XSS from CLI Output!")'>`.
    2. **Craft Malicious Config File (for Config File Injection test):** Create an `infracost.yml` file with a project that has a malicious name or other field that will be rendered in the webview, for example:
        ```yaml
        version: 0.1
        projects:
          - path: .
            name: "<img src='x' onerror='alert(\"XSS from Config File!\")'>"
        ```
    3. **Rebuild Extension:** Recompile the VS Code extension after modifying `src/cli.ts` (if testing CLI injection).
    4. **Open Terraform Project:** Open any Terraform project in VS Code (or the test repository with the malicious `infracost.yml`).
    5. **Trigger Infracost:** Run Infracost by saving a Terraform file, refreshing the project tree, or ensuring the extension is active and processes the config file.
    6. **Open Webview:** Open the cost breakdown webview for any resource (via code lens or tree view).
    7. **Verify Vulnerability:** An alert box with "XSS from CLI Output!" or "XSS from Config File!" (depending on the test case) should appear in the webview, indicating successful JavaScript injection. Inspect the webview's HTML source to confirm the injected script is present.
    8. **Cleanup:** Revert changes in `src/cli.ts` (if modified) and remove the malicious `infracost.yml` file. Rebuild the extension to restore normal functionality.

#### 2. Arbitrary Code Execution via Unsafe YAML Deserialization in Infracost Config File

- **Description:**
    - The Infracost VS Code extension reads and parses a configuration file named `infracost.yml` located at the workspace root.
    - The extension uses the `js-yaml` library's `load()` function to parse this YAML file.
    - The `load()` function, by default, uses an unsafe schema that allows for the instantiation of JavaScript functions and other potentially dangerous types through YAML tags (e.g., `!!js/function`).
    - If an attacker can introduce a malicious `infracost.yml` file containing unsafe YAML constructs, arbitrary code can be executed when the extension parses the file.

- **Impact:**
    - Successful exploitation of this vulnerability allows for arbitrary code execution with the privileges of the VS Code extension process.
    - This can lead to:
        - Compromise of the user's machine.
        - Exposure of sensitive data accessible to the VS Code extension.
        - Further escalation within the development environment.
        - Execution of malicious commands on the user's system.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The code directly uses `load(readFileSync(...))` from the `js-yaml` library without any sanitization or safe-parsing measures.

- **Missing Mitigations:**
    - **Mandatory Mitigation:** Replace the unsafe `load()` function with a safe YAML parsing method.
        - Use `js-yaml`'s `safeLoad()` function or the current safe API to parse the `infracost.yml` file.
        - Alternatively, enforce a strict YAML schema that disallows dangerous tags and custom types, ensuring only safe YAML constructs are processed.

- **Preconditions:**
    - **Malicious Config File:** The workspace must contain an `infracost.yml` configuration file that an attacker can control.
        - This could be achieved through a malicious commit or pull request in a public repository.
        - An attacker could also potentially trick a user into placing a malicious `infracost.yml` file in their workspace.

- **Source Code Analysis:**
    - **File:** `src/workspace.ts`
    - **Vulnerable Code Block:**
    ```javascript
    const encoding = await getFileEncoding(configFilePath);
    const doc = <ConfigFile>load(readFileSync(configFilePath, encoding as BufferEncoding));
    ```
    - **Explanation:**
        - The `runConfigFile` method in `workspace.ts` reads the `infracost.yml` file using `readFileSync` and parses it using `load()` from the `js-yaml` library.
        - The `load()` function is known to be unsafe and susceptible to arbitrary code execution when parsing YAML documents containing malicious tags like `!!js/function`.
        - The parsed configuration object `doc` is then used by the extension, but the vulnerability lies in the parsing step itself.

- **Security Test Case:**
    1. **Create Malicious `infracost.yml`:** In a test repository, create an `infracost.yml` file that includes a malicious payload using an unsafe YAML tag. For example, use `!!js/function` to execute JavaScript code when parsed:
        ```yaml
        version: 0.1
        command: !<tag:yaml.org,2002:js/function> 'function() { console.log("Arbitrary code execution!"); }'
        ```
        Or, to display an alert:
        ```yaml
        version: 0.1
        command: !<tag:yaml.org,2002:js/function> 'function() { alert("Arbitrary code execution!"); }'
        ```
    2. **Open Repository in VS Code:** Open the repository containing the malicious `infracost.yml` in VS Code with the Infracost extension installed and activated.
    3. **Verify Payload Execution:** Observe the console output (or an alert, depending on the payload) when the extension initializes its projects or processes the configuration file. You should see "Arbitrary code execution!" logged in the console or an alert box appearing.
    4. **Confirm Mitigation:** Replace `load` with `safeLoad` in `workspace.ts`, rebuild the extension, and repeat steps 2 and 3. Verify that the payload is no longer executed, demonstrating that safe YAML parsing prevents the vulnerability.

#### 3. Arbitrary File Access via Malicious Project Path Injection in Infracost Config File

- **Description:**
    - The `infracost.yml` configuration file defines projects using a "projects" array, where each project has a "path" property.
    - The Infracost VS Code extension, within the `runConfigFile` function in `workspace.ts`, reads these project paths from the config file.
    - These project paths are then directly passed as arguments (using the `--path` flag) to the `infracost` CLI command.
    - No validation or sanitization is performed on these project paths.
    - An attacker who can control the `infracost.yml` file can inject malicious paths, such as relative paths like `../../sensitive` or absolute paths, into the "path" property.
    - This can force the `infracost` CLI to process files and directories outside the intended workspace directory.

- **Impact:**
    - Exploitation of this vulnerability can lead to:
        - Disclosure of sensitive files located outside the intended workspace.
        - Unintended processing of directories outside the repository by the `infracost` CLI.
        - Potential leakage of confidential configuration or system files to the output displayed in the extension's UI, depending on how the CLI processes the given path and generates output.
        - Triggering errors or unexpected behavior in the extension or CLI due to processing unexpected files.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The project paths read from the YAML config file are used directly without any sanitization or validation.

- **Missing Mitigations:**
    - **Mandatory Mitigation:** Implement validation and sanitization for project paths read from the `infracost.yml` configuration file.
        - **Path Whitelisting:**  Validate that supplied project paths are relative to and reside within the workspace directory.
        - **Path Normalization:** Use path normalization techniques to resolve symbolic links and canonicalize paths to prevent directory traversal attacks.
        - **Directory Traversal Prevention:**  Implement checks to prevent directory traversal sequences (e.g., `../`) and absolute paths. Ensure that the resolved project path stays within the workspace boundaries.

- **Preconditions:**
    - **Malicious Config File:** The attacker must be able to commit a malicious `infracost.yml` file to the repository or otherwise influence the content of the configuration file read by the extension.

- **Source Code Analysis:**
    - **File:** `src/workspace.ts`
    - **Vulnerable Code Block:**
    ```javascript
    let args = ['--config-file', configFilePath];
    // ... later in the call, iterating through projects from config ...
    for (const p of config.projects || []) {
        if (p.path) {
            args.push('--path', p.path); // Unsanitized path from config
        }
        // ...
        const out = await this.cli.exec(['breakdown', ...args, '--format', 'json', '--log-level', 'info'], this.root);
        // ...
    }
    ```
    - **Explanation:**
        - The `runConfigFile` method reads project definitions from the parsed `config` object.
        - For each project `p`, if a `path` property is defined, its value `p.path` is directly added to the `args` array that is passed to the `cli.exec` function.
        - `cli.exec` then executes the `infracost breakdown` command with these arguments, including the unsanitized `--path` argument.
        - There are no checks to validate or sanitize `p.path` before it is passed to the CLI, allowing for path injection vulnerabilities.

- **Security Test Case:**
    1. **Create Malicious `infracost.yml`:** Create an `infracost.yml` file that defines at least one project entry with a "path" value set to a directory outside the workspace. For example, to target the parent directory:
        ```yaml
        version: 0.1
        projects:
          - path: ".." # or "../../sensitive-directory" or "/etc"
        ```
    2. **Open Repository in VS Code:** Open the repository containing the malicious `infracost.yml` in VS Code so that the extension reads and processes this configuration file.
    3. **Monitor CLI Arguments:** Monitor the arguments passed to the `infracost` CLI. You can do this by:
        - **Logging:** Add logging statements in `src/cli.ts` within the `CLI.exec` function to print the `args` array before executing the CLI command.
        - **Intercepting `child_process.spawn`:** Use a debugging tool or monkey-patch `child_process.spawn` to intercept and inspect the arguments passed to the CLI execution.
    4. **Verify Unsafe Path Usage:** Confirm that the logged or intercepted CLI arguments include the unsafe path (e.g., `"--path", ".."` ) as specified in the malicious `infracost.yml`.
    5. **Verify Information Disclosure (Optional, depends on CLI behavior):** Depending on how the `infracost` CLI handles processing files outside the workspace and generates output, you might be able to observe disclosure of sensitive file information or error messages containing paths to sensitive directories in the Infracost extension's output. This might require crafting specific Terraform files or directory structures in the parent directory to trigger information leakage via CLI output.
    6. **Validate Mitigation:** Implement path validation as described in "Missing Mitigations" in `src/workspace.ts`. Rebuild the extension and repeat steps 2-4. Verify that the unsafe path is now either rejected or sanitized, and is no longer passed to the CLI, thus mitigating the vulnerability.

#### 4. Insecure Binary Download without Checksum Validation

- **Description:**
    - The `download.sh` script, used during extension packaging, downloads the Infracost CLI binary from `https://infracost.io/downloads/latest`.
    - The script attempts to validate the downloaded binary using a SHA256 checksum downloaded from the same location.
    - **Vulnerability:** If the SHA256 checksum file is not found at the URL (returns HTTP 404), the `download.sh` script **skips** checksum validation and proceeds with the download, potentially packaging a malicious binary if the server has been compromised.
    - An attacker compromising `infracost.io` could replace the legitimate binary with a malicious one and simultaneously remove the checksum file.
    - In such a scenario, users downloading or updating the VSCode extension would unknowingly install a compromised Infracost CLI binary.

- **Impact:**
    - **Critical Impact:** Installation of a compromised Infracost CLI binary can lead to arbitrary code execution on the user's machine with the privileges of the VSCode extension.
    - This can result in:
        - Sensitive data exfiltration (e.g., Terraform configurations, cloud credentials).
        - Installation of malware.
        - Further compromise of the user's system.
        - Widespread impact due to the extension's popularity among developers.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - **Partial Mitigation:** The `download.sh` script *attempts* to perform SHA256 checksum validation under normal circumstances when the checksum file is available.
    - The script downloads the `.sha256` file, uses `shasum -sc` to compare checksums, and exits if validation fails (when the checksum file is found and validation fails).
    - **Location:** `scripts/download.sh`

- **Missing Mitigations:**
    - **Critical Missing Mitigation:** **Enforce Checksum Validation:** The script must **not** skip checksum validation if the SHA256 checksum file is not found (HTTP 404). Instead, it should **fail** the download process and prevent packaging the extension if the checksum file is missing, treating it as a critical error.
    - **Recommended Mitigation:** **Implement Signature Verification:**  Beyond SHA256 checksums, implement digital signature verification of the binary to guarantee authenticity and integrity against sophisticated attackers who might compromise the distribution server. This would involve verifying a digital signature from Infracost on the downloaded binary.

- **Preconditions:**
    - **Attacker Compromise of `infracost.io`:** The attacker must have compromised the `infracost.io` infrastructure to:
        - Replace the legitimate Infracost CLI binary with a malicious one.
        - Remove the corresponding SHA256 checksum file for the replaced binary.
    - **Extension Packaging or User Re-download:** The VSCode extension packaging process must execute `download.sh` *after* the attacker's actions, or a user must re-download/update the extension after these changes have been made on the server.

- **Source Code Analysis:**
    - **File:** `/code/scripts/download.sh`
    - **Vulnerable Code Block:**
    ```sh
    code=$(curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256")
    if [ "$code" = "404" ]; then
      echo "Skipping checksum validation as the sha for the release could not be found, no action needed."
    else
      # ... checksum validation logic ...
    fi
    ```
    - **Explanation:**
        - The script checks the HTTP status code of the SHA256 checksum file.
        - If the code is "404", it incorrectly assumes it's safe to skip validation and proceeds, which is the core vulnerability.
        - The `check_sha` function itself is correctly implemented for checksum validation when the file *is* found.

- **Security Test Case:**
    1. **Pre-setup (Attacker Simulation):**
        - **Compromise `infracost.io` (Simulated):** You don't need to actually compromise `infracost.io`. For testing, you can simulate this by running a local HTTP server (e.g., using `python -m http.server` in a directory) and modifying `download.sh` to point to your local server instead of `infracost.io`.
        - **Replace Binary (Simulated):** On your local server, serve a malicious binary (e.g., a simple shell script echoing "Malicious binary executed") at the path where the legitimate binary is expected (e.g., `/downloads/latest/infracost-linux-amd64`).
        - **Remove Checksum File (Simulated):** Ensure that no SHA256 checksum file exists at the expected path on your local server (e.g., `/downloads/latest/infracost-linux-amd64.tar.gz.sha256`) or that your local server returns a 404 for requests to this checksum file path.
    2. **Victim Setup:**
        - **Clean Environment:** Ensure a clean VSCode development environment where the Infracost extension is not yet installed or can be cleanly re-installed.
        - **Download Extension Source Code:** Clone the VSCode Infracost extension repository locally.
    3. **Modify `download.sh` (Point to Local Server):**
        - In `scripts/download.sh`, temporarily change the `url` variable to point to your local HTTP server address (e.g., `url="http://localhost:8000/downloads/latest"`).
    4. **Package the Extension:**
        - Navigate to the extension's root directory in the terminal.
        - Run the command to package the extension (e.g., `yarn vscode:package`). This will execute the modified `download.sh` script.
    5. **Install the Packaged Extension:**
        - Install the newly packaged `.vsix` file in VSCode.
    6. **Execute Extension Functionality:**
        - Open a Terraform project in VSCode.
        - Trigger the Infracost extension to execute the Infracost CLI binary (e.g., by opening a Terraform file or refreshing the Infracost project tree).
    7. **Verify Malicious Binary Execution:**
        - Check the output of the Infracost extension (e.g., in the "Infracost Debug" output channel or in a terminal if the malicious binary writes to stdout).
        - You should see the output from your malicious binary (e.g., "Malicious binary executed"), indicating that the compromised binary was downloaded and executed because checksum validation was skipped.
    8. **Cleanup:** Revert the changes in `scripts/download.sh` (restore the original `url`) and remove the malicious binary and local HTTP server setup. Rebuild the extension to restore normal functionality.