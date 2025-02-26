## Combined Vulnerability List

This document consolidates vulnerabilities identified in the File Nesting Config project. Duplicate vulnerabilities have been removed, and the following vulnerability is detailed with its description, impact, rank, mitigations, preconditions, source code analysis, and a security test case.

- **Vulnerability Name:** Arbitrary Remote Configuration Injection via Unvalidated Upstream Settings / Supply Chain Attack

  - **Description:**
    The VS Code extension "File Nesting Updater" fetches file nesting configurations from a remote repository's `README.md` file. Specifically, it constructs a URL using user-configurable values `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` to download the `README.md` from `https://cdn.jsdelivr.net/gh`.  The extension then parses this `README.md` to extract a JSON code block marked with ```jsonc, which is expected to contain file nesting patterns. This extracted JSON configuration is then applied to the user's VS Code settings.

    The vulnerability arises because the extension does not validate or sanitize the `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` configuration values. An attacker capable of influencing these settings – either through direct manipulation of user configuration, social engineering, insider threat, or by compromising the upstream repository (`antfu/vscode-file-nesting-config`) – can control the source of the configuration.  If the attacker can modify the `README.md` file at the specified remote location (or a location pointed to by manipulated settings), they can inject malicious or unintended file nesting configurations. When the extension updates, it fetches this compromised configuration and applies it, potentially disrupting the user's VS Code environment. This is a form of supply chain attack if the official upstream repository is compromised, or a more general configuration injection vulnerability if the user is tricked into using a malicious repository.

  - **Impact:**
    - Unauthorized changes to VS Code’s file nesting configuration can cause files to be hidden, erroneously displayed, or reorganized in unexpected ways within the VS Code Explorer.
    - This manipulation can disrupt developer workflows, making it harder for users to locate and manage their files, potentially reducing productivity and causing confusion.
    - An attacker could manipulate the configuration to obscure security-sensitive information by hiding specific file types or changing the visual representation of the project structure, potentially aiding in social engineering or obscuring malicious activities within a project.
    - While primarily affecting the VS Code environment and not directly compromising the user's operating system or sensitive data, this vulnerability can be a stepping stone for more sophisticated attacks if the injected configuration is crafted to mislead users or prepare for further exploitation.
    - In a supply chain attack scenario, widespread adoption of the extension could amplify the impact, affecting many developers who rely on the extension for file nesting configuration.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The URL construction uses a fixed HTTPS endpoint (`https://cdn.jsdelivr.net/gh`), ensuring transport security for the download process itself, after the potentially malicious URL is constructed.
    - The project includes an ESLint configuration with a custom rule ("wildcards‑check") to limit wildcard usage in string literals. However, this rule is for code style and pattern formatting within the project's code, not for validating external configuration inputs.

  - **Missing Mitigations:**
    - **Input Validation and Sanitization:** The extension lacks any validation or sanitization for the `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` configuration values. These values should be strictly validated against an expected format, a predefined whitelist of allowed repositories, or at least be sanitized to prevent URL injection attempts.
    - **Integrity Verification of Remote Content:** There is no mechanism to verify the integrity or authenticity of the fetched `README.md` content or the extracted JSON configuration. Digital signatures or checksum/hash verification should be implemented to ensure the configuration originates from a trusted source and has not been tampered with.
    - **Robust JSON Parsing:** The current JSON extraction relies on brittle regular expressions and string manipulation to parse the JSON configuration from the `README.md`. A robust JSON parser should be used to handle variations in the remote file format and prevent parsing errors or unexpected behavior.
    - **Content Security Policy/Sandboxing (for Extension Context):** While not directly mitigating the configuration injection, implementing a Content Security Policy for the VS Code extension context could limit the impact of a successful configuration injection by restricting the extension's capabilities and preventing execution of potentially malicious code if that were to be introduced via configuration (though this specific vulnerability primarily injects configuration data, not code).

  - **Preconditions:**
    - **Attacker Influence over Configuration:** The attacker must be able to influence the VS Code user configuration for the extension. This could be achieved by:
        - Directly modifying the workspace or user settings JSON file.
        - Socially engineering a user to change the settings.
        - Compromising a supply chain process that automatically sets these configuration values.
        - In a supply chain attack scenario, compromising the official `antfu/vscode-file-nesting-config` repository.
    - **Extension Enabled and Update Triggered:** The "File Nesting Updater" extension must be installed and enabled. The auto-update feature must be active, or the user must manually trigger an update via the "Update config now" command after the malicious configuration is in place.
    - **User Application of Configuration:** The user must confirm or allow the application of the updated configuration when prompted by the extension.

  - **Source Code Analysis:**
    The vulnerability is located in the `fetchLatest` function within `/extension/src/fetch.ts`.

    ```typescript
    export async function fetchLatest() {
      const repo = getConfig<string>('fileNestingUpdater.upstreamRepo')
      const branch = getConfig<string>('fileNestingUpdater.upstreamBranch')
      const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}` // URL_PREFIX is 'https://cdn.jsdelivr.net/gh' and FILE is 'README.md'
      const md = await fetch(url).then(r => r.text())
      const content = (md.match(/```jsonc([\s\S]*?)```/) || [])[1] || ''

      const json = `{${
        content
          .trim()
          .split(/\n/g)
          .filter(line => !line.trim().startsWith('//'))
          .join('\n')
          .slice(0, -1)
      }}`

      const config = JSON.parse(json) || {}
      return config['explorer.fileNesting.patterns']
    }
    ```

    **Step-by-step code analysis:**

    1. **Configuration Retrieval:** The function starts by retrieving the `upstreamRepo` and `upstreamBranch` values directly from the user's VS Code configuration using `getConfig<string>('fileNestingUpdater.upstreamRepo')` and `getConfig<string>('fileNestingUpdater.upstreamBranch')`.  **Crucially, these values are taken without any validation or sanitization.**

    2. **URL Construction:** A URL is constructed by concatenating a fixed prefix `URL_PREFIX` (`https://cdn.jsdelivr.net/gh`), the unsanitized `repo` value, an "@" symbol, the unsanitized `branch` value, and the filename `FILE` (`README.md`). This results in a URL like: `https://cdn.jsdelivr.net/gh/<repo>@<branch>/README.md`.  **The lack of validation on `repo` and `branch` allows an attacker to inject arbitrary repository and branch names into the URL.**

    3. **Fetching Remote Content:** The code uses `fetch(url)` to retrieve the content of the constructed URL. The response is then extracted as text (`r.text()`).

    4. **JSON Extraction via Regex:** A regular expression `(/```jsonc([\s\S]*?)```/)` is used to find and extract the first code block enclosed by ```jsonc and ``` delimiters from the fetched `README.md` content.  **This regex-based parsing is brittle and may fail or produce unexpected results if the `README.md` format deviates.**

    5. **JSON Cleaning (Crude):** The extracted content is then "cleaned" using a series of string manipulations:
        - `trim()`: Removes leading/trailing whitespace.
        - `split(/\n/g)`: Splits the content into lines.
        - `filter(line => !line.trim().startsWith('//'))`: Filters out lines that start with `//` (assumed comments).
        - `join('\n')`: Joins the lines back together.
        - `slice(0, -1)`: Removes the last character. **This last `slice` operation is particularly concerning as it seems intended to remove a trailing comma or similar, but is error-prone and could truncate valid JSON.**
        - The result is wrapped in curly braces `{}` to form a JSON string.

    6. **JSON Parsing:** `JSON.parse(json)` attempts to parse the constructed JSON string into a JavaScript object.

    7. **Configuration Extraction and Return:** Finally, the code extracts the value of the `explorer.fileNesting.patterns` property from the parsed JSON object and returns it.

    **Visualization:**

    ```
    User Configuration (fileNestingUpdater.upstreamRepo, fileNestingUpdater.upstreamBranch) --> No Validation --> URL Construction --> Fetch README.md from Remote --> Regex-based JSON Extraction --> Crude JSON Cleaning --> JSON.parse() --> Extract 'explorer.fileNesting.patterns' --> Return Configuration
    ```

    **Vulnerability Point:** The core vulnerability lies in the **lack of input validation and sanitization** of `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` before they are used to construct the URL for fetching the remote configuration. This allows an attacker to control the source of the configuration and inject malicious data. The **brittle regex-based JSON parsing and crude string manipulation** further exacerbate the issue by making the configuration update process unreliable and potentially vulnerable to format variations in the remote file.

  - **Security Test Case:**
    1. **Preparation:**
       - Set up a test VS Code instance with the "File Nesting Updater" extension installed.
       - **Attacker Controlled Repository:** Create a public or accessible Git repository (e.g., on GitHub, GitLab, or a local mock Git server). In this repository, create a `README.md` file.
       - **Malicious Configuration in README.md:** Within the `README.md` file, add a ```jsonc code block containing malicious or unexpected file nesting configuration. For example:
         ```markdown
         # File Nesting Configuration

         Here is the file nesting configuration:

         ```jsonc
         {
           "explorer.fileNesting.patterns": {
             "*.js": "*.test.js, *.spec.js, vulnerable.js",
             "*.txt": "secret.txt, important.txt"
           }
         }
         ```
         In this example, we are adding `vulnerable.js` to be nested under `*.js` files and nesting `secret.txt` and `important.txt` under `*.txt` files. These are just examples; more disruptive or misleading configurations could be used.

    2. **Extension Configuration Modification:**
       - In VS Code settings (File > Preferences > Settings, or Code > Settings > Settings on macOS), navigate to the "Extensions" section and find the settings for "File Nesting Updater".
       - Modify the following user settings:
         - `"fileNestingUpdater.upstreamRepo"`: Set this to the attacker-controlled repository's username/repository name (e.g., `"attacker-username/attacker-repo"`).
         - `"fileNestingUpdater.upstreamBranch"`: Set this to the branch containing the modified `README.md` (e.g., `"main"` or `"master"`).

    3. **Trigger Manual Update:**
       - Open the Command Palette (Ctrl+Shift+P or Cmd+Shift+P).
       - Type and run the command `antfu.file-nesting.manualUpdate` or "File Nesting Updater: Update config now".

    4. **Verification of Configuration Prompt:**
       - The extension should fetch the `README.md` from the attacker-controlled repository.
       - A notification prompt will appear displaying the updated file nesting configuration extracted from the malicious `README.md`. **Carefully examine this prompt and confirm that it reflects the malicious configuration you injected in step 1.**  Specifically, check for the added or modified nesting patterns (e.g., nesting `vulnerable.js` under `*.js`, and `secret.txt`, `important.txt` under `*.txt`).

    5. **Apply Malicious Configuration:**
       - Click the "Apply" button in the configuration update prompt to apply the malicious configuration to your VS Code settings.

    6. **Observe VS Code Explorer:**
       - Open the VS Code Explorer in a project that contains files matching the patterns in your malicious configuration (e.g., JavaScript files, text files, and specifically, files named `vulnerable.js`, `secret.txt`, `important.txt`).
       - **Verify if the file nesting in the Explorer has changed according to the malicious configuration.** For example, check if `vulnerable.js` is now nested under JavaScript files, and if `secret.txt` and `important.txt` are nested under other text files. If the Explorer reflects the injected malicious configuration, the vulnerability is confirmed.

    7. **Cleanup (Optional):** After testing, revert the "File Nesting Updater" extension settings back to their original values or uninstall the extension to avoid persistent malicious configuration.