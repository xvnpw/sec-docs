## Combined Vulnerability List for vscode-file-nesting-config

### Vulnerability 1: Configuration Injection via Upstream Repository Manipulation

- **Vulnerability Name**: Configuration Injection via Upstream Repository Manipulation
- **Description**:
    1. An attacker identifies a user of the `vscode-file-nesting-config` extension.
    2. The attacker finds the configured upstream repository and branch used by the extension. This configuration is user-defined through VS Code settings `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch`.
    3. The attacker gains write access to the upstream repository. This could be achieved by compromising a maintainer account, submitting a malicious pull request that gets merged, or by directly controlling the repository if the user misconfigures the extension to use an attacker-controlled repo. Alternatively, the attacker can trick a user into directly setting a malicious repository and branch in the extension settings.
    4. The attacker modifies the `README.md` file in the upstream repository, specifically the JSONC code block intended for file nesting patterns. The attacker injects malicious or unwanted file nesting patterns into this block.
    5. When the extension automatically updates or a user manually triggers an update, the extension fetches the `README.md` from the attacker-controlled repository. The extension constructs a URL using `https://cdn.jsdelivr.net/gh/{repo}@{branch}/README.md` to fetch the configuration.
    6. The extension extracts JSON content from within ` ```jsonc ``` ` blocks in the fetched `README.md`. This extracted JSON is parsed using `JSON.parse`.
    7. The extension parses the malicious JSONC block from the fetched `README.md` and updates the user's VS Code `explorer.fileNesting.patterns` setting with the injected patterns.
    8. This results in the user's VS Code file explorer displaying files and folders according to the attacker's injected configuration, modifying the file nesting behavior in VS Code in unexpected ways.

- **Impact**:
    - High. While this vulnerability does not directly lead to remote code execution, it allows an attacker to inject arbitrary file nesting configurations into users' VS Code environments. This can significantly disrupt developer workflows by:
        - **Hiding important files**: Malicious patterns can be crafted to hide specific file types or directories, making it difficult for developers to find and access necessary files.
        - **Misleading file structure**: Injecting patterns that rename or re-nest files can create a confusing and inaccurate representation of the project structure in the VS Code explorer.
        - **Reduced usability and developer frustration**: The altered file nesting can lead to significant frustration and reduced productivity for developers using the extension.
        - **Potential for social engineering**: A sophisticated attacker could craft patterns that subtly alter the file explorer in ways that could be used for social engineering attacks.
        - **Configuration injection**: Leading to unexpected and potentially malicious changes in VS Code's file nesting behavior.
        - **Potential user confusion and disruption**: Due to altered file organization in the explorer.
        - **Possible information disclosure or further exploitation**: Depending on how VS Code handles maliciously crafted file nesting patterns.

- **Vulnerability Rank**: High
- **Currently Implemented Mitigations**:
    - None. The extension directly fetches content from a user-configurable URL and applies it without any validation or sanitization of the fetched configuration. The extension directly fetches and applies configuration based on user-provided repository and branch settings.
- **Missing Mitigations**:
    - **Input Validation and Sanitization**: The extension should implement robust validation and sanitization of the fetched configuration before applying it to VS Code settings. This should include:
        - **Schema Validation**: Validate the fetched JSON configuration against a predefined schema to ensure it conforms to the expected structure and data types for file nesting patterns.
        - **Pattern Sanitization**: Sanitize the individual file nesting patterns to prevent unexpected characters, excessively broad patterns, or patterns that could cause unintended side effects.
        - **Content Integrity Check**: Implement a mechanism to verify the integrity and authenticity of the fetched content, such as using checksums or signatures, to detect tampering.
    - **Restrict Upstream Sources**: Consider limiting the allowed upstream repositories to a curated list of trusted sources or providing warnings when users configure custom repositories. However, this might reduce the flexibility of the extension.
    - **User Confirmation with Diff**: Before applying updates, especially from automatically updated sources, the extension could display a diff of the changes to the file nesting patterns and ask for explicit user confirmation. This would allow users to review and reject potentially malicious or unwanted changes.
    - **Input validation for `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` settings**: To restrict allowed characters and formats, preventing injection of arbitrary URLs or commands.
    - **Content validation of the fetched `README.md`**: Before extracting and parsing the JSON configuration. This could include checks for expected JSON structure and prevention of overly complex or malicious patterns.
    - **Consider using a more secure method of fetching configuration**: Or providing a curated list of trusted repositories instead of allowing arbitrary user input for the repository URL.

- **Preconditions**:
    - User has installed the `vscode-file-nesting-config` extension.
    - User has the default configuration or has configured `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` settings.
    - An attacker can modify the `README.md` file in the configured upstream repository and branch. This is the primary precondition for exploiting this vulnerability.
    - The user must configure the `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` settings to point to a repository controlled by the attacker or a compromised repository, or be tricked into doing so.

- **Source Code Analysis**:
    - File: `/code/extension/src/fetch.ts`
    ```typescript
    import { fetch } from 'ofetch'
    import { window, workspace } from 'vscode'
    import type { ExtensionContext } from 'vscode'
    import { getConfig } from './config'
    import { FILE, MSG_PREFIX, URL_PREFIX } from './constants'

    export async function fetchLatest() {
      const repo = getConfig<string>('fileNestingUpdater.upstreamRepo') // [1] User-controlled repo, User-configurable repository name
      const branch = getConfig<string>('fileNestingUpdater.upstreamBranch') // [2] User-controlled branch, User-configurable branch name
      const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}` // [3] URL constructed with user inputs, Constructs the URL using user-provided and hardcoded values. URL_PREFIX is 'https://cdn.jsdelivr.net/gh', FILE is 'README.md'
      const md = await fetch(url).then(r => r.text()) // [4] Fetching content from constructed URL, Fetches the content of README.md from the constructed URL
      const content = (md.match(/```jsonc([\s\S]*?)```/) || [])[1] || '' // [5] Extracting JSON-like content, Extracts the content within the first '```jsonc ... ```' block using a regular expression. No validation of the content or source.
      const json = `{${ // [6] Wrapping content in curly braces for JSON parsing, Prepares the extracted content to be parsed as JSON.  Removes comments, trims, and wraps in curly braces.
        content
          .trim()
          .split(/\n/g)
          .filter(line => !line.trim().startsWith('//'))
          .join('\n')
          .slice(0, -1)
      }}`

      const config = JSON.parse(json) || {} // [7] Parsing JSON content, Parses the extracted content as JSON. If parsing fails, defaults to an empty object. No error handling or validation of the JSON structure.
      return config['explorer.fileNesting.patterns'] // Returns the 'explorer.fileNesting.patterns' property from the parsed JSON. Assumes this property exists and is in the expected format.
    }

    export async function fetchAndUpdate(ctx: ExtensionContext, prompt = true) {
      const config = workspace.getConfiguration()
      const patterns = await fetchLatest() // [8] Fetching latest patterns, Calls fetchLatest to retrieve the file nesting patterns. This is where potentially malicious configuration is fetched.
      let shouldUpdate = true

      const oringalPatterns = { ...(config.get<object>('explorer.fileNesting.patterns') || {}) }
      delete oringalPatterns['//']
      // no change
      if (Object.keys(oringalPatterns).length > 0 && JSON.stringify(patterns) === JSON.stringify(oringalPatterns))
        return false

      if (prompt) {
        const buttonUpdate = 'Update'
        const buttonSkip = 'Skip this time'
        const result = await window.showInformationMessage(
          `${MSG_PREFIX} new config found, do you want to update?`,
          buttonUpdate,
          buttonSkip,
        )
        shouldUpdate = result === buttonUpdate
      }

      if (shouldUpdate) {
        if (config.inspect('explorer.fileNesting.enabled')?.globalValue == null)
          config.update('explorer.fileNesting.enabled', true, true)

        if (config.inspect('explorer.fileNesting.expand')?.globalValue == null)
          config.update('explorer.fileNesting.expand', false, true)

        config.update('explorer.fileNesting.patterns', { // [9] Updating VS Code configuration, Updates the VS Code 'explorer.fileNesting.patterns' setting with the fetched patterns. No sanitization or validation before applying the configuration.
          '//': `Last update at ${new Date().toLocaleString()}`,
          ...patterns,
        }, true)

        ctx.globalState.update('lastUpdate', Date.now())

        window.showInformationMessage(`${MSG_PREFIX} Config updated`)
      }
    }
    ```
    - The code directly uses user-provided configuration (`repo`, `branch`) to construct a URL and fetch content.
    - It extracts the JSONC block using a simple regular expression without any validation of the source or content.
    - The extracted JSON is parsed and directly applied to the VS Code settings without any sanitization or schema validation. This lack of validation makes the extension vulnerable to configuration injection if an attacker can control the content of the fetched `README.md`.
    - The code directly uses the user-provided `upstreamRepo` and `upstreamBranch` to construct the URL, without any validation or sanitization.
    - The fetched content is parsed as JSON and directly applied to the VS Code configuration.

- **Security Test Case**:
    1. **Prerequisites**:
        - Ensure you have VS Code installed.
        - Install the `vscode-file-nesting-config` extension in VS Code.
        - You will need a GitHub account to create a test repository.
    2. **Setup Attacker Repository**:
        - Create a new public GitHub repository (e.g., `attacker-repo`).
        - In the `attacker-repo`, create a `README.md` file.
        - Add the following content to `README.md`. This content includes a malicious file nesting configuration that will rename all folders to "INJECTED-FOLDER" and nest all `.txt` files under their parent folders.
        ```markdown
        # Malicious File Nesting Config

        This README contains a malicious file nesting configuration.

        \`\`\`jsonc
        {
          "explorer.fileNesting.patterns": {
            "**": "$(folder-opened) > INJECTED-FOLDER",
            "*.txt": "$(file-text) > "
          }
        }
        \`\`\`
        ```
        - Commit and push the `README.md` file to the `main` branch of your `attacker-repo`.
        - Alternatively, for a different malicious pattern, use the following content which injects a pattern `*.malicious: ["evil.js"]`:
        ```markdown
        ## File Nesting Configuration

        ```jsonc
        {
            "*.malicious": ["evil.js"]
        }
        ```
    3. **Configure Extension to use Attacker Repository**:
        - Open VS Code.
        - Go to VS Code settings (`File` > `Preferences` > `Settings` or `Code` > `Settings` > `Settings` on macOS).
        - Search for `fileNestingUpdater.upstreamRepo`.
        - Change the value of `fileNestingUpdater.upstreamRepo` to your attacker repository name, e.g., `your-github-username/attacker-repo`.
        - Ensure `fileNestingUpdater.upstreamBranch` is set to `main` (or the branch where you pushed the malicious `README.md`).
    4. **Trigger Update**:
        - Open the command palette (`Ctrl+Shift+P` or `Cmd+Shift+P`).
        - Execute the command `File Nesting Updater: Manual Update`.
        - If prompted to update, click "Update".
    5. **Verify Vulnerability**:
        - After the update completes, observe the file explorer in VS Code.
        - Create or open a project with some folders and `.txt` files.
        - **Observe that all folders in your project are now displayed as "INJECTED-FOLDER" in the explorer (if you used the first malicious pattern).**
        - **Observe that `.txt` files are nested under their parent folders (if you used the first malicious pattern).**
        - **Alternatively, if you used the second pattern, create a file named `test.malicious` and `evil.js` in a VS Code workspace. Verify that `evil.js` is now nested under `test.malicious` in the VS Code explorer.**
        - Open your VS Code settings (`settings.json`) and verify that the `explorer.fileNesting.patterns` setting has been updated with the malicious patterns from your `README.md`.

### Vulnerability 2: Potential SSRF via Unsanitized Upstream Repository Configuration

- **Vulnerability Name:** Potential SSRF via Unsanitized Upstream Repository Configuration
- **Description:**
  - The VS Code extension fetches file nesting configuration data from a remote URL that is built directly from configuration values. In the function `fetchLatest()`, the extension reads user (or workspace) configuration keys—specifically,
    `"fileNestingUpdater.upstreamRepo"` and `"fileNestingUpdater.upstreamBranch"`—without any validation or sanitization.
  - An attacker who can force a victim’s workspace to use malicious values (for example, through a compromised project settings file or social‐engineering the user into accepting altered configuration) can supply a repository string that is not a standard GitHub repository.
  - When the extension’s update is triggered (manually via the `antfu.file-nesting.manualUpdate` command or automatically based on the auto-update interval), the function constructs a URL using template literals:
    ```
    const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}`
    ```
    If—for example—the attacker sets
    `upstreamRepo = "127.0.0.1:8000/malicious"` and `upstreamBranch = "main"`, then the resulting URL becomes:
    `https://cdn.jsdelivr.net/gh/127.0.0.1:8000/malicious@main/README.md`.
  - The extension then issues a network request to that URL (via the `ofetch` library) and later consumes the returned data. As a result, the extension may be induced to request arbitrary resources—including those internal to the victim’s network—if the attacker can control the configuration values.

- **Impact:**
  - **Server-Side Request Forgery (SSRF):** The victim’s VS Code client (running the extension) will issue HTTP(S) requests to URLs controlled by the attacker. In corporate or restricted network environments, this may allow an attacker to probe or access internal services that would otherwise be inaccessible from the outside.
  - **Data Exposure:** Malicious responses from an attacker–controlled endpoint might alter the local file nesting configuration (or even later trigger behavior in VS Code if the format is specially crafted) and could be used to gather information about the internal network.
  - Although the extension does not execute dynamic code from the fetched resource, the ability to cause arbitrary outbound requests from a client inside a protected network constitutes a high‐severity risk.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - There is currently no sanitization or validation in place for the values returned by `getConfig()` for `"fileNestingUpdater.upstreamRepo"` or for `"fileNestingUpdater.upstreamBranch"`.
  - The URL is constructed by simply interpolating these settings into a fixed URL prefix (`https://cdn.jsdelivr.net/gh`), so any mitigation would have to be implemented within the extension code itself (or via limitations in the VS Code settings management).

- **Missing Mitigations:**
  - **Input Validation:** There is no check that the user-specified repository name conforms to a safe, well-defined format (for example, a regex such as `/^[\w-]+\/[\w.-]+$/` to enforce a GitHub "owner/repo" pattern).
  - **Whitelist Enforcement:** No mechanism is provided to restrict the upstream repository or branch to known safe values.
  - **Error Handling/Logging:** The extension does not log or throw an alert if the fetched URL does not match an expected pattern.

- **Preconditions:**
  - The attack requires that the attacker be able to influence or supply configuration values for the keys:
    - `fileNestingUpdater.upstreamRepo`
    - `fileNestingUpdater.upstreamBranch`
  - This may happen if:
    - The workspace settings or user settings are prepopulated by a project file (for example, via version-controlled settings) that the attacker can modify (for instance, through a pull request or commit to a public repository).
    - The victim is socially engineered into installing a workspace with a malicious configuration.
  - The victim’s machine must be configured to allow the extension to perform outbound HTTPS requests (which is the normal behavior).

- **Source Code Analysis:**
  - In `fetchLatest()` (located in `/code/extension/src/fetch.ts`):
    - The extension calls:
      ```js
      const repo = getConfig<string>('fileNestingUpdater.upstreamRepo')
      const branch = getConfig<string>('fileNestingUpdater.upstreamBranch')
      ```
      These values come directly from the workspace configuration without any checks.
    - The URL is built via:
      ```js
      const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}`
      ```
      Given that `URL_PREFIX` is a constant (`'https://cdn.jsdelivr.net/gh'`) and `FILE` is `'README.md'`, the entire URL depends solely on the values of `repo` and `branch`.
    - Because the values are used “as is”, an attacker can supply values that cause the extension to initiate requests to unintended endpoints.
    - A simple diagram of the flow:
      - **User Settings/Workspace Config:**
        `upstreamRepo` → *controlled malicious value*
        `upstreamBranch` → *controlled (or default) value*
      - **Inside `fetchLatest()`:**
        Construct URL:
        `https://cdn.jsdelivr.net/gh/<maliciousRepo>@<branch>/README.md`
      - **Fetch Action:** The extension calls `fetch(url)` and processes the resulting text.
  - No sanitization step or validation function is applied between reading the configuration values and using them in the URL.

- **Security Test Case:**
  1. **Setup:** In a controlled test environment (using a test instance of VS Code), install the extension.
  2. **Configuration Change:** Manually update the VS Code settings (either the user or workspace configuration) to set:
     - `"fileNestingUpdater.upstreamRepo": "127.0.0.1:8000/malicious"`
     - `"fileNestingUpdater.upstreamBranch": "main"`
  3. **Trigger Update:** Execute the command `antfu.file-nesting.manualUpdate` from the command palette.
  4. **Observation:** Using network monitoring tools (or by logging in the test harness), observe that the extension makes an HTTP request to:
     ```
     https://cdn.jsdelivr.net/gh/127.0.0.1:8000/malicious@main/README.md
     ```
     instead of a properly formatted GitHub repository URL.
  5. **Verification:** Confirm that no validation error was raised and that the extension processes (or attempts to process) content returned by this malicious endpoint.
  6. **Conclusion:** Demonstrate that unsanitized configuration values can be exploited to force the extension to perform unintended network requests (SSRF).