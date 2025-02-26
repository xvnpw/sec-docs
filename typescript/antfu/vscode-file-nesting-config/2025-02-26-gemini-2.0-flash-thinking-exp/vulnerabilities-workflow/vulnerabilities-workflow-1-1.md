## Vulnerability List for vscode-file-nesting-config

### Vulnerability 1: Configuration Injection via Upstream Repo Manipulation

- **Vulnerability Name**: Configuration Injection via Upstream Repo Manipulation
- **Description**:
    1. An attacker identifies a user of the `vscode-file-nesting-config` extension.
    2. The attacker finds the configured upstream repository and branch used by the extension. This configuration is user-defined through VS Code settings `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch`.
    3. The attacker gains write access to the upstream repository. This could be achieved by compromising a maintainer account, submitting a malicious pull request that gets merged, or by directly controlling the repository if the user misconfigures the extension to use an attacker-controlled repo.
    4. The attacker modifies the `README.md` file in the upstream repository, specifically the JSONC code block intended for file nesting patterns. The attacker injects malicious or unwanted file nesting patterns into this block.
    5. When the extension automatically updates or a user manually triggers an update, the extension fetches the modified `README.md` from the attacker-controlled repository.
    6. The extension parses the malicious JSONC block from the fetched `README.md` and updates the user's VS Code `explorer.fileNesting.patterns` setting with the injected patterns.
    7. This results in the user's VS Code file explorer displaying files and folders according to the attacker's injected configuration.

- **Impact**:
    - High. While this vulnerability does not directly lead to remote code execution, it allows an attacker to inject arbitrary file nesting configurations into users' VS Code environments. This can significantly disrupt developer workflows by:
        - **Hiding important files**: Malicious patterns can be crafted to hide specific file types or directories, making it difficult for developers to find and access necessary files.
        - **Misleading file structure**: Injecting patterns that rename or re-nest files can create a confusing and inaccurate representation of the project structure in the VS Code explorer.
        - **Reduced usability and developer frustration**: The altered file nesting can lead to significant frustration and reduced productivity for developers using the extension.
        - **Potential for social engineering**: A sophisticated attacker could craft patterns that subtly alter the file explorer in ways that could be used for social engineering attacks, although this is a less direct and less severe impact.

- **Vulnerability Rank**: High
- **Currently Implemented Mitigations**:
    - None. The extension directly fetches content from a user-configurable URL and applies it without any validation or sanitization of the fetched configuration.
- **Missing Mitigations**:
    - **Input Validation and Sanitization**: The extension should implement robust validation and sanitization of the fetched configuration before applying it to VS Code settings. This should include:
        - **Schema Validation**: Validate the fetched JSON configuration against a predefined schema to ensure it conforms to the expected structure and data types for file nesting patterns.
        - **Pattern Sanitization**: Sanitize the individual file nesting patterns to prevent unexpected characters, excessively broad patterns, or patterns that could cause unintended side effects.
        - **Content Integrity Check**: Implement a mechanism to verify the integrity and authenticity of the fetched content, such as using checksums or signatures, to detect tampering.
    - **Restrict Upstream Sources**: Consider limiting the allowed upstream repositories to a curated list of trusted sources or providing warnings when users configure custom repositories. However, this might reduce the flexibility of the extension.
    - **User Confirmation with Diff**: Before applying updates, especially from automatically updated sources, the extension could display a diff of the changes to the file nesting patterns and ask for explicit user confirmation. This would allow users to review and reject potentially malicious or unwanted changes.

- **Preconditions**:
    - User has installed the `vscode-file-nesting-config` extension.
    - User has the default configuration or has configured `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` settings.
    - An attacker can modify the `README.md` file in the configured upstream repository and branch. This is the primary precondition for exploiting this vulnerability.

- **Source Code Analysis**:
    - File: `/code/extension/src/fetch.ts`
    ```typescript
    import { fetch } from 'ofetch'
    import { window, workspace } from 'vscode'
    import type { ExtensionContext } from 'vscode'
    import { getConfig } from './config'
    import { FILE, MSG_PREFIX, URL_PREFIX } from './constants'

    export async function fetchLatest() {
      const repo = getConfig<string>('fileNestingUpdater.upstreamRepo') // User-configurable repository name
      const branch = getConfig<string>('fileNestingUpdater.upstreamBranch') // User-configurable branch name
      const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}` // Constructs the URL using user-provided and hardcoded values. URL_PREFIX is 'https://cdn.jsdelivr.net/gh', FILE is 'README.md'
      const md = await fetch(url).then(r => r.text()) // Fetches the content of README.md from the constructed URL
      const content = (md.match(/```jsonc([\s\S]*?)```/) || [])[1] || '' // Extracts the content within the first '```jsonc ... ```' block using a regular expression. No validation of the content or source.

      const json = `{${
        content
          .trim()
          .split(/\n/g)
          .filter(line => !line.trim().startsWith('//'))
          .join('\n')
          .slice(0, -1)
      }}` // Prepares the extracted content to be parsed as JSON.  Removes comments, trims, and wraps in curly braces.

      const config = JSON.parse(json) || {} // Parses the extracted content as JSON. If parsing fails, defaults to an empty object. No error handling or validation of the JSON structure.
      return config['explorer.fileNesting.patterns'] // Returns the 'explorer.fileNesting.patterns' property from the parsed JSON. Assumes this property exists and is in the expected format.
    }

    export async function fetchAndUpdate(ctx: ExtensionContext, prompt = true) {
      const config = workspace.getConfiguration()
      const patterns = await fetchLatest() // Calls fetchLatest to retrieve the file nesting patterns. This is where potentially malicious configuration is fetched.
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

        config.update('explorer.fileNesting.patterns', {
          '//': `Last update at ${new Date().toLocaleString()}`,
          ...patterns, // Updates the VS Code 'explorer.fileNesting.patterns' setting with the fetched patterns. No sanitization or validation before applying the configuration.
        }, true)

        ctx.globalState.update('lastUpdate', Date.now())

        window.showInformationMessage(`${MSG_PREFIX} Config updated`)
      }
    }
    ```
    - The code directly uses user-provided configuration (`repo`, `branch`) to construct a URL and fetch content.
    - It extracts the JSONC block using a simple regular expression without any validation of the source or content.
    - The extracted JSON is parsed and directly applied to the VS Code settings without any sanitization or schema validation. This lack of validation makes the extension vulnerable to configuration injection if an attacker can control the content of the fetched `README.md`.

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
        - **Observe that all folders in your project are now displayed as "INJECTED-FOLDER" in the explorer.**
        - **Observe that `.txt` files are nested under their parent folders.**
        - Open your VS Code settings (`settings.json`) and verify that the `explorer.fileNesting.patterns` setting has been updated with the malicious patterns from your `README.md`.