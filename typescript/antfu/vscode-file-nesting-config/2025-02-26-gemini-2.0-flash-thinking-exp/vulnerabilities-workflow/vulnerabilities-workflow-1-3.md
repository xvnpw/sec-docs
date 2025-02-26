## Vulnerability List

### Remote Configuration Injection

* Description:
    1. The VS Code extension fetches file nesting patterns from a remote repository specified by the `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` configurations.
    2. The extension constructs a URL using `https://cdn.jsdelivr.net/gh/{repo}@{branch}/README.md` to fetch the configuration.
    3. It extracts JSON content from within ` ```jsonc ``` ` blocks in the fetched README.md.
    4. This extracted JSON is parsed using `JSON.parse` and applied to the VS Code `explorer.fileNesting.patterns` setting.
    5. An attacker can trick a user into setting a malicious repository and branch in the extension settings.
    6. By controlling the content of the `README.md` in the malicious repository, the attacker can inject arbitrary JSON into the `explorer.fileNesting.patterns` setting.
    7. This injected configuration can modify the file nesting behavior in VS Code in unexpected ways, potentially leading to user confusion, data exposure, or further exploitation depending on how VS Code processes file nesting patterns.

* Impact:
    - Configuration injection leading to unexpected and potentially malicious changes in VS Code's file nesting behavior.
    - Potential user confusion and disruption due to altered file organization in the explorer.
    - Possible information disclosure or further exploitation depending on how VS Code handles maliciously crafted file nesting patterns.

* Vulnerability Rank: high

* Currently implemented mitigations:
    - None. The extension directly fetches and applies configuration based on user-provided repository and branch settings.

* Missing mitigations:
    - Input validation for `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` settings to restrict allowed characters and formats, preventing injection of arbitrary URLs or commands.
    - Content validation of the fetched `README.md` before extracting and parsing the JSON configuration. This could include checks for expected JSON structure and prevention of overly complex or malicious patterns.
    - Consider using a more secure method of fetching configuration, or providing a curated list of trusted repositories instead of allowing arbitrary user input for the repository URL.

* Preconditions:
    - The user must have the "File Nesting Updater" VS Code extension installed.
    - The user must configure the `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` settings to point to a repository controlled by the attacker or a compromised repository.

* Source code analysis:
    - **File: `/code/extension/src/fetch.ts`**
    ```typescript
    import { fetch } from 'ofetch'
    import { window, workspace } from 'vscode'
    import type { ExtensionContext } from 'vscode'
    import { getConfig } from './config'
    import { FILE, MSG_PREFIX, URL_PREFIX } from './constants'

    export async function fetchLatest() {
      const repo = getConfig<string>('fileNestingUpdater.upstreamRepo') // [1] User-controlled repo
      const branch = getConfig<string>('fileNestingUpdater.upstreamBranch') // [2] User-controlled branch
      const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}` // [3] URL constructed with user inputs
      const md = await fetch(url).then(r => r.text()) // [4] Fetching content from constructed URL
      const content = (md.match(/```jsonc([\s\S]*?)```/) || [])[1] || '' // [5] Extracting JSON-like content
      const json = `{${ // [6] Wrapping content in curly braces for JSON parsing
        content
          .trim()
          .split(/\n/g)
          .filter(line => !line.trim().startsWith('//'))
          .join('\n')
          .slice(0, -1)
      }}`

      const config = JSON.parse(json) || {} // [7] Parsing JSON content
      return config['explorer.fileNesting.patterns']
    }

    export async function fetchAndUpdate(ctx: ExtensionContext, prompt = true) {
      const config = workspace.getConfiguration()
      const patterns = await fetchLatest() // [8] Fetching latest patterns
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

        config.update('explorer.fileNesting.patterns', { // [9] Updating VS Code configuration
          '//': `Last update at ${new Date().toLocaleString()}`,
          ...patterns,
        }, true)

        ctx.globalState.update('lastUpdate', Date.now())

        window.showInformationMessage(`${MSG_PREFIX} Config updated`)
      }
    }
    ```
    - The code directly uses the user-provided `upstreamRepo` and `upstreamBranch` to construct the URL, without any validation or sanitization.
    - The fetched content is parsed as JSON and directly applied to the VS Code configuration.

* Security test case:
    1. Install the "File Nesting Updater" VS Code extension.
    2. Create a public GitHub repository controlled by the attacker (e.g., `attacker-repo`).
    3. In the `attacker-repo`, create a `README.md` file with the following content:
    ```markdown
    ## File Nesting Configuration

    ```jsonc
    {
        "*.malicious": ["evil.js"]
    }
    ```
    4. In VS Code, open the extension settings.
    5. Change the `fileNestingUpdater.upstreamRepo` setting to `github-username/attacker-repo` (replace `github-username` with the attacker's GitHub username).
    6. Change the `fileNestingUpdater.upstreamBranch` setting to `main` (or the branch where `README.md` is located).
    7. Trigger a manual update of the file nesting configuration by running the command "File Nesting Updater: Manual Update" from the VS Code command palette.
    8. Observe that the `explorer.fileNesting.patterns` setting in VS Code is updated to include the malicious pattern `*.malicious: ["evil.js"]`.
    9. Create a file named `test.malicious` and `evil.js` in a VS Code workspace.
    10. Verify that `evil.js` is now nested under `test.malicious` in the VS Code explorer, demonstrating that the malicious configuration from the attacker's repository has been successfully injected and applied.