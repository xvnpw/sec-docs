## Combined Vulnerability Report

This report consolidates multiple descriptions of a critical vulnerability found in the "File Nesting Updater" VSCode extension. This vulnerability allows for malicious configuration injection from a remote repository, potentially leading to remote code execution.

### Vulnerability: Malicious Configuration Injection via Upstream Repository

*   **Vulnerability Name:** Malicious Configuration Injection via Upstream Repository

*   **Description:**
    The "File Nesting Updater" VSCode extension is vulnerable to malicious configuration injection. The extension fetches file nesting patterns from a remote `README.md` file in a GitHub repository specified by the user in the extension settings (`fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch`). An attacker who gains control over this remote `README.md` file can inject malicious file nesting patterns. These patterns are then applied directly to the user's VSCode configuration, specifically the `explorer.fileNesting.patterns` setting, without any validation or sanitization.

    **Step-by-step exploitation:**
    1.  **Attacker Setup:** A malicious actor creates a GitHub repository and crafts a `README.md` file containing a JSON code block (labeled `jsonc`) with malicious configurations. This could include harmful file nesting patterns or, more critically, payloads designed for remote code execution, such as malicious tasks or debugger configurations.
    2.  **User Configuration Manipulation:** The attacker tricks a user into configuring the "File Nesting Updater" extension to use the attacker's repository as the upstream source. This can be achieved through social engineering, phishing, or by compromising a shared workspace configuration file that overrides user settings.
    3.  **Configuration Fetch:** When the extension updates the file nesting configuration (either automatically via `fileNestingUpdater.autoUpdate` or manually triggered by the user using the `antfu.file-nesting.manualUpdate` command), it constructs a URL based on the user-provided `upstreamRepo` and `upstreamBranch` settings.
    4.  **Malicious Content Retrieval:** The extension fetches the `README.md` file from the attacker-controlled repository via the constructed URL.
    5.  **Configuration Extraction:** The extension extracts the JSONC code block from the `README.md` file using regular expressions.
    6.  **Unsafe Configuration Application:** The extension parses the extracted JSON content and blindly merges the `explorer.fileNesting.patterns` section (and potentially other parts of the JSON if crafted maliciously) into the user's VSCode `settings.json` file. This update is performed without any validation, sanitization, user confirmation, or integrity checks.

*   **Impact:**
    *   **Remote Code Execution (Critical):** By injecting carefully crafted JSON payloads beyond just file nesting patterns, an attacker can potentially achieve remote code execution (RCE) on the user's machine. This could be done by defining malicious tasks, debugger configurations, or exploiting vulnerabilities in other VSCode extensions that process the `settings.json` file. Successful RCE allows the attacker to gain complete control over the user's system, leading to data theft, malware installation, and other malicious activities.
    *   **Configuration Manipulation (High):** An attacker can inject arbitrary glob patterns into the `explorer.fileNesting.patterns` setting. This allows them to control how files and folders are nested and displayed in the VSCode explorer.
    *   **User Confusion and Misdirection (Medium):** Malicious patterns can be crafted to hide important files or folders, or to create misleading file nesting structures. This can significantly disrupt the user's workflow, make it harder to find files, and lead to confusion. This misdirection can also be used to facilitate further attacks, such as hiding malicious files or confusing code review processes.
    *   **Potential Cascading Effects (Medium):** Specially crafted malicious patterns could trigger performance issues or unanticipated behavior in the VSCode file explorer if VSCode's internal handling of file nesting patterns is vulnerable to certain input strings.
    *   **Loss of Trust (Low):** Applying remote configuration without validation and user consent violates security principles and undermines the integrity of the IDE's configuration, potentially eroding user trust in the extension and the VSCode environment.

*   **Vulnerability Rank:** Critical

*   **Currently Implemented Mitigations:**
    None. The extension fetches and applies the configuration directly without any security measures. There is no validation or sanitization of the upstream repository or branch settings, nor of the fetched configuration content. The extension implicitly trusts the content from the configured upstream repository.

*   **Missing Mitigations:**
    *   **Input Validation and Sanitization:**
        *   **Upstream Repository and Branch Validation:** Implement strict validation for the `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` settings to restrict them to a predefined list of trusted repositories or enforce specific URL formats. Verify that the repo and branch strings match an expected pattern (such as a "username/repository" format with only allowed characters).
        *   **Configuration Sanitization:** Before merging the fetched configuration into `settings.json`, the extension should parse and sanitize the JSON content. This includes:
            *   Parsing and validating the patterns as valid glob patterns and the overall JSON structure.
            *   Checking for and removing potentially malicious payloads, such as task definitions (`tasks.tasks`), debugger configurations (`launch.configurations`), or any other settings that could be exploited for code execution or other malicious purposes.
            *   Consider using a sandboxed environment or a more secure method for processing and applying the fetched patterns.
    *   **User Confirmation and Awareness:**
        *   **User Consent on Auto-Update:** Implement a user confirmation step before applying any configuration updates fetched from remote sources, even for the first-time initialization and when auto-update is enabled. Clearly display the changes being applied and ask for explicit user consent.
        *   **Warnings for Remote Updates:** Display a warning message to the user when the extension is about to update file nesting patterns from a remote source, especially if the source repository is not explicitly trusted or is being changed.
    *   **Content Integrity and Authenticity Verification:**
        *   **Content Integrity Check:** Implement a mechanism to verify the integrity of the fetched configuration, such as using checksums or hashes, to ensure that the configuration has not been tampered with during transit.
        *   **Authenticity Verification:** Implement a mechanism to verify the authenticity and origin of the remote configuration, for example, by checking a cryptographic signature or by using a secure channel and pre-configured trusted source.
    *   **Error Handling:** Implement robust error handling for all stages of the configuration fetching and parsing process, including network errors, Markdown parsing errors, JSON parsing failures, and validation errors. Proper error handling can prevent unintended behavior and provide informative messages to the user.

*   **Preconditions:**
    *   The "File Nesting Updater" VSCode extension must be installed.
    *   The user must have configured the extension to use an upstream repository for file nesting patterns by setting `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch`.
    *   The user must have either enabled the `fileNestingUpdater.autoUpdate` setting or manually trigger the update command (`antfu.file-nesting.manualUpdate`).
    *   The attacker must be able to convince the user to change the `fileNestingUpdater.upstreamRepo` setting to point to a repository controlled by the attacker. This could involve social engineering, phishing, or compromising workspace settings.
    *   The user's workspace or user settings must be writable by an attacker in scenarios where the attacker aims to pre-configure the malicious upstream repository through a malicious workspace file.

*   **Source Code Analysis:**

    The vulnerability stems from the insecure implementation in `extension/src/fetch.ts`, specifically in the `fetchLatest()` and `fetchAndUpdate()` functions.

    1.  **`extension/src/fetch.ts:fetchLatest()`**:
        ```typescript
        export async function fetchLatest() {
          const repo = getConfig<string>('fileNestingUpdater.upstreamRepo') // User-configurable repository name
          const branch = getConfig<string>('fileNestingUpdater.upstreamBranch') // User-configurable branch name
          const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}` // Constructs URL using user configurations and constants
          const md = await fetch(url).then(r => r.text()) // Fetches content from the constructed URL
          const content = (md.match(/```jsonc([\s\S]*?)```/) || [])[1] || '' // Extracts JSONC content from markdown

          const json = `{${ // Constructs a JSON string by wrapping extracted content
            content
              .trim()
              .split(/\n/g)
              .filter(line => !line.trim().startsWith('//'))
              .join('\n')
              .slice(0, -1)
          }}`

          const config = JSON.parse(json) || {} // Parses the JSON string
          return config['explorer.fileNesting.patterns'] // Returns the 'explorer.fileNesting.patterns' from parsed JSON
        }
        ```
        The `fetchLatest` function constructs a URL using unsanitized user-provided configuration values. It fetches content from this URL and extracts a JSONC code block from the markdown. This extracted content is then parsed as JSON. **Vulnerability**: There is no validation of the `repo` and `branch` settings, allowing injection of arbitrary values into the URL. Furthermore, there is no validation or sanitization of the extracted JSON content itself.

    2.  **`extension/src/fetch.ts:fetchAndUpdate()`**:
        ```typescript
        export async function fetchAndUpdate(ctx: ExtensionContext, prompt = true) {
          const config = workspace.getConfiguration() // Gets VSCode configuration
          const patterns = await fetchLatest() // Fetches the latest patterns (potentially malicious)
          let shouldUpdate = true

          const oringalPatterns = { ...(config.get<object>('explorer.fileNesting.patterns') || {}) }
          delete oringalPatterns['//']
          // no change
          if (Object.keys(oringalPatterns).length > 0 && JSON.stringify(patterns) === JSON.stringify(oringalPatterns))
            return false

          if (prompt) { // User prompt for update (can be bypassed on first run)
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
            if (config.inspect('explorer.fileNesting.enabled')?.globalValue == null) // Ensures file nesting is enabled
              config.update('explorer.fileNesting.enabled', true, true)

            if (config.inspect('explorer.fileNesting.expand')?.globalValue == null) // Ensures file nesting is expanded
              config.update('explorer.fileNesting.expand', false, true)

            config.update('explorer.fileNesting.patterns', { // Updates 'explorer.fileNesting.patterns' with fetched patterns
              '//': `Last update at ${new Date().toLocaleString()}`,
              ...patterns, // Malicious patterns are directly applied here
            }, true)

            ctx.globalState.update('lastUpdate', Date.now())

            window.showInformationMessage(`${MSG_PREFIX} Config updated`)
          }
        }
        ```
        The `fetchAndUpdate` function retrieves patterns via `fetchLatest()`. These patterns, which could be malicious, are then directly applied to the `explorer.fileNesting.patterns` configuration using `config.update()`. **Vulnerability**: There is no validation of the fetched `patterns` before applying them to the configuration, allowing malicious patterns to be injected.  Furthermore, on the first activation of the extension (`ctx.globalState.get('init', false)` is false in `extension/src/index.ts`), `fetchAndUpdate(ctx, false)` is called without prompting the user, making initial exploitation easier.

    *Visualization:*

    ```mermaid
    graph LR
        subgraph VSCode Extension
            A[getConfig('fileNestingUpdater.upstreamRepo')] --> B{Construct URL}
            C[getConfig('fileNestingUpdater.upstreamBranch')] --> B
            D[URL_PREFIX + FILE] --> B
            B --> E[fetch(URL)]
            E --> F[Extract JSONC from Markdown]
            F --> G[JSON.parse(JSONC)]
            G --> H[config.update('explorer.fileNesting.patterns', patterns)]
            H --> I[VSCode Configuration Updated]
        end
        subgraph Attacker Controlled Repository
            J[Malicious README.md]
        end
        J --> F
        UserConfig --> A
        UserConfig --> C
        style J fill:#f9f,stroke:#333,stroke-width:2px
        style H fill:#faa,stroke:#333,stroke-width:2px
    ```

*   **Security Test Case (Remote Code Execution):**

    1.  **Setup Malicious Repository:**
        *   Create a public GitHub repository (e.g., `malicious-file-nesting-config`).
        *   Create a `README.md` file in this repository with the following content. This JSON payload injects a malicious task into the user's VS Code configuration that will execute `echo 'Vulnerable'` in the terminal when triggered:
            ```markdown
            ## File Nesting Configuration

            This repository contains file nesting patterns.

            \`\`\`jsonc
            {
              "explorer.fileNesting.patterns": {
                "malicious": "pattern"
              },
              "tasks.tasks": [
                {
                  "label": "Malicious Task",
                  "type": "shell",
                  "command": "echo 'Vulnerable'",
                  "problemMatcher": []
                }
              ]
            }
            \`\`\`
            ```
    2.  **Configure Extension:**
        *   Open VSCode.
        *   Install the "File Nesting Updater" extension (if not already installed).
        *   Open VS Code settings (File -> Preferences -> Settings or Code -> Settings -> Settings on macOS).
        *   Search for "file nesting updater" to locate the extension's settings.
        *   Modify the following settings:
            *   Set `"fileNestingUpdater.autoUpdate"` to `false` to prevent automatic updates during testing.
            *   Set `"fileNestingUpdater.upstreamRepo"` to `"your-github-username/malicious-file-nesting-config"` (replace `"your-github-username"` with your actual GitHub username).
            *   Set `"fileNestingUpdater.upstreamBranch"` to `"main"`.
    3.  **Trigger Configuration Update:**
        *   Execute the command "File Nesting Updater: Update config now" from the VS Code command palette (Ctrl+Shift+P or Cmd+Shift+P).
    4.  **Verify Malicious Task Injection and Execution:**
        *   After the update command completes, open the VS Code task menu (Terminal -> Run Task...).
        *   You should see a new task labeled "Malicious Task" in the list. Run this task.
        *   Observe the output in the terminal. If you see the word "Vulnerable" printed, it confirms that the malicious task from your repository was successfully injected into your VS Code configuration and executed, demonstrating the Remote Code Execution vulnerability.

    **Alternative Security Test Case (Configuration Manipulation - File Hiding):**

    1.  **Setup Malicious Repository:**
        *   Create a public GitHub repository (e.g., `malicious-nesting-config`).
        *   Create a `README.md` file in this repository with the following content to hide all top-level files and folders:
            ```markdown
            ## File Nesting Patterns

            \`\`\`jsonc
            {
              "explorer.fileNesting.patterns": {
                "**": "!*.*" // Malicious pattern: Hide all top-level files and folders
              }
            }
            \`\`\`
            ```
    2.  **Configure Extension:** (Same as steps in RCE test case, but using `malicious-nesting-config` repo)
    3.  **Trigger Configuration Update:** (Same as steps in RCE test case)
    4.  **Observe VSCode Explorer:**
        *   After the extension updates the configuration, observe the VSCode Explorer.
        *   **Expected Result (Vulnerability Confirmation):** All top-level files and folders in your workspace will be hidden due to the malicious pattern `"!*.*"`, demonstrating that the malicious configuration has been successfully injected and applied by the extension.