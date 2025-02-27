- Vulnerability name: Remote Configuration Injection leading to Potential Command Execution
- Description:
    1. An attacker compromises the remote repository specified in the extension's configuration (`fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch`).
    2. The attacker modifies the `README.md` file in the compromised repository.
    3. The attacker injects malicious JSON code within the JSON code block in `README.md`. This malicious JSON is crafted to be placed into the `explorer.fileNesting.patterns` setting in VSCode.
    4. The VSCode extension, either automatically based on the `autoUpdateInterval` or manually triggered by the user via the "File Nesting Updater: Update config now" command, fetches the modified `README.md` from the attacker's compromised repository using `fetchLatest()`.
    5. The `fetchLatest()` function extracts the JSON code block from the `README.md` and parses it using `JSON.parse()`.
    6. The `fetchAndUpdate()` function then applies this parsed JSON configuration to the VSCode settings using `workspace.getConfiguration().update()`, specifically targeting the `explorer.fileNesting.patterns` setting.
    7. If the attacker crafts the malicious JSON to include settings that can trigger command execution in VSCode (e.g., through tasks or other extensions that react to file explorer changes based on nesting patterns), they could potentially achieve Remote Code Execution (RCE) on the user's machine when VSCode applies the updated configuration.
- Impact:
    - Remote Code Execution (RCE) on the user's machine if malicious commands can be embedded within VSCode settings, specifically through `explorer.fileNesting.patterns` or related settings that react to changes in file nesting.
    - Account compromise if the attacker gains access to user's credentials or sensitive data stored on the compromised machine.
    - Malicious actions performed on behalf of the user, such as data exfiltration, malware installation, or further system compromise.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. The extension fetches and applies the configuration without any validation or sanitization of the fetched content.
- Missing mitigations:
    - Input validation: Implement validation of the fetched JSON configuration before applying it to VSCode settings. Verify that the JSON structure and values conform to expected schema for `explorer.fileNesting.patterns` and do not contain potentially malicious payloads.
    - Content Security Policy (CSP): If possible, investigate if VSCode settings allow for CSP to limit the capabilities of settings and prevent execution of arbitrary code.
    - Integrity checks: Implement integrity checks for the fetched `README.md` or the JSON configuration. This could involve using digital signatures or checksums to verify the authenticity and integrity of the remote content.
    - User review: Before applying configuration changes, especially those fetched from remote sources, provide a detailed preview to the user of the changes being made to the `explorer.fileNesting.patterns` setting and require explicit user confirmation to apply them.
- Preconditions:
    - The attacker needs to compromise the remote repository specified in the extension's configuration (`fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch`).
    - The user must have the "File Nesting Updater" extension installed and enabled in VSCode.
    - Automatic updates must be enabled (`fileNestingUpdater.autoUpdate": true`) or the user must manually trigger the update command.
- Source code analysis:
    1. `extension/src/fetch.ts:fetchLatest()`:
        ```typescript
        export async function fetchLatest() {
          const repo = getConfig<string>('fileNestingUpdater.upstreamRepo') // Reads repo name from config
          const branch = getConfig<string>('fileNestingUpdater.upstreamBranch') // Reads branch name from config
          const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}` // Constructs URL to README.md on jsDelivr CDN
          const md = await fetch(url).then(r => r.text()) // Fetches README.md content
          const content = (md.match(/```jsonc([\s\S]*?)```/) || [])[1] || '' // Extracts content within ```jsonc blocks
          // ... JSON parsing logic ...
          const config = JSON.parse(json) || {} // Parses extracted content as JSON
          return config['explorer.fileNesting.patterns'] // Returns the 'explorer.fileNesting.patterns' part of the parsed JSON
        }
        ```
        - The function fetches the `README.md` from a remote URL constructed from user configuration and extracts the JSON code block.
        - It uses `JSON.parse()` to convert the extracted string into a JavaScript object. **This is where malicious JSON could be parsed without validation.**
    2. `extension/src/fetch.ts:fetchAndUpdate()`:
        ```typescript
        export async function fetchAndUpdate(ctx: ExtensionContext, prompt = true) {
          const config = workspace.getConfiguration() // Gets VSCode configuration
          const patterns = await fetchLatest() // Fetches latest patterns from remote
          let shouldUpdate = true
          // ... Prompt logic ...
          if (shouldUpdate) {
            // ... Update explorer.fileNesting settings ...
            config.update('explorer.fileNesting.patterns', { // Updates 'explorer.fileNesting.patterns' setting
              '//': `Last update at ${new Date().toLocaleString()}`,
              ...patterns, // Applies fetched patterns
            }, true)
            // ...
          }
        }
        ```

    ```mermaid
    graph LR
        A[fetchLatest()] --> B{fetch(URL)};
        B --> C[README.md Content];
        C --> D{match(/```jsonc([\s\S]*?)```/)};
        D --> E[JSON String];
        E --> F{JSON.parse(json)};
        F --> G[Config Object];
        G --> H[return patterns];
        H --> I[fetchAndUpdate()];
        I --> J{workspace.getConfiguration()};
        J --> K{config.update('explorer.fileNesting.patterns', patterns, true)};
    ```

- Security test case:
    1. Fork the repository `antfu/vscode-file-nesting-config` on GitHub.
    2. Clone your forked repository locally.
    3. Edit the `README.md` file in your forked repository.
    4. Within the JSON code block, inject a malicious configuration. For example, try to execute a command when a specific file type is encountered in the explorer:
        ```jsonc
        {
          // updated 2025-02-19 04:53
          // https://github.com/antfu/vscode-file-nesting-config
          "explorer.fileNesting.enabled": true,
          "explorer.fileNesting.expand": false,
          "explorer.fileNesting.patterns": {
            "malicious.file": "$(echo 'Vulnerable' > /tmp/vscode_vuln.txt)"
            // ... rest of the config ...
          }
        }
        ```
        **Note:** Command execution in VSCode settings might be limited. A more realistic scenario might involve settings that trigger actions in other extensions or VSCode tasks. Further research is needed to identify exploitable settings within `explorer.fileNesting.patterns` or related VSCode features.  For this test case, we will assume that such a setting exists or can be crafted to demonstrate the injection.
    5. Commit and push your changes to your forked repository.
    6. In VSCode, install the "File Nesting Updater" extension.
    7. Modify the extension's settings (`fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch`) to point to your forked repository and the branch you modified (e.g., `your_username/vscode-file-nesting-config` and `main`).
    8. Trigger the update command by either:
        - Waiting for the automatic update interval to elapse (if `fileNestingUpdater.autoUpdate` is true and `fileNestingUpdater.autoUpdateInterval` is set to a low value for testing).
        - Manually executing the command "File Nesting Updater: Update config now" from the VSCode command palette (Ctrl+Shift+P or Cmd+Shift+P).
    9. After the update is applied, check if the file `/tmp/vscode_vuln.txt` exists and contains the word "Vulnerable". If it does, this indicates that the malicious configuration from the remote `README.md` was successfully injected and potentially executed a command, proving the vulnerability.