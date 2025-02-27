### Vulnerability List

* Vulnerability Name: Remote Code Execution via Configuration Injection
* Description:
    1. An attacker forks the upstream repository specified in `fileNestingUpdater.upstreamRepo`.
    2. The attacker modifies the `README.md` file in their forked repository. They inject a malicious JSON payload into the `explorer.fileNesting.patterns` section. This payload leverages VS Code's file nesting feature to execute arbitrary commands. For example, they could add a pattern like `"malicious.*": "$(echo 'pwned') > /tmp/pwned.txt"`.
    3. The victim configures the VS Code extension `fileNestingUpdater.upstreamRepo` setting to point to the attacker's forked repository and sets `fileNestingUpdater.autoUpdate` to `true` or manually triggers the update command `antfu.file-nesting.manualUpdate`.
    4. The extension fetches the modified `README.md` from the attacker's repository.
    5. The extension extracts the JSON configuration from the `README.md` and parses it using `JSON.parse`.
    6. The extension updates the VS Code `explorer.fileNesting.patterns` setting with the malicious configuration from the attacker.
    7. When the victim opens or interacts with a file in VS Code that matches the malicious pattern (e.g., a file named `malicious.txt`), VS Code executes the command injected by the attacker (e.g., `$(echo 'pwned') > /tmp/pwned.txt`).
* Impact: Remote code execution on the victim's machine with the privileges of the VS Code process. This can lead to data theft, malware installation, or complete system compromise.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    * None. The extension directly fetches and applies configurations from a remote source without any validation or sanitization.
* Missing Mitigations:
    * **Input Validation and Sanitization**: The extension must validate and sanitize the fetched configuration before applying it. Specifically, it should:
        * Validate that the fetched content is indeed JSON.
        * Validate the structure of the JSON and ensure it conforms to the expected schema for `explorer.fileNesting.patterns`.
        * Sanitize the values in the `explorer.fileNesting.patterns` to prevent command execution. VS Code's file nesting feature should not be used to execute arbitrary commands from configuration. If command execution is intended, it should be explicitly controlled and secured, not implicitly through file nesting patterns.  Ideally, the extension should only handle the nesting patterns and avoid any features that could lead to command execution.
    * **Content Integrity Check**: Implement a mechanism to verify the integrity and authenticity of the fetched content, such as using signed commits or checksums, to prevent tampering. However, for this specific vulnerability, sanitization is more critical as even a legitimate repository could be compromised.
    * **Restrict Configuration Sources**:  Consider limiting the sources from which configurations can be fetched to only trusted repositories or providing a curated list. However, user configurability is a feature, so sanitization is still needed.
* Preconditions:
    * The victim has the File Nesting Updater extension installed.
    * The victim has the `fileNestingUpdater.autoUpdate` setting enabled or manually triggers the update.
    * The victim uses the default or configures `fileNestingUpdater.upstreamRepo` to point to a repository that can be controlled by the attacker.
* Source Code Analysis:
    1. **`extension/src/fetch.ts:fetchLatest()`**:
    ```typescript
    export async function fetchLatest() {
      const repo = getConfig<string>('fileNestingUpdater.upstreamRepo') // Configuration value
      const branch = getConfig<string>('fileNestingUpdater.upstreamBranch') // Configuration value
      const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}` // URL constructed with configuration values
      const md = await fetch(url).then(r => r.text()) // Fetching content from constructed URL
      const content = (md.match(/```jsonc([\s\S]*?)```/) || [])[1] || '' // Extracting JSON using regex

      const json = `{${
        content
          .trim()
          .split(/\n/g)
          .filter(line => !line.trim().startsWith('//'))
          .join('\n')
          .slice(0, -1)
      }}`

      const config = JSON.parse(json) || {} // Parsing JSON content
      return config['explorer.fileNesting.patterns'] // Returning 'explorer.fileNesting.patterns'
    }
    ```
    The `fetchLatest` function constructs a URL based on user-provided configuration and fetches content. It then extracts JSON from markdown and parses it using `JSON.parse`. This is where malicious JSON can be injected.

    2. **`extension/src/fetch.ts:fetchAndUpdate()`**:
    ```typescript
    export async function fetchAndUpdate(ctx: ExtensionContext, prompt = true) {
      const config = workspace.getConfiguration()
      const patterns = await fetchLatest() // Fetching latest patterns, potentially malicious
      let shouldUpdate = true

      // ... (Prompt logic) ...

      if (shouldUpdate) {
        // ... (Configuration update logic) ...

        config.update('explorer.fileNesting.patterns', { // Updating VS Code configuration with fetched patterns
          '//': `Last update at ${new Date().toLocaleString()}`,
          ...patterns, // Malicious patterns are directly used here
        }, true)

        // ...
      }
    }
    ```
    The `fetchAndUpdate` function takes the `patterns` obtained from `fetchLatest()` and directly updates the VS Code configuration using `config.update('explorer.fileNesting.patterns', ...)`.  No sanitization or validation is performed on `patterns` before updating the configuration.

* Security Test Case:
    1. **Setup Attacker Repository:**
        * Fork the repository `antfu/vscode-file-nesting-config` on GitHub.
        * Clone your forked repository locally.
        * Modify the `README.md` file. Replace the existing `"explorer.fileNesting.patterns"` section with the following malicious payload:
        ```jsonc
        "explorer.fileNesting.patterns": {
            "package.json": "*.code-workspace, .browserslist*, .circleci*, .commitlint*, .cspell*, .cursorrules, .cz-config.js, .czrc, .dlint.json, .dprint.json*, .editorconfig, .eslint*, .firebase*, .flowconfig, .github*, .gitlab*, .gitmojirc.json, .gitpod*, .huskyrc*, .jslint*, .knip.*, .lintstagedrc*, .ls-lint.yml, .markdownlint*, .node-version, .nodemon*, .npm*, .nvmrc, .pm2*, .pnp.*, .pnpm*, .prettier*, .pylintrc, .release-please*.json, .releaserc*, .ruff.toml, .sentry*, .simple-git-hooks*, .stackblitz*, .styleci*, .stylelint*, .tazerc*, .textlint*, .tool-versions, .travis*, .versionrc*, .vscode*, .watchman*, .xo-config*, .yamllint*, .yarnrc*, Procfile, apollo.config.*, appveyor*, azure-pipelines*, biome.json*, bower.json, build.config.*, bun.lock, bun.lockb, bunfig.toml, colada.options.ts, commitlint*, crowdin*, cspell*, dangerfile*, dlint.json, dprint.json*, ec.config.*, electron-builder.*, eslint*, firebase.json, grunt*, gulp*, jenkins*, knip.*, lerna*, lint-staged*, nest-cli.*, netlify*, nixpacks*, nodemon*, npm-shrinkwrap.json, nx.*, package-lock.json, package.nls*.json, phpcs.xml, pm2.*, pnpm*, prettier*, pullapprove*, pyrightconfig.json, release-please*.json, release-tasks.sh, release.config.*, renovate*, rolldown.config.*, rollup.config.*, rspack*, ruff.toml, sentry.*.config.ts, simple-git-hooks*, sonar-project.properties, stylelint*, tsdown.config.*, tslint*, tsup.config.*, turbo*, typedoc*, unlighthouse*, vercel*, vetur.config.*, webpack*, workspace.json, wrangler.*, xo.config.*, yarn*",
            "malicious.txt": "$(touch /tmp/pwned_file_nesting_extension)"
        }
        ```
        * Commit and push the changes to your forked repository.

    2. **Configure VS Code Extension:**
        * Open VS Code.
        * Install the "File Nesting Updater" extension (if not already installed).
        * Go to VS Code settings (`Ctrl+,` or `Cmd+,`).
        * Set `fileNestingUpdater.upstreamRepo` to your forked repository name (e.g., `your-github-username/vscode-file-nesting-config`).
        * Set `fileNestingUpdater.autoUpdate` to `true` to automatically trigger the update or leave it `false` to manually trigger.

    3. **Trigger Configuration Update:**
        * If `fileNestingUpdater.autoUpdate` is `true`, wait for the auto-update interval (default 12 hours, or modify `fileNestingUpdater.autoUpdateInterval` for faster testing).
        * If `fileNestingUpdater.autoUpdate` is `false`, execute the command "File Nesting Updater: Update config now" from the VS Code command palette (`Ctrl+Shift+P` or `Cmd+Shift+P`).

    4. **Trigger Malicious Pattern:**
        * Create a new file named `malicious.txt` in any project folder open in VS Code.
        * Open the `malicious.txt` file in the editor or just ensure it's visible in the VS Code explorer.

    5. **Verify Code Execution:**
        * Check if the file `/tmp/pwned_file_nesting_extension` exists. If it exists, the command injection was successful and remote code execution vulnerability is confirmed.