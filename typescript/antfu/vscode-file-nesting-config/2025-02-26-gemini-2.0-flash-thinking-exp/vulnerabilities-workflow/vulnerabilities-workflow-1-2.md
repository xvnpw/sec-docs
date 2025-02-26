---

**Vulnerability Name:** Insecure Remote Configuration Injection

**Description:**
The extension automatically fetches a “file nesting” configuration from a remote Markdown file hosted on jsDelivr. It does so by reading user/workspace settings for the upstream repository and branch without any validation or sanitization. An attacker who is able to influence these configuration values (for example, via a malicious workspace file or social engineering) can point these settings to an attacker‑controlled repository. Then, by crafting a malicious “README.md” (with a code block labeled “jsonc”) containing unexpected or harmful nesting patterns, the attacker can force the extension to update VS Code’s file nesting setting with arbitrary data. In a step‐by-step scenario, an attacker might:

- Convince the user (or by default workspace settings) to set:
  - `fileNestingUpdater.upstreamRepo` to an attacker‑controlled value (e.g. `"malicious-org/malicious-config"`),
  - `fileNestingUpdater.upstreamBranch` to a branch hosting malicious content.
- When the extension activates (or when the user manually triggers the update command), it constructs a URL by concatenating the fixed URL prefix with these unsanitized values.
- The extension downloads the Markdown file, extracts the JSON snippet using a regular expression, strips all commented lines, and then parses the text into JSON.
- Finally, the resulting object is merged (with a timestamp comment) and used to update VS Code’s configuration key `explorer.fileNesting.patterns` with no further checks.

Because the extension auto‑updates the configuration (including during first‑time initialization without user confirmation) with data received from this remote source, an attacker–controlled repository or branch can inject arbitrary file nesting rules into the user’s VS Code settings.

**Impact:**
- **Misconfiguration and Misdirection:** The injected file nesting patterns may hide important files or rearrange the file tree in unexpected ways, confusing the user or facilitating further attacks (for example, by hiding files that should be reviewed).
- **Potential Cascading Effects:** If VS Code’s internal handling of file nesting patterns depends on these strings (for example, by constructing internal regular expressions), specially crafted malicious patterns could trigger performance issues or unanticipated behavior in the file explorer.
- **Loss of Trust:** Applying remote configuration without validation violates the principle of user consent and may undermine the integrity of the IDE’s configuration.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- There is no validation or sanitization of the configuration values read from VS Code’s settings (i.e. the keys `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` are used verbatim).
- The remote content is fetched, parsed, and applied without verifying its authenticity (no digital signature or hash check is performed).

**Missing Mitigations:**
- **Input Validation:** The project should validate and sanitize the contents of both the configuration values used to construct the URL and the remote content itself. For example, verify that the repo and branch strings match an expected pattern (such as a “username/repository” format with only allowed characters).
- **Authenticity Verification:** Before applying an update, the extension should verify the integrity and origin of the remote configuration (for example, by checking a cryptographic signature, hash, or using a secure channel and pre‑configured trusted source).
- **User Consent on Auto‑Update:** Consider prompting the user even at first‑time initialization (or default to a safe configuration update policy) so that remote changes are not applied automatically without explicit user awareness.
- **Error Handling:** Although not directly exploitable to run arbitrary code, more robust error handling for JSON parsing failures or unexpected content could prevent unintended behavior.

**Preconditions:**
- The user’s workspace or user settings must be writable by an attacker. This might be achieved when an attacker supplies a malicious workspace file that overrides the extension’s configuration keys.
- The user must have the extension installed and have auto‑update enabled (or run the manual update command) so that the unvalidated remote configuration is fetched and applied.
- Remote control over the upstream repository/branch (or convincing the user to change these settings) is necessary for the attacker to supply malicious configuration.

**Source Code Analysis:**
- In `extension/src/fetch.ts`, the function `fetchLatest()` obtains configuration values via the helper `getConfig()`, and then constructs the URL as follows:
  ```ts
  const repo = getConfig<string>('fileNestingUpdater.upstreamRepo')
  const branch = getConfig<string>('fileNestingUpdater.upstreamBranch')
  const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}`
  ```
  Here, neither `repo` nor `branch` is sanitized—any value (including path traversal characters or attacker‑crafted strings) will be injected into the URL.
- The code then fetches the file with `ofetch` and reads it as text. It uses a regular expression:
  ```ts
  const content = (md.match(/```jsonc([\s\S]*?)```/) || [])[1] || ''
  ```
  to extract the configuration snippet. The snippet is reformatted (trimming, splitting lines, filtering out comment lines, joining, and slicing off the final character) and then wrapped in curly braces before being passed to `JSON.parse()`.
- No verification is done on the result from JSON.parse. The value returned (specifically the property `['explorer.fileNesting.patterns']`) is then used to update the VS Code configuration via:
  ```ts
  config.update('explorer.fileNesting.patterns', {
    '//': `Last update at ${new Date().toLocaleString()}`,
    ...patterns,
  }, true)
  ```
- Also note that in `extension/src/index.ts`, when the extension is first activated (i.e. when `ctx.globalState.get('init', false)` is false), it calls `fetchAndUpdate(ctx, false)` without prompting the user—a behavior that further lowers the barrier for an attacker‐supplied remote configuration to be applied immediately.

**Security Test Case:**
1. **Setup the Malicious Environment:**
   - Create a malicious workspace (or instruct a test user) that overrides the settings `fileNestingUpdater.upstreamRepo` and `fileNestingUpdater.upstreamBranch` to point to an attacker‑controlled repository and branch (for example, use the values `"malicious-org/malicious-config"` and `"main"`).
   - In the attacker‑controlled repository, prepare a README.md file that contains a code-fenced block labeled “jsonc” with configuration data designed to, for example, alter file nesting patterns in a harmful way.
2. **Trigger the Update Mechanism:**
   - Open the workspace in VS Code with the extension installed.
   - Depending on your configuration:
     - For first‑time initialization, the extension will trigger `fetchAndUpdate(ctx, false)` without prompting.
     - Or, if auto‑update is enabled with prompting, wait until the auto‑update condition is met or run the command `antfu.file-nesting.manualUpdate`.
3. **Observe the Outcome:**
   - Watch for the information message from the extension that indicates a configuration update.
   - Verify that the VS Code setting `explorer.fileNesting.patterns` is replaced with the configuration data from the remote (malicious) source (including the injected patterns).
   - Optionally, verify any abnormal behavior in the file explorer (such as mis‐nesting or hidden files) that confirms the remote configuration has been applied.
4. **Conclusion:**
   - Successful application of attacker‑controlled settings (without any validation) demonstrates the vulnerability.

---