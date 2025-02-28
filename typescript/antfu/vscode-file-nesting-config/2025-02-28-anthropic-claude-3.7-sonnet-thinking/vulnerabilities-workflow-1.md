# Security Vulnerabilities Analysis

## Vulnerability 1: Remote Code Execution via Malicious Repository Configuration

### Vulnerability Name
Remote Code Execution via Malicious Repository Configuration

### Description
The extension allows users to specify a custom GitHub repository and branch to fetch file nesting configuration from. The extension fetches markdown content from this repository, extracts JSON configuration using regex, parses it with minimal validation, and applies it to VSCode settings. An attacker can create a malicious repository with specially crafted content that, when parsed and applied by the extension, could lead to code execution within VSCode.

Step by step exploitation:
1. An attacker creates a malicious GitHub repository with a README.md file containing specially crafted JSON
2. The attacker tricks a user into opening a project with settings pointing to this malicious repository
3. When the extension runs (automatically or manually), it fetches from the attacker's repository
4. The extension extracts and parses the malicious JSON with insufficient validation
5. The extension applies this configuration to VSCode settings, potentially executing malicious code

### Impact
This vulnerability could allow an attacker to execute arbitrary code within the context of VSCode, potentially leading to:
- Access to the user's workspace files
- Access to sensitive information accessible to VSCode
- Execution of commands with the same privileges as the VSCode process
- Potential access to the user's system depending on VSCode's security model

### Vulnerability Rank
High

### Currently Implemented Mitigations
- The extension can be configured to prompt before applying updates (when `promptOnAutoUpdate` is enabled)
- Basic filtering of comment lines in the JSON

### Missing Mitigations
- Repository URL validation and sanitization
- Allowlist of trusted repositories
- JSON schema validation before applying configurations
- Content security policies
- Secure parsing techniques

### Preconditions
- The victim must have the VSCode File Nesting Config extension installed
- The attacker must either:
  - Trick the victim into opening a project with malicious settings that point to an attacker-controlled repository
  - Gain access to modify the victim's VSCode settings directly

### Source Code Analysis
The vulnerability flow can be traced through several components:

1. In `index.ts`, the extension can automatically call `fetchAndUpdate()`:
```typescript
if (getConfig('fileNestingUpdater.autoUpdate')) {
  if (Date.now() - lastUpdate >= autoUpdateInterval * 60_000)
    fetchAndUpdate(ctx, getConfig('fileNestingUpdater.promptOnAutoUpdate'))
}
```

2. In `fetch.ts`, the `fetchLatest()` function retrieves configuration from a potentially malicious source without validation:
```typescript
const repo = getConfig<string>('fileNestingUpdater.upstreamRepo')
const branch = getConfig<string>('fileNestingUpdater.upstreamBranch')
const url = `${URL_PREFIX}/${repo}@${branch}/${FILE}`
const md = await fetch(url).then(r => r.text())
```

3. The fetched content is unsafely parsed using regex and direct JSON parsing:
```typescript
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
```

4. Finally, the parsed configuration is applied to VSCode settings without thorough validation:
```typescript
config.update('explorer.fileNesting.patterns', {
  '//': `Last update at ${new Date().toLocaleString()}`,
  ...patterns,
}, true)
```

The vulnerability exists because:
- There's no validation of repository and branch names used to construct the URL
- The parsing of fetched content uses potentially unsafe methods (regex extraction and direct JSON.parse)
- The parsed content is directly applied to VSCode settings without proper validation

### Security Test Case
1. Setup:
   - Create a GitHub repository (e.g., "malicious-config/file-nesting")
   - Add a README.md file with malicious content structured as JSON within code blocks:
     ```
     # Malicious Config
     
     ```jsonc
     "*.js": "*.{test.js,spec.js}",
     "__proto__": {"polluted": true},
     "malicious": "${constructor.constructor('alert(\"RCE\")')()}"
     ```
     ```

2. Create a malicious project:
   - Set up a VS Code project with a .vscode/settings.json file:
     ```json
     {
       "fileNestingUpdater.upstreamRepo": "malicious-config/file-nesting",
       "fileNestingUpdater.upstreamBranch": "main",
       "fileNestingUpdater.autoUpdate": true,
       "fileNestingUpdater.promptOnAutoUpdate": false
     }
     ```

3. Execute the attack:
   - Share the malicious project with the victim
   - When they open it in VSCode with the extension installed, it will automatically fetch configuration from the attacker's repository
   - The extension will parse and apply the malicious configuration

4. Verification:
   - If successful, the malicious payload in the configuration could be executed within the VS Code context
   - Depending on VS Code's security model, this could lead to code execution, data exfiltration, or other malicious activities

## Vulnerability 2: Prototype Pollution via Unsanitized Remote Configuration Injection

### Vulnerability Name
Prototype Pollution via Unsanitized Remote Configuration Injection

### Description
The extension periodically fetches a remote README file from a repository (whose location is controlled by the user's settings "fileNestingUpdater.upstreamRepo" and "…upstreamBranch"). In the function that retrieves the latest file nesting config (in `extension/src/fetch.ts`), the extension locates a JSONC code block from the README, then performs a rudimentary transformation (by splitting lines, filtering out "//" comments, joining and slicing off the last character) and wraps the result in curly braces before calling `JSON.parse`.  

This unsanitized processing does not check which keys are provided in the remote content. An attacker who can control the remote repository content can supply a payload that includes dangerous property names (for example, `"__proto__"`) as part of the JSON. When the parsed object is later spread into a new object and used to update the workspace configuration (in the `fetchAndUpdate` function), such keys will become own properties of the new object and may pollute the prototype chain. Under certain circumstances this prototype pollution can be leveraged into code injection or even remote code execution if later code or a dependent library trusts the configuration object without accounting for polluted inherited properties.

### Impact
By polluting the prototype, an attacker may change the behavior of subsequent configuration lookups or internal logic. In the worst-case scenario the polluted prototype could be exploited to inject and execute arbitrary code—especially if other parts of VSCode or a third‑party library later use the polluted object in a dynamic context. This vulnerability is therefore potentially critical and may lead to remote code execution on the victim's machine.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- The code does attempt to "clean" the fetched content by filtering out lines that start with `//` but does not check for malicious property names or validate against a whitelist.
- The implementation uses object spread (`{ ...patterns }`) when updating settings. (While the spread operator only copies own enumerable properties, if the remote JSON supplies dangerous keys as own properties they will be included.)

### Missing Mitigations
- **Input Validation and Sanitization:** There is no check to ensure that the keys in the remote JSON conform to an expected whitelist. In particular, keys such as `"__proto__"`, `"prototype"`, or `"constructor"` should be disallowed or sanitized.
- **Safe Merging:** The update to the configuration directly spreads the attacker-controlled object into the settings update. A safer merge or deep cloning procedure that explicitly ignores dangerous keys should be implemented.
- **Robust Parsing:** Relying on simple string manipulation before wrapping the content in curly braces leaves the JSON vulnerable to misinterpretation. A proper parser for "jsonc" (JSON with comments) should be used.

### Preconditions
- The victim's configuration (either auto‑update enabled or manual update triggered) points the extension to an upstream repository controlled by the attacker.
- The attacker must have created a malicious repository (or manipulated branch/README) containing a code block marked with "```jsonc" whose content includes payload keys (e.g. `"__proto__": { "polluted": "yes" }`).
- The victim's VSCode environment accepts and applies the configuration update without additional checks.

### Source Code Analysis
1. In `extension/src/fetch.ts`, the function `fetchLatest()` uses the helper `getConfig` (from the user's VSCode configuration) to read the repository and branch names. It then constructs a URL of the form  
   `https://cdn.jsdelivr.net/gh/<repo>@<branch>/README.md`  
   and fetches the text from that URL.
2. It applies a regular expression (`/```jsonc([\s\S]*?)```/`) to capture a block of text in the README file. The captured text (if any) is then processed:
   - The text is trimmed.
   - It is split into lines.
   - Lines starting with `//` (after trimming) are filtered out.
   - The remaining lines are rejoined with newlines.
   - Finally, the last character is removed via `.slice(0, -1)`.
3. The resulting string is wrapped in curly braces, creating a new string that is passed to `JSON.parse`. There is no check here on what keys are present in the JSON.
4. The parsed object is expected to have a property called `"explorer.fileNesting.patterns"`—this value is returned.
5. In `fetchAndUpdate()`, the returned object (stored as `patterns`) is spread into a new object (along with a comment key) and then used to update VSCode's configuration:
   ```js
   config.update('explorer.fileNesting.patterns', {
     '//': `Last update at ${new Date().toLocaleString()}`,
     ...patterns,
   }, true)
   ```
   Because there is no sanitation of the keys in `patterns`, any own property supplied by the attacker (including special keys such as `"__proto__"`) will be copied into the configuration object. If later processes (possibly within VSCode or within the extension) iterate over these settings or use them in a dynamic manner, the polluted prototype may lead to code paths that execute unintended (attacker‑supplied) logic.

### Security Test Case
1. **Preparation:**  
   - Set up a controlled test instance of VSCode with the extension installed.
   - In the user settings (or via other means) configure the extension's `"fileNestingUpdater.upstreamRepo"` and `"fileNestingUpdater.upstreamBranch"` values to point to a repository under the tester's control.
2. **Craft a Malicious Repository:**  
   - In the repository's `README.md`, include a code block marked with "```jsonc" that contains a payload. For example:
     ```
     ```jsonc
     "__proto__": { "polluted": "yes" },
     "explorer.fileNesting.patterns": {
       "a.txt": "b.txt"
     },
     ```
     ```
   - Ensure that the payload is such that when processed (trim, split, filter, join, and slice), the resulting JSON (once wrapped in curly braces) is valid and contains the malicious key.
3. **Trigger the Update:**  
   - Either wait for the auto-update interval to elapse or manually trigger the update by running the VSCode command registered by the extension (e.g. `antfu.file-nesting.manualUpdate`).
4. **Verification:**  
   - After the update, inspect the updated configuration for `explorer.fileNesting.patterns` and test whether the polluted property appears. For example, in a VSCode debug console, evaluate an empty object's prototype property:
     ```js
     ({}).polluted
     ```
     If the output is `"yes"`, prototype pollution has occurred.
   - Additionally, review subsequent behavior in VSCode or the extension that relies on these settings to determine if the polluted prototype influences application logic in a dangerous way.
5. **Conclusion:**  
   - Confirm that the lack of input validation on the remote configuration data allows an attacker to inject properties into the configuration object that can be exploited and that appropriate measures (whitelisting or sanitizing keys) are missing.