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

This attack represents a high-severity security risk as it creates a pathway for remote code execution through a supply chain attack targeting VSCode users.