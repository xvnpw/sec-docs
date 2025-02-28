# Critical Vulnerabilities in vscode-wakatime Extension

## 1. Command Injection via api_key_vault_cmd

### Description
The extension has a critical vulnerability in the API key vault command functionality. When retrieving an API key from a vault command, the extension executes a command specified in the configuration file. The problem lies in how the command string is split using spaces without properly handling quoted arguments or escaping, which allows for command injection.

Step by step to trigger vulnerability:
1. An attacker creates a malicious Git repository
2. The repository contains a `.wakatime.cfg` file with a crafted `api_key_vault_cmd` value that includes arbitrary shell commands
3. When a victim opens this repository in VSCode with the WakaTime extension installed, it reads the configuration
4. The extension executes the malicious command when trying to retrieve the API key

### Impact
Remote code execution on the victim's machine. An attacker can execute arbitrary commands with the same privileges as the VSCode process.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension checks if the command string is empty or only contains whitespace, but there are no other validations or sanitizations for the command.

### Missing Mitigations
- The extension should validate the command against an allowlist of safe commands
- Command arguments should be properly parsed and escaped instead of naive string splitting
- Configuration from untrusted repositories should not be automatically used

### Preconditions
- Victim must have WakaTime extension installed
- Victim must open a repository controlled by the attacker
- No valid API key is provided through the other channels (editor settings, environment variable), forcing the extension to fall back to the vault command

### Source Code Analysis
In `options.ts`, the `getApiKeyFromVaultCmd` function executes a command from the configuration:

```typescript
public async getApiKeyFromVaultCmd(): Promise<string> {
  try {
    const cmdStr = await this.getSettingAsync<string>('settings', 'api_key_vault_cmd');
    if (!cmdStr?.trim()) return '';

    const cmdParts = cmdStr.trim().split(' '); // Vulnerable: naive splitting by spaces
    if (cmdParts.length === 0) return '';

    const [cmdName, ...cmdArgs] = cmdParts; // Command and args extracted without proper escaping

    const options = Desktop.buildOptions();
    const proc = child_process.spawn(cmdName, cmdArgs, options); // Command execution
    // ...
  }
  // ...
}
```

The vulnerability occurs because:
1. The command string is split naively by spaces (`split(' ')`)
2. No validation is done on the command name
3. No escaping or sanitization of arguments
4. `child_process.spawn` is called with these unsanitized values

If an attacker creates a config with `api_key_vault_cmd = malicious.exe arg1 && evil.exe`, the extension would execute both commands.

### Security Test Case
1. Create a test repository with a `.wakatime.cfg` file containing:
   ```
   [settings]
   api_key_vault_cmd = cmd.exe /c echo MALICIOUS_CODE_EXECUTED && calc.exe
   ```
2. Push this repository to a public Git host
3. Send a link to the victim, convincing them to open it in VSCode
4. As the extension initializes and tries to retrieve the API key, observe that the malicious command is executed
5. Verify that the calculator application launches or the test command output appears, confirming the vulnerability

## 2. Command Injection via Incomplete Quoting in Utils.quote()

### Description
The extension uses a `quote` function to quote arguments passed to the WakaTime CLI, but this function only escapes the first occurrence of double-quotes in a string. This can allow command injection if an attacker creates files with specially crafted names.

Step by step to trigger vulnerability:
1. Attacker creates a Git repository with files that have specially crafted names containing multiple double quotes
2. When a victim opens this repository, the extension processes these file names
3. The extension incorrectly quotes the file names when passing them to wakatime-cli
4. This allows breaking out of the quoted string and injecting additional shell commands

### Impact
Remote code execution. An attacker can execute arbitrary commands by crafting specific file names.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension attempts to quote strings that contain spaces, but the implementation is flawed.

### Missing Mitigations
- Replace the current `quote` function with proper shell escaping that handles all occurrences of quotes
- Consider using a library designed for shell escaping
- Validate file paths before passing them to shell commands

### Preconditions
- Victim must have WakaTime extension installed
- Victim must open a repository with maliciously named files

### Source Code Analysis
In `utils.ts`, the `quote` function contains a critical flaw:

```typescript
public static quote(str: string): string {
  if (str.includes(' ')) return `"${str.replace('"', '\\"')}"`;
  return str;
}
```

The issue is that `replace('"', '\\"')` only replaces the first occurrence of a double quote. If a string contains multiple double quotes, only the first one will be escaped.

This function is used in `wakatime.ts` when constructing arguments for the CLI:

```typescript
args.push('--entity', Utils.quote(file));
// ...
args.push('--plugin', Utils.quote(user_agent));
// ...
if (!Utils.apiKeyInvalid(apiKey)) args.push('--key', Utils.quote(apiKey));
// ...
if (apiUrl) args.push('--api-url', Utils.quote(apiUrl));
// ...
if (project) args.push('--alternate-project', Utils.quote(project));
// ...
if (folder) args.push('--project-folder', Utils.quote(folder));
```

When these arguments are passed to `child_process.execFile`, a maliciously crafted filename could break out of the quotes and inject arbitrary commands:

```typescript
let proc = child_process.execFile(binary, args, options, (error, stdout, stderr) => {
  // ...
});
```

### Security Test Case
1. Create a Git repository with a file named: `exploit.js" && calc.exe && echo "pwned`
2. Push this repository to a public Git host
3. Send the repository link to a victim who has the WakaTime extension installed
4. When the victim opens the file in VSCode, WakaTime will process the file and send a heartbeat
5. The extension will call `Utils.quote(file)` which will produce: `"exploit.js\" && calc.exe && echo "pwned"`
6. This string is passed to the CLI, where the unescaped quotes allow command injection
7. On Windows, the calculator application will launch, demonstrating the vulnerability

## 3. Remote Code Execution via MITM with no_ssl_verify

### Description
The extension downloads the wakatime-cli executable from GitHub. If the `no_ssl_verify` option is set to `true` in the configuration, SSL verification is disabled, making the download vulnerable to man-in-the-middle attacks. An attacker could intercept the download and substitute a malicious executable.

Step by step to trigger vulnerability:
1. Attacker creates a repository with a `.wakatime.cfg` file that sets `no_ssl_verify = true`
2. Attacker performs a MITM attack (e.g., on a public WiFi network)
3. Victim opens the attacker's repository in VSCode with the WakaTime extension
4. When the extension checks for or downloads wakatime-cli, it does so without SSL verification
5. Attacker intercepts the download and substitutes a malicious executable
6. The malicious executable is run by the extension

### Impact
Remote code execution. An attacker can deliver and execute malicious code on the victim's machine.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The extension respects the `no_ssl_verify` setting without warning the user of the risks.

### Missing Mitigations
- Remove the `no_ssl_verify` option entirely or implement strong warnings
- Verify downloaded binaries using checksums or digital signatures
- Only use HTTPS URLs for downloads, regardless of user settings

### Preconditions
- Victim must have WakaTime extension installed
- Victim must open a repository with the `no_ssl_verify` setting
- Attacker must be in a position to perform a MITM attack

### Source Code Analysis
In `dependencies.ts`, the `downloadFile` function disables SSL verification if the setting is enabled:

```typescript
private downloadFile(url: string, outputFile: string, callback: () => void, error: () => void): void {
  this.options.getSetting('settings', 'proxy', false, (proxy: Setting) => {
    this.options.getSetting('settings', 'no_ssl_verify', false, (noSSLVerify: Setting) => {
      let options = { url: url };
      if (proxy.value) {
        this.logger.debug(`Using Proxy: ${proxy.value}`);
        options['proxy'] = proxy.value;
      }
      if (noSSLVerify.value === 'true') options['strictSSL'] = false; // Vulnerable: SSL verification disabled
      try {
        let r = request.get(options);
        // ...
      } catch (e) {
        // ...
      }
    });
  });
}
```

If an attacker can set `no_ssl_verify = true` in the configuration, the extension will download the CLI without verifying SSL certificates. This function is called when installing the CLI:

```typescript
private installCli(callback: () => void): void {
  this.logger.debug(`Downloading wakatime-cli from GitHub...`);
  const url = this.cliDownloadUrl();
  let zipFile = path.join(this.resourcesLocation, 'wakatime-cli' + this.randStr() + '.zip');
  this.downloadFile(url, zipFile, () => { // Vulnerable: uses downloadFile without enforcing SSL
    this.extractCli(zipFile, callback);
  }, callback);
}
```

After downloading, the binary is extracted and executed without any integrity verification.

### Security Test Case
1. Create a test repository with a `.wakatime.cfg` file containing:
   ```
   [settings]
   no_ssl_verify = true
   ```
2. Set up a proxy server that intercepts HTTPS requests to GitHub
3. Configure the proxy to substitute the wakatime-cli download with a harmless test executable
4. Configure the victim's machine to use this proxy
5. When the victim opens the repository, WakaTime will attempt to download the CLI
6. Verify that the intercepted request does not use SSL verification
7. Verify that the substituted executable is downloaded and executed by the extension