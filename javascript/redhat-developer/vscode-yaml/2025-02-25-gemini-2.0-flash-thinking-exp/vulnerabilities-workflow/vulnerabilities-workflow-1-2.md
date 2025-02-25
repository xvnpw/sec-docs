- **Vulnerability Name:** Insecure Proxy SSL Certificate Validation
  **Description:**
  The extension’s configuration exposes an option (`http.proxyStrictSSL`) that defaults to false. This means that when the language server downloads remote schemas or sends telemetry data, it does not verify the proxy server’s certificate against trusted certificate authorities. An external attacker in a position to intercept or modify network traffic (for example, on a public Wi‑Fi or compromised enterprise network) can perform a man-in-the-middle (MITM) attack. By substituting a forged certificate, the attacker may be able to inject malicious schema content or alter data being sent or received by the extension.
  **Impact:**
  - An attacker can intercept and modify content (such as JSON schema definitions) downloaded by the extension.
  - Malicious schema modifications might lead to unexpected language server behavior, misinformation via hover or validation results, or even facilitate further attack scenarios if downstream processing trusts the mis‐delivered content.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The project offers a configuration setting (`http.proxyStrictSSL`) that, if manually set to true, forces verification of the proxy server’s SSL certificate.
  - Documentation explains the purpose of the setting but leaves it disabled by default.
  **Missing Mitigations:**
  - There is no enforcement or warning when running with the default insecure setting.
  - A recommended mitigation would be to enable strict SSL verification by default or, at the very least, warn users when operating in a proxy environment that the current default does not verify proxy certificates.
  **Preconditions:**
  - The user is operating in an environment where a proxy is configured and network traffic is vulnerable to interception (for example, through public Wi‑Fi or a compromised internal network).
  - The user has not overridden the default (`http.proxyStrictSSL: false`).
  **Source Code Analysis:**
  - The project’s README (in the “Extension Settings” section) documents the `http.proxyStrictSSL` option and notes that its default value is false.
  - When the extension makes HTTP requests (to download remote schemas from JSON Schema Store or send telemetry), it uses the proxy settings as configured by the user. With strict SSL verification disabled, the handshake does not verify that the proxy’s certificate is legitimate.
  - *(Visualization)*
    • Setting in configuration:
      – `"http.proxyStrictSSL": false` (default)
    • HTTP request flow: Request → Proxy (certificate not verified) → Response
  **Security Test Case:**
  1. In a controlled test environment, configure a proxy server that performs active MITM interception using a self‑signed certificate.
  2. Install and run the extension (with a default configuration where `http.proxyStrictSSL` is false) in Visual Studio Code.
  3. Force the extension to perform an action that triggers a remote HTTP request (for example, opening a YAML file that requires downloading a schema).
  4. Verify that the extension accepts the forged proxy certificate and successfully downloads the schema.
  5. Then, set `"http.proxyStrictSSL": true` in the user settings and repeat the test.
  6. Confirm that with strict SSL enabled, the connection fails and the extension does not download the schema, thereby preventing a MITM attack.

- **Vulnerability Name:** Arbitrary File Disclosure via Malicious Relative Schema Reference
  **Description:**
  The extension supports associating a YAML file with a schema by using a modeline in the document (e.g.,
  `# yaml-language-server: $schema=<urlToTheSchema>`). When a relative schema URL is provided, it is resolved relative to the YAML file’s own location. This behavior means that if an attacker can supply a YAML file (for example, via a public repository or shared workspace) they could specify a relative path that traverses outside the intended workspace (e.g., `# yaml-language-server: $schema=../../sensitive_file.json`). As a result, the language server may attempt to load and validate against a file from an arbitrary location on the user’s filesystem.
  **Impact:**
  - Sensitive local files (such as configuration files or other private data) may be inadvertently disclosed through error messages, hover details, or logs produced by the language server.
  - Attackers could trick users into opening a malicious YAML file that references system files, resulting in unintended file disclosure.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The README documents that relative paths are resolved from the YAML file’s location but does not provide any built‑in restrictions or sandboxing to limit file access.
  **Missing Mitigations:**
  - There is no validation or sandboxing mechanism to restrict relative schema references to a safe subset of the file system (for example, confining access to the current workspace).
  - A mitigation would be to reject or warn about schema references that resolve outside an allowed directory (or otherwise require explicit user confirmation).
  **Preconditions:**
  - An attacker must craft a YAML file that includes a modeline with a relative schema path pointing to a sensitive file (e.g., using path traversal like `../../sensitive_file.json`).
  - The victim must open this malicious YAML file in an instance of Visual Studio Code running the extension.
  **Source Code Analysis:**
  - The documentation in `/code/README.md` explains that a schema URL can be specified in a YAML file and that relative paths are resolved starting from the YAML file’s location.
  - There is no indication (in the provided documentation or changelog) that the implementation validates or constrains such paths.
  - *(Visualization)*
    • Example YAML modeline:
      `# yaml-language-server: $schema=../../secret.txt`
    • Resolution logic: Computed absolute path = (YAML file directory) + "../../secret.txt"
    • Outcome: The language server reads the content of the file without further checks.
  **Security Test Case:**
  1. In a test environment, create a YAML file in a controlled workspace containing the modeline:
     `# yaml-language-server: $schema=../../test_sensitive.txt`
     where `test_sensitive.txt` is a file with known sensitive content located outside the workspace.
  2. Open the YAML file in Visual Studio Code with the vscode‑yaml extension enabled.
  3. Observe whether the extension attempts to read the file specified by the relative path.
  4. Check for any disclosure of the file’s content through validation error messages, hover tooltips, logs, or other UI elements.
  5. Confirm that without additional mitigation the extension reads and potentially exposes the sensitive file content.
  6. As a remediation test, implement a sandboxing or path‑restriction mechanism and verify that attempts to reference files outside the permitted directory are rejected or trigger a clear warning.