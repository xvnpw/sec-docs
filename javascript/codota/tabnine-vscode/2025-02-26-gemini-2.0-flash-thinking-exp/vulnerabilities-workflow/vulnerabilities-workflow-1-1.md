## Vulnerability List:

### 1. VSIX Package Download and Installation Vulnerability in Pre-release Channel Updates

- **Vulnerability Name:** VSIX Package Download and Installation Vulnerability in Pre-release Channel Updates
- **Description:**
    1. The Tabnine extension checks for pre-release updates in the `handlePreReleaseChannels` function located in `/code/src/preRelease/installer.ts`.
    2. The `getArtifactUrl` function fetches release information from `LATEST_RELEASE_URL` (defined in `/code/src/globals/consts.ts`) which points to a GitHub API endpoint.
    3. It parses the JSON response to find pre-release assets and selects the `browser_download_url` of the first asset.
    4. The extension downloads the VSIX package from this `browser_download_url` using `downloadFileToDestination`.
    5. Finally, it installs the downloaded VSIX package using `commands.executeCommand(INSTALL_COMMAND, Uri.file(name))`.
    6. There is no explicit verification of the downloaded VSIX package's integrity (e.g., checksum verification) or authenticity (e.g., signature verification) after downloading from the URL.
    7. An attacker who can compromise the GitHub repository serving `LATEST_RELEASE_URL` or perform a MITM attack could replace the legitimate VSIX package with a malicious one.
    8. When the extension installs this malicious VSIX, it could lead to Remote Code Execution (RCE) within the user's VS Code environment upon extension reload or VS Code restart.

- **Impact:**
    - Remote Code Execution (RCE). An attacker can potentially execute arbitrary code on the machine where the VS Code extension is installed. This could lead to full system compromise, data theft, or other malicious activities.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - HTTPS is used for downloading the VSIX package, which provides some protection against MITM attacks, but doesn't prevent attacks originating from a compromised GitHub repository.
    - The code checks if `userConsumesPreReleaseChannelUpdates()` returns true before attempting to download and install, which limits the vulnerability to users who have opted into pre-release channels.

- **Missing Mitigations:**
    - **VSIX Package Integrity Verification:** Implement verification of the downloaded VSIX package's integrity using a checksum (like SHA256) provided by GitHub releases. The extension should compare the calculated checksum of the downloaded file with the expected checksum before attempting installation.
    - **VSIX Package Authenticity Verification:** Ideally, the extension should verify the digital signature of the VSIX package to ensure it is genuinely from Tabnine and hasn't been tampered with. VS Code might offer APIs for VSIX signature verification.

- **Preconditions:**
    - The user must have enabled pre-release channel updates for the Tabnine extension (either by enabling beta channel in settings or having `ALPHA_CAPABILITY` enabled).
    - An attacker must be able to compromise the GitHub repository serving the release information or successfully perform a MITM attack during the VSIX download process.

- **Source Code Analysis:**
    ```typescript
    // File: /code/src/preRelease/installer.ts

    async function getArtifactUrl(): Promise<string | undefined> {
      const response = JSON.parse(
        await downloadFileToStr(LATEST_RELEASE_URL) // LATEST_RELEASE_URL = "https://api.github.com/repos/codota/tabnine-vscode/releases/latest"
      ) as GitHubReleaseResponse;
      return response.filter(({ prerelease }) => prerelease).sort(({ id }) => id)[0]
        ?.assets[0]?.browser_download_url; // Selects the first asset's download URL without validation.
    }

    async function handlePreReleaseChannels(
      context: ExtensionContext
    ): Promise<void> {
      try {
        // ...
        if (userConsumesPreReleaseChannelUpdates()) { // Checks if pre-release updates are enabled.
          const artifactUrl = await getArtifactUrl();
          if (artifactUrl) {
            const availableVersion = getAvailableAlphaVersion(artifactUrl);

            if (isNewerAlphaVersionAvailable(context, availableVersion)) {
              const { name } = await createTempFileWithPostfix(".vsix");
              await downloadFileToDestination(artifactUrl, name); // Downloads VSIX from artifactUrl.
              await commands.executeCommand(INSTALL_COMMAND, Uri.file(name)); // Installs the downloaded VSIX without integrity check.
              // ...
            }
          }
        }
      } catch (e) {
        Logger.error(e);
      }
    }
    ```
    - The code directly downloads and installs the VSIX package from the `browser_download_url` obtained from GitHub API without any integrity or authenticity checks.
    - Visualization:

    ```mermaid
    sequenceDiagram
      participant Extension
      participant GitHubAPI
      participant Attacker
      participant UserVSCode

      Extension->>GitHubAPI: GET LATEST_RELEASE_URL (Release Info)
      GitHubAPI-->>Extension: JSON Response (Release Assets with browser_download_url)
      Extension->>Attacker: Download VSIX from browser_download_url (Potential MITM or compromised repo)
      Attacker-->>Extension: Malicious VSIX (if attack successful)
      Extension->>UserVSCode: Install VSIX (commands.executeCommand(INSTALL_COMMAND))
      UserVSCode-->>UserVSCode: Extension Reload/Restart
      UserVSCode->>UserVSCode: Malicious code execution within VS Code context
    ```

- **Security Test Case:**
    1. **Setup:**
        - Enable pre-release updates for the Tabnine extension in VS Code settings.
        - Set up a local HTTP proxy (e.g., using Burp Suite or mitmproxy).
    2. **MITM Attack Simulation:**
        - Configure the proxy to intercept traffic to the GitHub API endpoint (`LATEST_RELEASE_URL`).
        - When the extension requests the latest release information, the proxy should intercept the response.
        - Modify the intercepted JSON response to replace the `browser_download_url` of the VSIX asset with a URL pointing to a malicious VSIX package hosted by the attacker.
        - Forward the modified response to the extension.
    3. **Trigger Update Check:**
        - Force the extension to check for pre-release updates (this might require restarting VS Code or triggering an update check mechanism if available).
    4. **Observe Installation:**
        - Observe that the extension downloads and attempts to install the malicious VSIX package from the attacker-controlled URL.
    5. **Verify Code Execution (Example):**
        - The malicious VSIX package could be crafted to display a warning message or perform some other observable action upon installation or extension activation to confirm code execution.
    6. **Expected Result:** The extension should attempt to install the malicious VSIX package without any warnings about integrity or authenticity, potentially leading to code execution within the VS Code environment.
    7. **Note:** For a real-world test, creating a truly malicious VSIX package and hosting it is necessary. In a controlled testing environment, a benign VSIX that simply displays a message box can be used to demonstrate the vulnerability.