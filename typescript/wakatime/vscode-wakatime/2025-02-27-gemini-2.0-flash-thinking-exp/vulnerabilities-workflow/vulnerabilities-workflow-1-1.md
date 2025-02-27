### Vulnerability List

- Vulnerability Name: Server-Side Request Forgery (SSRF) in Web Extension
- Description:
    - An attacker can control the `api_url` setting of the WakaTime extension for VSCode Web.
    - The extension in web environment makes API requests using `fetch` to the configured `api_url`.
    - Without proper validation of the `api_url`, it leads to a Server-Side Request Forgery (SSRF) vulnerability.
    - An attacker can set the `api_url` to a malicious server, internal or external.
    - This causes the extension to make requests to that server.
    - This can be exploited to probe internal network resources or perform other malicious actions from the context of the VSCode web extension.
- Impact:
    - An attacker can use the VSCode web extension as a proxy to make requests to internal network resources or external servers.
    - This could lead to:
        - Information disclosure by accessing sensitive data on internal servers.
        - Internal network scanning to discover open ports and services.
        - Potential exploitation of vulnerabilities in internal services if they are reachable and exploitable through HTTP requests.
- Vulnerability Rank: high
- Currently implemented mitigations:
    - None. The `api_url` setting is directly used in `fetch` calls in `src/web/wakatime.ts` without any validation to prevent SSRF.
- Missing mitigations:
    - Input validation and sanitization for the `api_url` setting.
    - Implement a whitelist of allowed API domains or URL prefixes.
    - Validate that the provided API URL is a valid and expected WakaTime API endpoint.
    - Prevent users from setting arbitrary URLs for `api_url`.
- Preconditions:
    - The attacker needs to be able to configure the `api_url` setting of the WakaTime extension in VSCode Web. This can be done through VSCode settings UI.
    - The VSCode Web environment needs to have network access to the target internal or external resources that the attacker wants to reach.
- Source code analysis:
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
- Security test case:
    - Step 1: Open VSCode in a web browser (e.g., vscode.dev).
    - Step 2: Install the WakaTime extension in the web VSCode.
    - Step 3: Open VSCode settings (File -> Preferences -> Settings).
    - Step 4: Search for "WakaTime Api Url".
    - Step 5: In the "WakaTime: Api Url" setting, enter a malicious URL, for example, `http://attacker.example.com`.
    - Step 6: Open any code file in VSCode editor and start editing it to trigger a heartbeat.
    - Step 7: Open browser's developer tools (Network tab).
    - Step 8: Verify that a network request (e.g., POST) is made to `http://attacker.example.com/users/current/heartbeats?api_key=YOUR_API_KEY`.
    - Step 9: On the attacker's server (`attacker.example.com`), set up a simple HTTP listener and verify that a request is received from the VSCode web extension. This confirms the SSRF vulnerability as the extension is making requests to the attacker-controlled `api_url`.