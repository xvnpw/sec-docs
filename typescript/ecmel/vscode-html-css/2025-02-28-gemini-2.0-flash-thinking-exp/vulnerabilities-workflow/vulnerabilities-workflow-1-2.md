### Vulnerability List

- Vulnerability Name: Server-Side Request Forgery (SSRF) in Stylesheet Fetching
- Description:
    1. An attacker can configure the `css.styleSheets` setting in the VS Code workspace settings.
    2. The attacker provides a malicious URL as a value in the `css.styleSheets` array. This URL can point to an internal service, a requestbin for exfiltration, or a slow endpoint.
    3. When the "vscode-html-css" extension is activated (e.g., upon opening a relevant file like an HTML file), the `Provider.getStyles` function is triggered.
    4. `getStyles` iterates through the configured `css.styleSheets`. For each entry, it checks if it's a remote URL using `this.isRemote.test(glob)`.
    5. If identified as a remote URL, the `getRemote` function is called with the malicious URL.
    6. `getRemote` function uses the `fetch(url)` API to make an HTTP request to the attacker-controlled URL without any validation or sanitization.
    7. The VS Code extension, acting as a client, initiates an HTTP request to the specified malicious URL.
    8. If the malicious URL points to an internal service within the network where VS Code is running, the attacker can potentially access and interact with that internal service.
    9. If the malicious URL points to a service like RequestBin, the attacker can capture and inspect the details of the HTTP request originating from the VS Code environment. This may reveal sensitive information about the user's environment or workspace.
- Impact:
    - Information Disclosure: An attacker might gain access to sensitive information from internal services or the VS Code environment by observing the responses from the malicious URL or by capturing request details.
    - Internal Network Access: An attacker could potentially interact with internal network resources that are accessible from the VS Code environment, potentially leading to further unauthorized actions depending on the nature of the internal services.
- Vulnerability Rank: high
- Currently implemented mitigations:
    - None. The extension directly fetches URLs provided in the `css.styleSheets` setting without any validation or security measures.
- Missing mitigations:
    - Input validation and sanitization for URLs in the `css.styleSheets` setting to prevent malicious URLs.
    - Implement URL scheme restriction to only allow `https` URLs, or a whitelist of allowed schemes.
    - Implement a blocklist for specific hostnames or IP ranges, especially to prevent access to private IP ranges or known malicious hosts.
    - Introduce a user confirmation or warning mechanism before fetching remote stylesheets, especially if the URL is not from a trusted domain, to ensure users are aware of potential risks.
- Preconditions:
    - The "vscode-html-css" extension must be installed and activated in VS Code.
    - A user must open a workspace in VS Code.
    - The user or an attacker (if they can influence workspace settings) must configure the `css.styleSheets` setting in the workspace's `.vscode/settings.json` file and include a malicious URL.
    - The extension needs to be triggered to activate, typically by opening a file type that the extension processes (e.g., HTML, or any language enabled in `css.enabledLanguages`).
- Source code analysis:
    - `src/settings.ts`: The `getStyleSheets` function retrieves the `css.styleSheets` configuration.
    - `src/provider.ts`:
        - `getStyles` function iterates through stylesheets and calls `getRemote` for remote URLs:
          ```typescript
          private async getStyles(document: TextDocument) {
              ...
              for (const glob of globs) {
                  if (this.isRemote.test(glob)) {
                      styles.set(glob, await this.getRemote(glob));
                  } ...
              }
              ...
          }
          ```
        - `getRemote` function fetches remote content using `fetch`:
          ```typescript
          private async getRemote(name: string) {
              ...
              const content = await this.fetch(name);
              styles = parse(content);
              ...
          }
          ```
        - `fetch` function directly uses the `fetch` API on user-provided URLs without any validation:
          ```typescript
          private async fetch(url: string) {
              try {
                  const res = await fetch(url); // No URL validation here
                  const res = await fetch(url);
                  if (res.ok) {
                      return res.text();
                  }
                  throw new Error(res.statusText);
              } catch (error) {
                  window.showErrorMessage(`Fetching ${url} failed. ${error}`);
              }
              return "";
          }
          ```
- Security test case:
    1. Install the "vscode-html-css" extension in VS Code.
    2. Open VS Code and create a new workspace, or open an existing one.
    3. In the workspace root, create or modify the `.vscode/settings.json` file.
    4. Add the following configuration to `.vscode/settings.json`, replacing `YOUR_REQUESTBIN_URL` with a valid RequestBin URL (e.g., from https://requestbin.com/ or a self-hosted alternative):
       ```json
       {
         "css.styleSheets": [
           "YOUR_REQUESTBIN_URL"
         ]
       }
       ```
    5. Create a new HTML file (e.g., `test.html`) or open an existing HTML file within the workspace. This action should trigger the extension to activate and attempt to fetch the stylesheet from the configured URL.
    6. Navigate to your RequestBin URL in a web browser.
    7. Inspect the captured requests in RequestBin. You should observe an HTTP request originating from the VS Code environment to the URL you configured in `css.styleSheets`. The request details (headers, IP address, etc.) can confirm the SSRF vulnerability and may reveal information about the VS Code environment.