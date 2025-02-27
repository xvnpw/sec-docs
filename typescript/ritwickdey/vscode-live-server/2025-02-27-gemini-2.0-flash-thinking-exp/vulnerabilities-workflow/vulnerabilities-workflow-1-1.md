### Vulnerability List

- Vulnerability Name: Server-Side Request Forgery (SSRF) via Proxy Configuration

- Description:
    1. An attacker can trick a user into configuring the `liveServer.settings.proxy.proxyUri` setting in VS Code.
    2. The user then starts the Live Server extension.
    3. When the Live Server receives a request matching the `baseUri` configured in the proxy settings, it will forward this request to the URL specified in `proxyUri`.
    4. If the attacker controlled the `proxyUri` configuration, they can make the Live Server act as a proxy to any URL they specify.
    5. This allows the attacker to potentially access internal network resources or external resources that the user's machine has access to.

- Impact:
    - An attacker can use the Live Server extension as a proxy to perform Server-Side Request Forgery (SSRF) attacks.
    - This can lead to unauthorized access to internal network resources, sensitive data exposure, or further exploitation of internal systems if the user's VS Code environment has network access to internal resources.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The extension directly uses the configured `proxyUri` without validation.

- Missing Mitigations:
    - Input validation and sanitization for the `proxyUri` setting.
    - Implement a whitelist or blacklist for allowed proxy destinations.
    - Warn users about the security risks of using proxy configurations, especially when using untrusted `proxyUri` values.

- Preconditions:
    - The attacker needs to trick a user into configuring the `liveServer.settings.proxy.proxyUri` setting with a URL controlled by the attacker or pointing to an internal resource.
    - The user must have the Live Server extension installed and activated in VS Code.
    - The user needs to start the Live Server.
    - The user's machine must have network access to the target resource specified in the malicious `proxyUri`.

- Source Code Analysis:
    1. File: `/code/src/Config.ts`
        - The `Config.getProxy()` function retrieves the proxy settings from VS Code configuration without any validation:
        ```typescript
        public static get getProxy(): IProxy {
            return Config.getSettings<IProxy>('proxy');
        }
        ```
    2. File: `/code/src/Helper.ts`
        - The `Helper.getProxySetup()` function reads the proxy configuration from `Config.getProxy()`:
        ```typescript
        static getProxySetup() {
            const proxySetup = Config.getProxy;
            let proxy = [[]];
            if (proxySetup.enable === true) {
                proxy[0].push(proxySetup.baseUri, proxySetup.proxyUri);
            }
            else {
                proxy = null; // required to change the type [[]] to black array [].
            }

            return proxy;
        }
        ```
    3. File: `/code/lib/live-server/index.js`
        - In `LiveServer.start()`, the proxy configuration is retrieved from `Helper.generateParams()` and then used to configure the `proxy-middleware`:
        ```javascript
        proxy.forEach(function (proxyRule) {
            var proxyOpts = url.parse(proxyRule[1]); // proxyRule[1] is proxyUri from config
            proxyOpts.via = true;
            proxyOpts.preserveHost = true;
            app.use(proxyRule[0], require('proxy-middleware')(proxyOpts)); // proxyRule[0] is baseUri
            if (LiveServer.logLevel >= 1)
                console.log('Mapping %s to "%s"', proxyRule[0], proxyRule[1]);
        });
        ```
        - The `proxyUri` from user configuration is directly passed to `url.parse()` and `proxy-middleware` without any validation or sanitization.

- Security Test Case:
    1. Install the Live Server extension in VS Code.
    2. Open a workspace folder in VS Code.
    3. Create a file named `.vscode/settings.json` in the workspace root.
    4. Add the following configuration to `.vscode/settings.json` to set up a malicious proxy. Replace `http://internal.example.com/sensitive-data` with a URL pointing to an internal resource or a URL you control for testing purposes:
        ```json
        {
            "liveServer.settings.proxy": {
                "enable": true,
                "baseUri": "/api",
                "proxyUri": "http://internal.example.com/sensitive-data"
            }
        }
        ```
    5. Create an HTML file (e.g., `index.html`) in the workspace root. The content of the HTML file is not important for this test.
    6. Start the Live Server by clicking "Go Live" in the status bar or using any other start method.
    7. Open a browser and navigate to `http://localhost:<port>/api` (replace `<port>` with the port Live Server is running on, usually 5500).
    8. Observe the response in the browser. If the SSRF is successful, you will see the content from `http://internal.example.com/sensitive-data` (or your test URL) displayed in the browser, served through the Live Server proxy.
    9. To further verify, you can set `proxyUri` to a requestbin or webhook.site URL and observe the incoming request, confirming that the Live Server is making a request to the specified external URL.