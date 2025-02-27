### Vulnerability List:

* Vulnerability Name: Server-Side Request Forgery (SSRF) in External Stylesheet Fetching
* Description:
    1. An attacker creates or modifies an HTML file within a workspace opened in VSCode with the extension installed.
    2. In the HTML file, the attacker inserts a `<link>` tag with the `rel` attribute set to `stylesheet` and the `href` attribute pointing to an attacker-controlled URL. This URL can be an internal resource (e.g., `http://localhost:1337`) or an external malicious site.
    3. When the extension parses this HTML file, either automatically upon file change or manually via the "Cache CSS class definitions" command, the `HtmlParseEngine` extracts the URL from the `href` attribute of the `<link>` tag.
    4. The `HtmlParseEngine`, located in `/code/src/parse-engines/types/html-parse-engine.ts`, uses the `request` library to fetch the content from the extracted URL using `request.get(url)`.
    5. The response from the fetched URL is then parsed as CSS, and CSS class names are extracted to provide autocompletion suggestions.
    6. Due to the lack of proper URL validation, the extension makes an outbound request to the attacker-specified URL. This can lead to SSRF, allowing the attacker to potentially access internal network resources, probe internal services, or leak sensitive information to external sites under the attacker's control.
* Impact:
    - Information Disclosure: An attacker can potentially access sensitive information from internal services if the extension is tricked into making requests to internal endpoints (e.g., configuration files, internal APIs).
    - Internal Port Scanning: The attacker can use the extension to probe open ports on internal networks by providing URLs like `http://localhost:PORT`, potentially mapping out internal network infrastructure.
    - Potential for further exploitation: Depending on the nature of the internal services exposed, successful SSRF can be a stepping stone to more severe vulnerabilities.
* Vulnerability Rank: high
* Currently implemented mitigations:
    - None. The code in `/code/src/parse-engines/types/html-parse-engine.ts` checks if the URL starts with "http" (`value.indexOf("http") === 0`) but this is insufficient to prevent SSRF attacks. It does not validate the hostname, protocol, or path to ensure the URL is safe.
* Missing mitigations:
    - Implement robust URL validation and sanitization in `/code/src/parse-engines/types/html-parse-engine.ts` before making external requests using `request.get(url)`.
    - Consider using a whitelist of allowed domains or URL patterns for external stylesheets to restrict the scope of allowed external requests.
    - Implement checks to prevent requests to internal networks or reserved IP addresses (e.g., private IP ranges, localhost).
* Preconditions:
    - The victim must have the VSCode extension installed and activated.
    - The attacker needs to be able to create or modify HTML files within a workspace that is open in VSCode. This could be achieved through various means, such as contributing to a shared workspace, exploiting other vulnerabilities to write files, or social engineering.
* Source code analysis:
    - Vulnerable code is located in `/code/src/parse-engines/types/html-parse-engine.ts`.
    - The `parse` function in `HtmlParseEngine` extracts `href` attributes from `<link rel="stylesheet">` tags.
    - The extracted URLs are stored in the `urls` array.
    - The following code block iterates through the `urls` array and fetches content from each URL using `request.get(url)`:
    ```typescript
    await Bluebird.map(urls, async (url) => {
        const content = await request.get(url);
        definitions.push(...CssClassExtractor.extract(css.parse(content)));
    }, { concurrency: 10 });
    ```
    - There is no validation of the `url` within this block before the `request.get(url)` call, making it vulnerable to SSRF. The check `value.indexOf("http") === 0` in the `onattribute` handler is insufficient for security.

    ```mermaid
    graph LR
        A[HTML File] --> B{HTML Parser (htmlparser2)};
        B --> C{onattribute: name="href", value=URL};
        C -- rel="stylesheet" --> D{Extract URL};
        D --> E[URLs Array];
        E --> F{Bluebird.map(urls)};
        F --> G{request.get(URL)};
        G --> H[Response Content];
        H --> I{css.parse(Content)};
        I --> J{CssClassExtractor.extract()};
        J --> K[CssClassDefinitions];
    ```

* Security test case:
    1. Setup: You will need a VSCode instance with the extension installed and a tool to observe HTTP requests, such as `requestbin.com` or a local HTTP server.
    2. Create a new workspace or open an existing one in VSCode.
    3. Create a new HTML file (e.g., `test.html`) in the workspace.
    4. Insert the following HTML code into `test.html`, replacing `<YOUR_REQUESTBIN_URL>` with a RequestBin URL or the address of your local HTTP server:
    ```html
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" href="http://<YOUR_REQUESTBIN_URL>.requestbin.net/ssrf-test">
    </head>
    <body>
        <div class="container"></div>
    </body>
    </html>
    ```
    5. Open the Command Palette (Ctrl+Shift+P or Cmd+Shift+P) and execute the command "Cache CSS class definitions".
    6. Observe the HTTP requests received by your RequestBin URL or local HTTP server. You should see an incoming GET request to `http://<YOUR_REQUESTBIN_URL>.requestbin.net/ssrf-test`, originating from the VSCode extension. This confirms that the extension is making an external request to the URL specified in the HTML file.
    7. To test for internal SSRF, modify the `href` attribute in `test.html` to point to `http://localhost:1337`. Ensure no service is running on port 1337 of your localhost to avoid accidental interaction with a real service during the test, or set up a simple HTTP listener on port 1337 to observe the request.
    ```html
    <link rel="stylesheet" href="http://localhost:1337">
    ```
    8. Execute the "Cache CSS class definitions" command again.
    9. Observe if the extension attempts to connect to `http://localhost:1337`. If you have a listener on port 1337, you should see an incoming connection attempt in its logs. This demonstrates the potential for internal SSRF.