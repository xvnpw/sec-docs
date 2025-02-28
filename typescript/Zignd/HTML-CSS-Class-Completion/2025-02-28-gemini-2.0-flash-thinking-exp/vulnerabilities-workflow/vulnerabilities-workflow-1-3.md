### Vulnerability List:

* Vulnerability Name: Server-Side Request Forgery (SSRF) in HTML Parse Engine
* Description:
    1. An attacker crafts a malicious HTML file.
    2. The malicious HTML file includes a `<link rel="stylesheet">` tag.
    3. The `href` attribute of the `<link>` tag contains a URL controlled by the attacker (e.g., `http://attacker.com/malicious.css` or `http://localhost:8080/`).
    4. The user opens a workspace in VSCode that contains this malicious HTML file.
    5. The VSCode extension "IntelliSense for CSS class names in HTML" is activated and starts caching CSS class definitions.
    6. The HTML Parse Engine (`src/parse-engines/types/html-parse-engine.ts`) parses the HTML file.
    7. The parser extracts the URL from the `<link>` tag.
    8. The extension, using the `request` library, sends an HTTP GET request to the attacker-controlled URL without proper validation.
    9. The attacker's server receives the request, confirming the SSRF vulnerability.

* Impact:
    * **Server-Side Request Forgery (SSRF):** An attacker can cause the VSCode extension (running on the user's machine) to make requests to arbitrary URLs. This can be exploited to:
        * **Port Scanning:** Scan internal networks and identify open ports and services.
        * **Internal Service Access:** Access internal services or APIs that are not publicly accessible but are reachable from the user's machine's network.
        * **Data Exfiltration:** Potentially exfiltrate sensitive information from internal services if they are accessed and their responses are processed by the extension in an unintended way (although less likely in this specific extension's context).
        * **Denial of Service (Indirect):** Overload internal or external services with requests originating from the user's machine.

* Vulnerability Rank: high
* Currently implemented mitigations:
    * None. The code in `src/parse-engines/types/html-parse-engine.ts` directly fetches URLs from `<link>` tags using the `request` library without any validation or sanitization.

* Missing mitigations:
    * **URL Validation and Sanitization:** Implement validation and sanitization of URLs extracted from `<link>` tags before making HTTP requests. This should include:
        * **Protocol Whitelisting:** Allow only `http://` and `https://` protocols.
        * **Domain Whitelisting/Blacklisting:** Consider whitelisting or blacklisting specific domains based on security policies. For example, restricting requests to only workspace-relative URLs or known safe domains.
        * **Input Sanitization:** Sanitize the URL string to prevent injection attacks if URL construction is done dynamically.
    * **User Confirmation:** For external URLs, consider prompting the user for confirmation before fetching external resources, especially if the URL points to a different domain than the workspace.

* Preconditions:
    * The VSCode extension "IntelliSense for CSS class names in HTML" is installed and activated.
    * A VSCode workspace is opened.
    * The workspace contains an HTML file that includes a `<link rel="stylesheet">` tag with a malicious or attacker-controlled URL in the `href` attribute.
    * The extension's CSS class caching mechanism is triggered (either automatically on workspace load or manually by the user).

* Source code analysis:
    1. **File:** `/code/src/parse-engines/types/html-parse-engine.ts`
    2. **Function:** `parse(textDocument: ISimpleTextDocument)`
    3. **Code Snippet:**
    ```typescript
    await Bluebird.map(urls, async (url) => {
        const content = await request.get(url);
        definitions.push(...CssClassExtractor.extract(css.parse(content)));
    }, { concurrency: 10 });
    ```
    4. **Analysis:**
        * The `parse` function in `HtmlParseEngine` extracts URLs from `<link rel="stylesheet">` tags within HTML files.
        * The extracted URLs are stored in the `urls` array.
        * The code then iterates over the `urls` array using `Bluebird.map`.
        * For each `url` in the `urls` array, it calls `request.get(url)` to fetch the content of the stylesheet from the URL.
        * **Vulnerability:** There is no validation or sanitization of the `url` before it is passed to `request.get()`. This allows an attacker to inject arbitrary URLs, leading to SSRF. The `request.get()` function will blindly send an HTTP GET request to the provided URL.

* Security test case:
    1. **Prerequisites:**
        * Install the "IntelliSense for CSS class names in HTML" extension in VSCode.
        * Have `netcat` or a similar network utility installed, or a simple HTTP server setup.
    2. **Setup Malicious Server:**
        * Open a terminal and start a simple HTTP server using `netcat` to listen on port 8080. For example:
          ```bash
          mkfifo req; while true; do nc -l -p 8080 < req | tee -a req | grep "^Host: " ; done > req
          ```
          (This command will listen on port 8080 and print the Host header of incoming requests)
    3. **Create Malicious HTML File:**
        * Create a new folder and open it as a workspace in VSCode.
        * Create a file named `malicious.html` inside the workspace with the following content:
          ```html
          <!DOCTYPE html>
          <html>
          <head>
              <link rel="stylesheet" href="http://localhost:8080/malicious.css">
          </head>
          <body>
              <div class="container">Hello World</div>
          </body>
          </html>
          ```
    4. **Trigger Caching:**
        * Open the `malicious.html` file in VSCode. This should trigger the extension to activate and start caching CSS classes. If not, you can manually trigger caching by:
            * Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) to open the command palette.
            * Type "Cache CSS class definitions" and select the command.
    5. **Verify SSRF:**
        * Check the terminal where `netcat` is running. You should see an entry for the incoming request. Look for the `Host:` header in the output. If you see `Host: localhost:8080`, it confirms that the VSCode extension has made a request to `http://localhost:8080/malicious.css`, demonstrating the SSRF vulnerability.