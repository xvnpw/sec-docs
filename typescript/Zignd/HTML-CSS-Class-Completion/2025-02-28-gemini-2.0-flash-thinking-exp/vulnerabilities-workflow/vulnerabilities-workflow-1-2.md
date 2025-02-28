### Vulnerability 1

* Vulnerability Name: Server-Side Request Forgery (SSRF) in HTML Parsing
* Description:
    1. The extension parses HTML files to extract CSS class names for autocompletion.
    2. During HTML parsing, the `HtmlParseEngine` identifies `<link rel="stylesheet" href="...">` tags.
    3. If the `href` attribute of a `<link>` tag starts with `http`, the extension uses the `request` library to fetch the content from the specified URL.
    4. The fetched content is then parsed as CSS to extract class names.
    5. A malicious user can craft an HTML file containing a `<link>` tag with an `href` attribute pointing to an internal resource (e.g., `http://localhost:22`, `http://192.168.1.1/admin`) or an attacker-controlled external server.
    6. When the extension parses this malicious HTML file, it will make an HTTP GET request to the attacker-specified URL from the machine running VSCode. This can be exploited to probe internal network resources or leak sensitive information to an external server.
* Impact:
    An attacker can potentially perform the following actions:
    - **Port Scanning of Internal Network:** By providing URLs like `http://localhost:22`, `http://192.168.1.1:80`, the attacker can check if services are running on specific ports within the internal network of the VSCode user.
    - **Information Disclosure:** By targeting internal URLs, the attacker might be able to access configuration pages or retrieve sensitive data exposed on internal services if those services don't require authentication or rely on IP-based access control that trusts the VSCode user's machine.
    - **Exfiltration of Data (Limited):** While direct exfiltration is limited because the response from the URL is parsed for CSS classes, an attacker could potentially encode small amounts of data in URLs and observe the requested URLs on their server.
* Vulnerability Rank: High
* Currently implemented mitigations:
    No mitigations are currently implemented in the project. The code directly fetches external URLs without any validation or sanitization.
* Missing mitigations:
    - **URL Validation and Sanitization:** The extension should validate URLs to ensure they are safe and expected. This could include:
        - Checking the URL scheme (only allow `http` and `https`, or even restrict to `https` only).
        - Implementing a blocklist for private IP ranges (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and potentially reserved IP ranges.
        - Using a whitelist of allowed domains or patterns if the use case allows it (though this might be too restrictive for a general-purpose extension).
    - **Preventing Network Requests to Internal Resources:** Implement checks to prevent requests to `localhost` and private network ranges.
    - **User Confirmation/Warning:** Before making external requests, especially to non-HTTPS URLs, the extension could prompt the user for confirmation or display a warning message, especially if the URL is not from a trusted domain.
* Preconditions:
    - The attacker needs to provide or influence the content of an HTML file that is opened or processed by the VSCode extension. This could be achieved by:
        - Opening a malicious HTML file from a local or network path.
        - If the extension were to process HTML content from remote sources (though not evident in the provided code, this is a potential future risk if the extension's features are expanded).
    - The extension must be activated and running within VSCode.
    - The user must trigger the extension's CSS class caching mechanism, either manually via the command or automatically upon workspace/configuration changes.
* Source code analysis:
    ```typescript
    // /code/src/parse-engines/types/html-parse-engine.ts
    class HtmlParseEngine implements IParseEngine {
        public languageId = "html";
        public extension = "html";

        public async parse(textDocument: ISimpleTextDocument): Promise<CssClassDefinition[]> {
            const definitions: CssClassDefinition[] = [];
            const urls: string[] = [];
            let tag: string;
            let isRelStylesheet = false;
            let linkHref: string | null;

            const parser = new html.Parser({
                onattribute: (name: string, value: string) => {
                    if (name === "rel" && value === "stylesheet") {
                        isRelStylesheet = true;
                    }

                    if (tag === "link" && name === "href" && value.indexOf("http") === 0) { // [LINE 20] URL extraction based on "http" prefix
                        linkHref = value;
                    }
                },
                onclosetag: () => {
                    if (tag === "link" && isRelStylesheet && linkHref) {
                        urls.push(linkHref); // [LINE 27] Add extracted URL to the list for fetching
                    }

                    isRelStylesheet = false;
                    linkHref = null;
                },
                onopentagname: (name: string) => {
                    tag = name;
                },
                ontext: (text: string) => {
                    if (tag === "style") {
                        definitions.push(...CssClassExtractor.extract(css.parse(text)));
                    }
                },
            });

            parser.write(textDocument.getText());
            parser.end();

            await Bluebird.map(urls, async (url) => { // [LINE 43] Process URLs concurrently
                try {
                    const content = await request.get(url); // [LINE 44] HTTP GET request to the URL without validation
                    definitions.push(...CssClassExtractor.extract(css.parse(content)));
                } catch (error) {
                    console.error(`Failed to fetch or parse stylesheet from ${url}:`, error); // Error handling, but no security mitigation
                }
            }, { concurrency: 10 });

            return definitions;
        }
    }
    ```
    - **Line 20**: The code identifies potential external stylesheets by checking if the `href` attribute of a `<link>` tag starts with "http". This is a very basic check and does not perform any further validation on the URL's safety or destination.
    - **Line 27**:  Extracted URLs are added to the `urls` array for later processing.
    - **Line 43-44**: The code iterates through the `urls` array and uses `request.get(url)` to fetch the content of each URL. Crucially, there is no URL validation or sanitization before making the `request.get` call. This is where the SSRF vulnerability is present. The `request.get` function will directly attempt to fetch content from any URL provided, including those pointing to internal network resources or attacker-controlled servers.

* Security test case:
    1. **Setup:**
        - Install the "HTML CSS Class Completion" extension in VSCode.
        - Install `node.js` and `npm` if not already installed.
        - Open a terminal and install `netcat` (e.g., `sudo apt install netcat` on Debian/Ubuntu or use `ncat` on macOS with `brew install nmap`). Alternatively, use Python's `http.server` if preferred.
        - Choose a port for the test listener, e.g., port `8080`.
        - Start a listener on your local machine using `netcat` to capture HTTP requests: `nc -l -p 8080` (or `ncat -lvp 8080`).
    2. **Create Malicious HTML File:**
        - Create a new file named `ssrf_test.html` in a folder that is open in VSCode.
        - Add the following content to `ssrf_test.html`:
            ```html
            <html>
            <head>
                <link rel="stylesheet" href="http://localhost:8080/test.css">
            </head>
            <body>
                <div class="container"></div>
            </body>
            </html>
            ```
            (This test case uses `http://localhost:8080/test.css` to probe the local machine. You can replace `localhost` with a private IP address like `http://192.168.1.1:80/test.css` to test internal network access, assuming you have a network setup for testing).
        - Save the `ssrf_test.html` file.
    3. **Trigger Extension's Cache:**
        - In VSCode, open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`).
        - Type and execute the command "Cache CSS class definitions". This will force the extension to re-cache CSS classes, including parsing the newly created `ssrf_test.html` file.
    4. **Observe Network Traffic:**
        - Monitor the `netcat` listener terminal.
        - If the SSRF vulnerability exists, you will observe an HTTP GET request logged by `netcat` similar to:
            ```
            GET /test.css HTTP/1.1
            Host: localhost:8080
            User-Agent: ... (User agent string of the request library)
            Connection: close
            ```
        - The presence of this logged request confirms that the VSCode extension, when parsing the malicious HTML file, made an outbound HTTP request to `localhost:8080` as instructed by the `<link href="...">` attribute, thus demonstrating the SSRF vulnerability.

This test case demonstrates that an attacker can induce the extension to make arbitrary HTTP requests by controlling the `href` attribute in a `<link rel="stylesheet">` tag within an HTML file.