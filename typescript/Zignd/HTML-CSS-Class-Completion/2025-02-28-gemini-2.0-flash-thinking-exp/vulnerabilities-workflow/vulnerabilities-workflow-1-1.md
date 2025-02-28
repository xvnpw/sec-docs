### Vulnerability List

- Vulnerability Name: Server-Side Request Forgery (SSRF) in External Stylesheet Fetching
- Description:
    1. An attacker crafts a malicious HTML file.
    2. The malicious HTML file includes a `<link>` tag that points to an internal or malicious URL in the `href` attribute. For example: `<link rel="stylesheet" href="http://internal.example.com/sensitive-data.css">` or `<link rel="stylesheet" href="http://malicious-attacker.com/malicious.css">`.
    3. The user opens this malicious HTML file in VSCode within a workspace where the extension is active.
    4. The extension's `HtmlParseEngine` parses the HTML file and identifies the `<link>` tag.
    5. The `HtmlParseEngine` uses the `request` library to fetch the content of the URL specified in the `href` attribute without proper validation.
    6. The `request` library sends an HTTP GET request to the attacker-controlled URL (`http://internal.example.com/sensitive-data.css` or `http://malicious-attacker.com/malicious.css`).
    7. If the URL points to an internal resource, the extension can access and potentially leak sensitive information from the internal network. If the URL points to a malicious server, the attacker can potentially gain information about the extension's environment or stage further attacks.
- Impact:
    - **Information Disclosure:** An attacker can potentially access sensitive information from internal network resources if the VSCode instance is running within a network that has internal resources accessible. For example, they might be able to access internal configuration files, API endpoints, or other sensitive data.
    - **Port Scanning:** An attacker could use this vulnerability to perform port scanning on internal network, identifying open ports and services running on internal machines.
    - **Exfiltration of Workspace Files (in some scenarios):** If an attacker can control a server that the VSCode instance can reach, they might be able to exfiltrate contents of files by crafting responses that trigger specific behaviors in the extension or VSCode itself (though less likely in this specific case, but SSRF can be a stepping stone).
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly uses `request.get(url)` without any URL validation or sanitization in `/code/src/parse-engines/types/html-parse-engine.ts`.
- Missing Mitigations:
    - **URL Validation:** Implement robust URL validation to ensure that only external stylesheets from trusted domains or within the workspace are fetched. A whitelist of allowed domains or protocols could be used. Alternatively, restricting to only `https` protocol would be a good starting point.
    - **Input Sanitization:** While URL validation is key, general input sanitization practices should be considered to prevent other potential injection issues.
- Preconditions:
    - The user must have the extension installed and activated in VSCode.
    - The user must open a workspace in VSCode that contains a malicious HTML file or a HTML file that includes a link to a malicious external stylesheet.
    - The user's VSCode instance must have network connectivity to the attacker-controlled URL or the internal resource the attacker wants to access.
- Source Code Analysis:
    1. **File:** `/code/src/parse-engines/types/html-parse-engine.ts`
    2. **Function:** `HtmlParseEngine.parse`
    3. **Code Snippet:**
    ```typescript
    await Bluebird.map(urls, async (url) => {
        const content = await request.get(url); // Vulnerable line: No URL validation
        definitions.push(...CssClassExtractor.extract(css.parse(content)));
    }, { concurrency: 10 });
    ```
    4. **Vulnerability Flow:**
        - The `HtmlParseEngine.parse` function extracts URLs from `<link rel="stylesheet" href="...">` tags in HTML files.
        - The extracted URLs are stored in the `urls` array.
        - The code iterates through the `urls` array using `Bluebird.map`.
        - For each `url` in `urls`, `request.get(url)` is called to fetch the content of the URL.
        - **Vulnerability:** The `url` variable, which comes directly from the `href` attribute of the `<link>` tag in the HTML file, is passed directly to `request.get()` without any validation. This allows an attacker to control the URL that `request.get()` fetches, leading to SSRF.
    5. **Visualization:**
    ```
    [Malicious HTML File] -->  HtmlParseEngine.parse() --> [Extracts URLs] --> urls[] --> Bluebird.map(urls, ...) --> request.get(url) [NO VALIDATION] --> [External/Internal Server]
    ```
- Security Test Case:
    1. **Setup:**
        - Install the "HTML CSS Class Completion" extension in VSCode.
        - Create a new workspace in VSCode.
        - Create a new HTML file named `malicious.html` in the workspace.
        - On a separate attacker-controlled server (e.g., using `python -m http.server 8000` in a directory with a file named `malicious.css`), create a file named `malicious.css` with any content (e.g., `.test-class { color: red; }`).
        - In `malicious.css` on the attacker server, add a line to log the incoming request, for example, if using python http server, you will see request in console.
    2. **Craft Malicious HTML:**
        - In `malicious.html`, add the following content:
        ```html
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="http://localhost:8000/malicious.css"> <--- Attacker controlled URL
        </head>
        <body>
            <div class="test-class">Hello World</div>
        </body>
        </html>
        ```
        - Replace `http://localhost:8000/malicious.css` with the actual URL of your attacker-controlled server. If you want to test internal network access, replace it with a URL to an internal resource (e.g., `http://internal.example.com/`).
    3. **Trigger Vulnerability:**
        - Open the `malicious.html` file in VSCode within the created workspace.
        - Observe the attacker-controlled server's logs. You should see an HTTP request originating from VSCode to `http://localhost:8000/malicious.css`. This confirms that the extension is fetching the external stylesheet from the attacker-specified URL.
    4. **Expected Result:**
        - The attacker-controlled server receives an HTTP GET request when `malicious.html` is opened in VSCode.
        - If you point the `href` to an internal resource, you might be able to observe network traffic indicating access to that internal resource (depending on network setup and monitoring capabilities).