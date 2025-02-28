### Vulnerability List

- Vulnerability Name: Remote Code Execution via Malicious Custom Theme CSS
- Description:
    1. An attacker can convince a user to add a malicious URL to the `markdown.marp.themes` setting in VS Code.
    2. The Marp for VS Code extension will fetch and apply the CSS from this URL to the Marp preview and during export.
    3. A malicious CSS file can contain JavaScript code within CSS directives like `@import` or `url()`, which gets executed in the context of the VS Code preview or during export processing by Marp CLI, leading to Remote Code Execution.
- Impact: Remote Code Execution. An attacker can execute arbitrary code on the user's machine by crafting a malicious CSS theme and tricking the user into adding it to their VS Code settings. This can lead to data theft, malware installation, or further system compromise.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - Workspace Trust: The documentation mentions Workspace Trust restricting some features, marked with a shield icon 🛡️, including "Use custom theme CSS 🛡️" and "Export slide deck to HTML, PDF, PPTX, and image 🛡️". However, the extension still loads and applies CSS from remote URLs even in untrusted workspaces, just with restricted HTML rendering.
    - Allowed HTML elements: In trusted workspaces, only a limited set of HTML elements are allowed by default, controlled by `markdown.marp.html`. In untrusted workspaces, HTML elements are always ignored. This mitigates some XSS risks but does not prevent RCE through CSS-based injection.
- Missing Mitigations:
    - Input sanitization and validation: The extension should sanitize and validate URLs provided in `markdown.marp.themes` to ensure they are safe and legitimate.
    - Content Security Policy (CSP): Implement a strict CSP for the Marp preview to prevent the execution of inline scripts and restrict the loading of external resources, especially scripts.
    - Subresource Integrity (SRI): If loading external CSS is necessary, implement SRI to ensure the integrity of fetched resources and prevent tampering.
    - Sandboxing: Isolate the Marp preview rendering process in a sandbox to limit the impact of potential vulnerabilities.
    - Disallow JavaScript execution from CSS: The extension should be configured to disallow or strictly control JavaScript execution within CSS, especially when loading external themes.
- Preconditions:
    - User must have Marp for VS Code extension installed.
    - User must manually add a malicious URL to the `markdown.marp.themes` setting in VS Code. This could be achieved through social engineering, e.g., by sharing a malicious Marp Markdown file that suggests adding a specific theme URL for better rendering.
    - Workspace must be trusted to allow full feature set, although basic preview and theme loading still works in untrusted workspaces and is vulnerable.
- Source Code Analysis:
    1. **`/src/themes.ts`**: The `Themes.registerTheme` function fetches CSS from a provided URI using `fetch(themePath, { timeout: 5000 })` or `readFile(themeUri)`.
    2. **`/src/themes.ts`**: The fetched CSS content is directly added to the Marp Core themeSet using `marp.themeSet.add(css)` in `Themes.getMarpThemeSetFor` and `Themes.registerTheme`.
    3. **`/src/extension.ts`**: The `extendMarkdownIt` function in `activate` loads and registers custom themes using `themes.loadStyles(baseFolder)` and then applies them during Markdown parsing and rendering.
    4. **Marp Core**: Marp Core itself, which is used by the extension, can execute JavaScript within CSS, particularly through `@import` and `url()` directives. If a malicious CSS file is loaded, it can inject and execute arbitrary JavaScript code within the preview context or during export.

    ```typescript
    // /src/themes.ts
    async registerTheme(themeUri: Uri): Promise<Theme> {
        ...
        const css = await (async (): Promise<string> => {
          switch (type) {
            case ThemeType.Remote:
              return await fetch(themePath, { timeout: 5000 }) // Fetch remote CSS
            default:
              return await readFile(themeUri)
          }
        })()

        const registeredTheme: Theme = { css, type, path: ..., };
        this.observedThemes.set(themePath, registeredTheme);
        marp.themeSet.add(css) // Vulnerable line: Directly adding fetched CSS to Marp Core's themeSet
        ...
    }
    ```

- Security Test Case:
    1. Create a malicious CSS file hosted on a publicly accessible server (e.g., `https://attacker.com/malicious-theme.css`). The CSS file should contain JavaScript code that will execute when the CSS is loaded. For example:
    ```css
    @import 'data:text/css;base64, body { background-color: red; }';
    body::after {
      content: url("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>/* Malicious JavaScript Code */ alert('RCE Vulnerability!');</script></svg>");
    }
    ```
    2. Open VS Code and navigate to the settings (File > Preferences > Settings > Settings or Code > Settings > Settings).
    3. Search for `markdown.marp.themes`.
    4. Click "Add Item" and enter `https://attacker.com/malicious-theme.css`.
    5. Open or create a Marp Markdown file (`.md` file with `marp: true` in the front-matter).
    6. Open the preview for the Marp Markdown file (right-click on the editor and select "Open Preview to the Side").
    7. Observe that the JavaScript code in the malicious CSS file is executed. In this test case, an alert box with "RCE Vulnerability!" should be displayed. If alert is not working, try `console.log('RCE Vulnerability!');` and check developer console in preview window (Help -> Toggle Developer Tools -> Console).
    8. To test for export vulnerability, trigger export command (`markdown.marp.export`) for the same Marp Markdown file.
    9. Observe if the JavaScript code executes during the export process. This might be harder to directly observe but can be confirmed by actions the script performs, like sending data to an external server or modifying local files if the environment permits.

---