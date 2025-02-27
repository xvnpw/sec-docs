- Vulnerability name: Cross-Site Scripting (XSS) vulnerability in Plot Webview when rendering SVG plots
- Description:
    1. A threat actor can craft a malicious SVG payload that contains embedded JavaScript code.
    2. If a user executes Julia code (in REPL or Notebook) that generates an SVG plot and if this generated SVG plot incorporates the malicious SVG payload, the Julia extension will receive this SVG data.
    3. The Julia extension's plot feature (specifically in `plots.ts`) embeds this SVG content directly into a webview without sufficient sanitization.
    4. When the webview renders the HTML containing the malicious SVG, the embedded JavaScript code within the SVG will be executed within the context of the webview.
    5. This allows the threat actor to execute arbitrary JavaScript code within the VS Code extension's plot webview, potentially leading to information disclosure or further exploitation.
- Impact: Arbitrary JavaScript code execution within the VS Code extension's plot webview. This could enable an attacker to steal sensitive information accessible within the webview context, manipulate the displayed content for phishing, or potentially escalate privileges if other vulnerabilities exist in the extension or VS Code itself.
- Vulnerability rank: High
- Currently implemented mitigations: None. The code in `plots.ts` directly embeds the SVG content into the webview without any sanitization.
- Missing mitigations:
    - SVG Sanitization: Implement sanitization of SVG payloads before embedding them into the webview. This should remove or neutralize any embedded JavaScript, such as `<script>` tags and event handlers (e.g., `onload`, `onclick`). A library like DOMPurify could be used for effective SVG sanitization.
    - Content Security Policy (CSP): Implement a strict Content Security Policy for the plot webview to restrict the execution of inline scripts and the loading of external resources. This can act as a defense-in-depth measure even if sanitization is bypassed.
- Preconditions:
    - The user must execute Julia code (either in a REPL or Notebook) that results in the generation of an SVG plot.
    - The Julia code must be crafted in such a way that the generated SVG payload contains embedded malicious JavaScript. This could be achieved by manipulating plotting libraries or directly constructing SVG strings in Julia code.
    - The plot pane feature must be in use or the plot must be displayed in a webview context where this rendering path is triggered.
- Source code analysis:
    1. File: `/code/src/interactive/plots.ts`
    2. Function: `displayPlot(params: { kind: string, data: string }, kernel?: JuliaKernel)`
    3. Condition: `if (kind === 'image/svg+xml')`
    4. Code Path:
        ```typescript
        else if (kind === 'image/svg+xml') {
            const has_xmlns_attribute = payload.includes('xmlns=')
            let plotPaneContent: string
            if (has_xmlns_attribute) {
                plotPaneContent = wrapImagelike(`data:image/svg+xml,${encodeURIComponent(payload)}`) // [POINT OF VULNERABILITY] - SVG payload is embedded without sanitization
            } else {
                plotPaneContent = payload
            }

            g_currentPlotIndex = g_plots.push(plotPaneContent) - 1
            showPlotPane()
        }
        ```
    5. Function: `wrapImagelike(srcString: string)`
        ```typescript
        function wrapImagelike(srcString: string) {
            const isSvg = srcString.includes('data:image/svg+xml')
            let svgTag = ''
            if (isSvg) {
                svgTag = decodeURIComponent(srcString).replace(/^data.*<\?xml version="1\.0" encoding="utf-8"\?>\n/i, '')
                svgTag = `<div id="plot-element">${svgTag}</div>` // [POINT OF VULNERABILITY] - SVG tag is directly constructed and embedded
            }

            return `<html lang="en" style="padding:0;margin:0;">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                    <title>Julia Plots</title>
                    <style>
                    ${plotElementStyle}
                    </style>
                </head>
                <body style="padding:0;margin:0;">
                    ${isSvg ? svgTag : `<img id= "plot-element" style = "max-height: 100vh; max-width: 100vw; display:block;" src = "${srcString}" >`}
                </body>
                </html>`
        }
        ```
    6. Visualization: The SVG `payload` received from Julia process is directly embedded into the webview HTML content through `wrapImagelike` function without any sanitization, creating a path for XSS.

- Security test case:
    1. Install the Julia VS Code extension.
    2. Open VS Code and create a new Julia file or open an existing Julia project.
    3. Ensure that you have Plotly.jl installed in your Julia environment. If not, open Julia REPL (Julia: Start REPL) and run `using Pkg; Pkg.add("PlotlyJS")`.
    4. Open a Julia REPL (Julia: Start REPL) or a Julia Notebook.
    5. Execute the following Julia code in the REPL or a cell in the notebook to generate a malicious SVG plot using PlotlyJS:
        ```julia
        using PlotlyJS
        plot(scatter(x=[1,2,3], y=[4,5,6]), HTML("<script>alert('XSS Vulnerability!')</script>"))
        ```
        Or alternatively, use this code to inject `onload` event handler:
        ```julia
        using PlotlyJS
        svg_payload = """<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')"><circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" /></svg>"""
        plot(Dict("data" => [Dict("type" => "scatter", "x" => [1, 2], "y" => [1, 2])], "layout" => Dict("annotations" => [Dict("x" => 0.5, "y" => 0.5, "xref" => "paper", "yref" => "paper", "text" => svg_payload, "showarrow" => false)])))
        ```
    6. If the plot pane is not already visible, activate it by running the command "Julia: Show Plot Pane".
    7. Observe if an alert dialog box appears in VS Code with the message "XSS Vulnerability!" or "XSS".
    8. If the alert box appears, it confirms that the XSS vulnerability is present in the plot webview when rendering SVG plots.

- Vulnerability name: Path Traversal in Documentation Viewer via `file://` links
- Description:
    1. A threat actor crafts a malicious Markdown document containing a `file://` link. This link can point to any file on the user's local file system.
    2. If a user opens or previews this malicious Markdown document using the Julia extension's documentation viewer, the extension will parse the Markdown content.
    3. The `markdown-it` library, configured in `documentation.ts`, processes the `file://` link. The custom link validator `md.validateLink` and renderer rule `md.renderer.rules.link_open` in `documentation.ts` are designed to handle and open these links.
    4. The `link_open` rule uses `vscode.commands.executeCommand('language-julia.openFile', { path: uri, line })` or `vscode.commands.executeCommand('vscode.open', uri)` to open the linked resource. For `file://` links, the `uri` is constructed directly from the link in the Markdown document without sufficient sanitization.
    5. The `language-julia.openFile` command, implemented in `repl.ts`, uses `vscode.window.showTextDocument` to open the file specified by the `path` parameter. If the `path` is not properly validated, it can lead to path traversal, allowing access to files outside the intended scope.
    6. By exploiting this path traversal vulnerability, a threat actor can potentially trick a user into opening sensitive local files (e.g., `/etc/passwd` on Linux/macOS or `C:\Windows\System32\drivers\etc\hosts` on Windows) through the documentation viewer, leading to information disclosure.
- Impact: Disclosure of sensitive local files. An attacker can potentially read the content of arbitrary files on the user's system that the VS Code process has access to.
- Vulnerability rank: High
- Currently implemented mitigations: The code in `documentation.ts` uses `md.validateLink` which, while intending to restrict protocols, might inadvertently allow `file://` protocol. The `language-julia.openFile` command in `repl.ts` directly opens the provided path without path traversal sanitization.
- Missing mitigations:
    - Strict validation and sanitization of `file://` URLs within the `md.validateLink` function in `documentation.ts` to prevent path traversal. Ideally, `file://` protocol should be completely disallowed or strictly limited to specific whitelisted paths if absolutely necessary.
    - Path traversal sanitization within the `openFile` function in `repl.ts` to ensure that only files within the workspace or allowed directories can be opened, regardless of the protocol used.
- Preconditions:
    - The user must open or preview a malicious Markdown document using the Julia extension's documentation viewer.
    - This Markdown document must contain a crafted `file://` link pointing to a sensitive file on the user's local file system.
    - The documentation viewer feature must be in use and the user must interact with the malicious link.
- Source code analysis:
    1. File: `/code/src/docbrowser/documentation.ts`
    2. Function: `md.validateLink = (url) => { ... }`
    3. Code Path: The `validateLink` function checks for `vbscript|javascript|data` protocols but might allow `file://` protocol.
        ```typescript
        const BAD_PROTO_RE = /^(vbscript|javascript|data):/
        const GOOD_DATA_RE = /^data:image\/(gif|png|jpeg|webp);/
        md.validateLink = (url) => {
            const str = url.trim().toLowerCase()
            return BAD_PROTO_RE.test(str) ? (GOOD_DATA_RE.test(str) ? true : false) : true
        }
        ```
        If `url` is `file:///etc/passwd`, `BAD_PROTO_RE.test(str)` will be false, and the function will return `true`, allowing the link.

    4. Function: `md.renderer.rules.link_open = (tokens, idx, options, env, self) => { ... }`
    5. Code Path: The `link_open` function extracts the href from the token and uses `openArgs` to parse it. Then it uses `vscode.commands.executeCommand` to open the URI using `language-julia.openFile` or `vscode.open`.
        ```typescript
        md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
            const aIndex = tokens[idx].attrIndex('href')
            if (aIndex >= 0 && tokens.length > idx + 1) {
                const href = tokens[idx + 1].content
                const { uri, line } = openArgs(href)
                let commandUri
                if (line === undefined) {
                    commandUri = constructCommandString('vscode.open', uri)
                } else {
                    commandUri = constructCommandString('language-julia.openFile', { path: uri, line })
                }
                tokens[idx].attrs[aIndex][1] = commandUri
            }
            return self.renderToken(tokens, idx, options)
        }
        ```
    6. Function: `openArgs(href: string)`
    7. Code Path: Parses the href string to extract URI and line number. It uses `vscode.Uri.parse(matches[1])` which will parse `file:///etc/passwd` correctly as a file URI.
        ```typescript
        function openArgs(href: string) {
            const matches = href.match(/^((\w+\:\/\/)?.+?)(?:[\:#](\d+))?$/)
            let uri
            let line
            if (matches[1] && matches[3] && matches[2] === undefined) {
                uri = matches[1]
                line = parseInt(matches[3])
            } else {
                uri = vscode.Uri.parse(matches[1])
            }
            return { uri, line }
        }
        ```
    8. File: `/code/src/interactive/repl.ts`
    9. Function: `openFile(file: string, line: number, preserveFocus?: boolean)`
    10. Code Path:  Opens the file using `vscode.window.showTextDocument(vscode.Uri.file(file), { ... })` without any path traversal checks.
        ```typescript
        export async function openFile(file: string, line: number, column?: number, preserveFocus?: boolean) {
            try {
                const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(file))
                await vscode.window.showTextDocument(doc, {
                    selection: new vscode.Range(line - 1, column === undefined ? 0 : column - 1, line - 1, column === undefined ? 0 : column - 1),
                    preserveFocus: preserveFocus,
                    preview: false
                })
            } catch (e) {
                console.error('Failed to open file', e)
                throw(e)
            }
        }
        ```
    11. Visualization: Markdown link with `file://` protocol -> `markdown-it` processing with custom link rules -> `openArgs` parses URI -> `language-julia.openFile` command execution -> `openFile` in `repl.ts` opens file via `vscode.window.showTextDocument(vscode.Uri.file(file))` without path traversal sanitization.

- Security test case:
    1. Install the Julia VS Code extension.
    2. Create a new Markdown file (e.g., `malicious_doc.md`) or use an existing one.
    3. Add the following Markdown link to the document: `[Sensitive File Link](file:///etc/passwd)` (for Linux/macOS) or `[Sensitive File Link](file:///C:/Windows/System32/drivers/etc/hosts)` (for Windows).
    4. Open the Markdown preview for `malicious_doc.md` in VS Code.
    5. Activate the Julia documentation viewer pane by running the command "Julia: Show Documentation Pane".
    6. In the Markdown preview, click on the "Sensitive File Link".
    7. Observe if VS Code attempts to open the linked sensitive file in a new editor window. If VS Code opens an editor window and displays the content of `/etc/passwd` or `C:\Windows\System32\drivers\etc\hosts`, or if you see error messages indicating an attempt to access these files, it confirms the path traversal vulnerability. Note that VS Code might prevent direct display of `/etc/passwd` content due to OS-level permissions, but any indication of the extension attempting to access the file path is a vulnerability. A more reliable test would be to link to a file within the workspace and check if it opens as expected, confirming the `file://` link handling.