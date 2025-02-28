# Critical Vulnerabilities in HTML-CSS-Class-Completion Extension

## 1. Remote CSS Loading SSRF/RCE Vulnerability

### Vulnerability Name
Remote CSS Loading Vulnerability (SSRF leading to potential RCE)

### Description
The HTML-CSS-Class-Completion extension automatically fetches and parses external CSS files referenced in HTML link elements when processing a repository. When a victim opens a malicious repository, the extension will parse HTML files and automatically make HTTP requests to any URLs specified in `<link rel="stylesheet">` tags. 

Steps to trigger the vulnerability:
1. Attacker creates a repository with HTML files containing manipulated link elements
2. The link elements reference malicious or controlled URLs: `<link rel="stylesheet" href="http://attacker-controlled-server.com/exploit.css">`
3. Victim opens the repository in VSCode with the extension installed
4. The extension automatically parses HTML files looking for CSS classes
5. When processing link elements, it extracts URLs and makes HTTP requests to them
6. The content returned is parsed as CSS without proper validation

### Impact
This vulnerability allows an attacker to:
- Force the victim's VSCode instance to make arbitrary HTTP requests to any host (SSRF)
- Potentially exploit vulnerabilities in the CSS parser through specially crafted responses
- Access internal network resources through redirects
- Exfiltrate data via DNS requests or HTTP callbacks
- If the CSS parser has known vulnerabilities, potentially achieve remote code execution

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The code has a very basic validation check that only permits URLs starting with "http":
```typescript
if (tag === "link" && name === "href" && value.indexOf("http") === 0) {
    linkHref = value;
}
```

### Missing Mitigations
- Proper URL validation using a URL parser
- Restriction on allowed domains or URL patterns
- Disabling of redirects in HTTP requests
- User confirmation before making external requests
- Content validation before parsing the returned CSS
- Rate limiting of requests
- Option to disable external CSS loading completely

### Preconditions
- Victim must have the HTML-CSS-Class-Completion extension installed
- Victim must open a repository containing malicious HTML files
- Extension must be enabled and active

### Source Code Analysis
The vulnerability exists in the `HtmlParseEngine` class in `/code/src/parse-engines/types/html-parse-engine.ts`:

1. The HTML parser collects URLs from stylesheet link elements:
```typescript
const parser = new html.Parser({
    onattribute: (name: string, value: string) => {
        if (name === "rel" && value === "stylesheet") {
            isRelStylesheet = true;
        }
        if (tag === "link" && name === "href" && value.indexOf("http") === 0) {
            linkHref = value;
        }
    },
    onclosetag: () => {
        if (tag === "link" && isRelStylesheet && linkHref) {
            urls.push(linkHref);
        }
        isRelStylesheet = false;
        linkHref = null;
    },
    // ...
});
```

2. The validation is insufficient. It only checks that the URL starts with "http", which could be bypassed in multiple ways.

3. The collected URLs are then used to make HTTP requests without any additional validation:
```typescript
await Bluebird.map(urls, async (url) => {
    const content = await request.get(url);
    definitions.push(...CssClassExtractor.extract(css.parse(content)));
}, { concurrency: 10 });
```

4. The `request.get(url)` call uses the request-promise library which follows redirects by default, allowing an attacker to redirect to internal resources.

5. The response content is directly passed to `css.parse()` without validation, potentially exposing the parser to malicious input.

### Security Test Case
To verify this vulnerability:

1. Set up a malicious web server that logs incoming requests and returns a specially crafted CSS file
2. Create an HTML file with the following content:
```html
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="http://your-malicious-server.com/exploit.css">
</head>
<body>
    <div class="test"></div>
</body>
</html>
```
3. Create a repository containing this HTML file
4. Have the victim clone and open this repository in VSCode with the HTML-CSS-Class-Completion extension installed
5. Observe that your malicious server receives a request from the victim's machine without any user interaction or permission
6. The request will include information about the user's environment in the User-Agent header

This test confirms that the extension is making unauthorized HTTP requests to arbitrary domains based solely on the content of HTML files in a repository.

## 2. Insecure CSS Parser Input Handling Vulnerability

### Vulnerability Name
Insecure CSS Parser Input Handling Vulnerability (potential for Code Injection)

### Description
The extension uses the "css" npm package to parse CSS content without properly validating or sanitizing the input. When parsing CSS files from a malicious repository or from external URLs, specially crafted CSS content could potentially exploit vulnerabilities in the CSS parser library.

Steps to trigger the vulnerability:
1. Attacker creates a repository with malicious CSS files or references external malicious CSS files
2. Victim opens the repository in VSCode
3. The extension parses these CSS files using the "css" npm package
4. If the CSS parser has vulnerabilities, the malicious content could trigger them

### Impact
If there are known vulnerabilities in the CSS parser library, this could lead to:
- Code execution within the VSCode extension context
- Access to files within the victim's workspace
- Potential escalation to access the user's filesystem

### Vulnerability Rank
High

### Currently Implemented Mitigations
There are no validations or sanitizations performed on CSS content before passing it to the parser.

### Missing Mitigations
- Input validation for CSS content
- Content length limitations
- Error handling to catch and recover from parser failures
- Sandboxing the parsing operation

### Preconditions
- Victim must have the HTML-CSS-Class-Completion extension installed
- Victim must open a repository containing malicious CSS files
- The CSS parser library must have exploitable vulnerabilities

### Source Code Analysis
The issue exists in multiple locations where CSS content is parsed without validation:

1. In `CssParseEngine` (/code/src/parse-engines/types/css-parse-engine.ts):
```typescript
public async parse(textDocument: ISimpleTextDocument): Promise<CssClassDefinition[]> {
    const code: string = textDocument.getText();
    const codeAst: css.Stylesheet = css.parse(code); // No validation before parsing
    return CssClassExtractor.extract(codeAst);
}
```

2. In `HtmlParseEngine` (/code/src/parse-engines/types/html-parse-engine.ts):
```typescript
ontext: (text: string) => {
    if (tag === "style") {
        definitions.push(...CssClassExtractor.extract(css.parse(text))); // No validation
    }
},
```

3. Also in `HtmlParseEngine` when processing external CSS:
```typescript
await Bluebird.map(urls, async (url) => {
    const content = await request.get(url);
    definitions.push(...CssClassExtractor.extract(css.parse(content))); // No validation
}, { concurrency: 10 });
```

In all cases, the CSS content is directly passed to `css.parse()` without any validation or sanitization.

### Security Test Case
To verify this vulnerability:

1. Identify a known vulnerability in the specific version of the "css" npm package used by the extension
2. Create a CSS file that exploits this vulnerability
3. Create a repository containing this CSS file
4. Have the victim open this repository in VSCode with the extension installed
5. Observe if the vulnerable parser triggers the exploit when processing the malicious CSS

Alternative test via external CSS:
1. Host a malicious CSS file on a web server
2. Create an HTML file that references this CSS:
```html
<link rel="stylesheet" href="http://your-server.com/malicious.css">
```
3. Have the victim open a repository containing this HTML file
4. Observe if the extension fetches and parses the malicious CSS, triggering the exploit

Note: The specific CSS payload would depend on identifying vulnerabilities in the exact version of the "css" npm package used by the extension.