- **Vulnerability Name:** Arbitrary File Read via Request Body File Inclusion  
  **Description:**  
  • The REST Client extension lets a user specify a file path as the request body (using the “<” or “<@” syntax). An attacker who prepares a malicious HTTP request file (or convinces a user to open one) may reference an absolute or relative file path that points to sensitive files outside the intended workspace.  
  • For example, a crafted request file might include a line such as:  
    `POST https://target.example/api/submit HTTP/1.1`  
    `Content-Type: text/plain`  
    `Authorization: token xxx`  
    *(blank line)*  
    `< /etc/passwd`  
  • When the extension processes the file, it reads the file from the host file system and injects its contents into the request (or displays it in preview).  
  **Impact:**  
  • An attacker could cause the extension to disclose sensitive local files (such as system files or confidential configuration data) to the user. This local file disclosure can lead to exposure of credentials or system details that further aid in compromise.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  • The documentation explains the file inclusion feature but does not describe any checks that restrict the file path to a safe or expected directory.  
  **Missing Mitigations:**  
  • No enforcement of sandboxing or file–path validation is indicated.  
  • Lacking an explicit check that limits file reading to the current workspace (or another approved directory) and user confirmation before accessing arbitrary files.  
  **Preconditions:**  
  • The user must open (or be tricked into opening) an HTTP file that contains a file inclusion directive referencing an arbitrary system file.  
  **Source Code Analysis:**  
  • In the module that processes HTTP request bodies, the parser looks for lines beginning with “<” (or “<@” when variable processing is needed).  
  • This input is directly used to resolve and read a file path without further validation.  
  • As a result, an attacker–supplied file path (whether absolute or via directory traversal) is read and its contents injected into the request body/preview.  
  **Security Test Case:**  
  • Create an HTTP file (e.g., malicious.http) with the following content:  
    ```
    POST https://example.com/api/test HTTP/1.1
    Content-Type: text/plain

    < /etc/passwd
    ```  
  • Open the file in Visual Studio Code with the REST Client extension installed.  
  • Trigger the request (or simply use any preview feature that causes the extension to resolve and read the file).  
  • Observe whether the contents of “/etc/passwd” (or another sensitive file, on Windows use an equivalent sensitive file) are read and displayed.  
  • If the file’s contents are visible in the output or preview, the vulnerability is confirmed.

- **Vulnerability Name:** Webview Cross-Site Scripting (XSS) via Malicious HTTP Response Content Injection  
  **Description:**  
  • The extension displays HTTP response headers and body within a dedicated webview panel in Visual Studio Code.  
  • If an HTTP server controlled by an attacker returns a response whose body contains malicious HTML or JavaScript—for example, a payload like  
    `<img src=x onerror=alert("XSS")>`  
    or  
    `<script>alert("XSS")</script>`—and if that content is passed into the webview without thorough sanitization, the malicious script may execute.  
  • The typical attack scenario follows these steps: an attacker hosts a server that sends such a malicious response, a user issues a request (or loads a preconfigured HTTP file) that points to this server, and the unsafe content is rendered in the webview panel.  
  **Impact:**  
  • Successful XSS in the webview can lead to arbitrary JavaScript execution in the context of Visual Studio Code.  
  • This could ultimately allow an attacker to steal sensitive data from open files, manipulate extension or editor behavior, or escalate the attack to gain access to the host environment.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  • The changelog (version 0.22.1) notes that a Content Security Policy (CSP) has been added for response and code snippet webviews. This measure is intended to limit inline scripts and restrict resource loading.  
  **Missing Mitigations:**  
  • It remains unclear whether the extension also performs proper output encoding and sanitization of the HTTP response content before rendering it in the webview.  
  • Relying solely on CSP may be insufficient if the response is injected into the HTML template without escaping dangerous characters. An explicit sanitization step is missing.  
  **Preconditions:**  
  • The user must send an HTTP request to (or load an HTTP file pointing to) an attacker–controlled server that returns a malicious payload.  
  • The response must be rendered in the webview where the unsanitized content could trigger script execution.  
  **Source Code Analysis:**  
  • The typical flow is:  
    1. The extension sends an HTTP request and receives the response.  
    2. A function assembles an HTML template that embeds the response headers and body for syntax highlighting and display.  
    3. If the response body is inserted verbatim into the HTML without robust sanitization/escaping, any embedded script tags or event attributes become active.  
  • Although a CSP has been added, if the policy does not block inline execution completely or if there is any CSP bypass possibility, the raw response content might allow injection.  
  **Security Test Case:**  
  • Set up a local HTTP server that, on receiving any request, returns the following response:  
    - **Headers:**  
      `Content-Type: text/html`  
    - **Body:**  
      `<html><body><img src="x" onerror="alert('XSS')"></body></html>`  
  • In a new HTTP file in VSCode, craft a request to point to this local server. For example:  
    ```
    GET http://localhost:8080/test HTTP/1.1
    ```  
  • Send the request using the REST Client extension.  
  • Observe the response rendered in the webview.  
  • If the injected payload (for example, an alert box) is executed in the webview, it confirms that the response content is not safely sanitized, and the vulnerability exists.