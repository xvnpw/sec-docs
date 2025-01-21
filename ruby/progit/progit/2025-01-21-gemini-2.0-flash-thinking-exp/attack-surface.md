# Attack Surface Analysis for progit/progit

## Attack Surface: [Path Traversal when Serving Content](./attack_surfaces/path_traversal_when_serving_content.md)

**Description:** The application allows users to request specific files from the `progit/progit` repository based on user-provided input without proper sanitization.

**How progit contributes:** The repository's file structure becomes directly accessible to the application, and if the application doesn't validate user input, attackers can manipulate paths to access files outside the intended book content directory.

**Example:** An attacker crafts a URL like `example.com/book?file=../../../../etc/passwd` attempting to access the server's password file if the application directly uses the `file` parameter to serve content from the repository.

**Impact:** Exposure of sensitive server files, application configuration, or other resources residing on the same filesystem as the repository.

**Risk Severity:** High

**Mitigation Strategies:**
* **Input Sanitization:**  Strictly validate and sanitize user-provided file paths. Use allow-lists of permitted files or directories instead of blacklists.
* **Chroot/Jail:** If possible, restrict the application's access to only the necessary parts of the `progit/progit` repository.
* **Indirect File Access:** Instead of directly using user input to construct file paths, map user requests to predefined content identifiers.

## Attack Surface: [Markdown/Asciidoc Injection Leading to XSS](./attack_surfaces/markdownasciidoc_injection_leading_to_xss.md)

**Description:** The application processes Markdown or Asciidoc content from the `progit/progit` repository without proper sanitization, allowing attackers to inject malicious scripts that execute in users' browsers.

**How progit contributes:** The book content is primarily in Markdown and potentially Asciidoc. If the application renders this content directly without escaping or sanitizing, it becomes vulnerable to injection.

**Example:** A malicious actor submits a pull request to the `progit/progit` repository containing Markdown like `<script>alert("XSS")</script>`. If the application renders this chapter without sanitization, the script will execute in the user's browser.

**Impact:** Cross-site scripting attacks, potentially leading to session hijacking, cookie theft, redirection to malicious sites, or other client-side exploits.

**Risk Severity:** High

**Mitigation Strategies:**
* **Secure Parsing Libraries:** Use well-vetted and actively maintained Markdown/Asciidoc parsing libraries that automatically sanitize or escape potentially dangerous HTML.
* **Content Security Policy (CSP):** Implement a strong CSP to restrict the sources from which the browser can load resources, mitigating the impact of successful XSS.
* **Output Encoding:** Ensure that the output of the parsing process is properly encoded before being displayed in the browser.

