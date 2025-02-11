# Attack Surface Analysis for ultraq/thymeleaf-layout-dialect

## Attack Surface: [Unvalidated Layout File Paths](./attack_surfaces/unvalidated_layout_file_paths.md)

*   **Description:**  The core mechanism of including layout templates (e.g., `layout:decorate`, `layout:replace`) involves specifying file paths.  If these paths are constructed using unvalidated user input, it opens the door to file inclusion vulnerabilities.
*   **How Thymeleaf-Layout-Dialect Contributes:** The dialect's primary function is to manage layout files via these directives, making this a central point of vulnerability. The dialect *provides the mechanism* for including files; the vulnerability arises from *how that mechanism is used*.
*   **Example:**
    *   Application code: `model.addAttribute("layoutName", userInput);` and in the template: `<html layout:decorate="~{layouts/${layoutName}}">`
    *   Attacker provides `userInput`: `../../etc/passwd`
*   **Impact:**
    *   **Local File Inclusion (LFI):** Exposure of sensitive files (configuration, source code, etc.) on the server.
    *   **Remote File Inclusion (RFI) (Less Likely):**  Execution of malicious code from a remote server (highly dependent on Thymeleaf configuration).
    *   **Denial of Service (DoS):**  Resource exhaustion.
*   **Risk Severity:** **Critical** (LFI/RFI can lead to complete system compromise).
*   **Mitigation Strategies:**
    *   **Primary:** Implement a strict whitelist of allowed layout file names.  *Do not* construct layout paths dynamically from user input.
    *   **Secondary (If Whitelist is Impossible):**  If dynamic selection is *required*, implement *extremely rigorous* input validation and sanitization:
        *   **Path Traversal Prevention:** Use a library function (e.g., `java.nio.file.Paths.get()` and `normalize()`) to prevent path traversal.
        *   **Character Filtering:**  Allow only a very restricted set of characters.
        *   **Length Limits:**  Enforce strict length limits.
        *   **Template Resolver Configuration:** Restrict access to only intended layout directories.

## Attack Surface: [Custom Dialect Processor Vulnerabilities](./attack_surfaces/custom_dialect_processor_vulnerabilities.md)

*   **Description:**  Developers can create custom processors to extend the dialect's functionality.  These custom processors, if poorly implemented, can introduce a wide range of vulnerabilities.
*   **How Thymeleaf-Layout-Dialect Contributes:** The dialect *allows* the creation and execution of custom processors, providing the entry point for these vulnerabilities. This is a *direct* feature of the dialect.
*   **Example:**  A custom processor that attempts to read a file based on user input without proper validation.
*   **Impact:**
    *   **Arbitrary Code Execution:**  (Worst case) An attacker could execute arbitrary code on the server.
    *   **Information Disclosure:**  Leakage of sensitive data.
    *   **Denial of Service:**  Resource exhaustion.
*   **Risk Severity:** **Critical** to **High** (depending on the specific vulnerability).
*   **Mitigation Strategies:**
    *   **Thorough Code Review:**  Rigorously review the code of *all* custom processors.
    *   **Principle of Least Privilege:**  Ensure minimum necessary permissions.
    *   **Input Validation:**  Validate and sanitize *all* input used by custom processors.
    *   **Secure Coding Practices:**  Follow secure coding best practices.
    * **Avoid Complexity:** Keep custom processors as simple as possible.
    * **Unit and Integration Testing:** Thoroughly test custom processors.

## Attack Surface: [Content Fragment Manipulation (Indirect XSS - via `th:replace` or `th:insert` with unescaped content)](./attack_surfaces/content_fragment_manipulation__indirect_xss_-_via__threplace__or__thinsert__with_unescaped_content_.md)

*   **Description:** While Thymeleaf itself provides XSS protection, using `layout:replace` or `layout:insert` to insert a fragment that *itself* contains unescaped user input bypasses this protection. The vulnerability is in the *combination* of unescaped user input and the dialect's fragment insertion.
*   **How Thymeleaf-Layout-Dialect Contributes:** The dialect's `layout:replace` and `layout:insert` attributes are the *mechanism* by which the unescaped content (the actual vulnerability) is injected into the final rendered output.  Without these attributes, the unescaped content wouldn't be included in the layout.
*   **Example:**
    *   Application code (vulnerable): `model.addAttribute("userComment", userInput);`
    *   Fragment file (`comment.html`): `<div th:fragment="comment" th:utext="${userComment}"></div>`
    *   Main template: `<div layout:replace="~{::comment}"></div>`  (or using `layout:insert`)
    *   Attacker provides `userInput`: `<script>alert('XSS');</script>`
*   **Impact:**
    *   **Cross-Site Scripting (XSS):** Execution of malicious JavaScript in the user's browser.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Consistent Escaping:** *Always* use `th:text` (or other escaping attributes) within fragments when displaying user-supplied data. *Avoid* `th:utext` unless absolutely necessary and with extreme caution.  The escaping must happen *within the fragment itself*.  
        ```html
        <!-- Correct: -->
        <div th:fragment="comment" th:text="${userComment}"></div>
        ```
    *   **Input Validation:** Validate and sanitize user input *before* it's used to construct the fragment's content.
    *   **Content Security Policy (CSP):** Implement a strong CSP.
    * **Avoid Dynamic Fragment Content if Possible:** If a fragment's content doesn't need to be dynamic, make it static.

