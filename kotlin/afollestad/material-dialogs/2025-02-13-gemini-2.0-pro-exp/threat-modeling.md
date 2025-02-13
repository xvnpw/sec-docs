# Threat Model Analysis for afollestad/material-dialogs

## Threat: [Cross-Site Scripting (XSS) via Unsanitized Input](./threats/cross-site_scripting__xss__via_unsanitized_input.md)

*   **Description:** An attacker injects malicious JavaScript code into user-supplied data that is then displayed *directly* within a Material Dialog's content. This happens because the application fails to sanitize or encode user input before passing it to the dialog's `title`, `content`, or `customView` parameters. The library itself does not perform any sanitization; it renders the provided content. The attacker's script executes in the context of other users' browsers.
    *   **Impact:**
        *   Theft of user cookies and session tokens.
        *   Redirection of users to malicious websites.
        *   Defacement of the application's UI (specifically, the dialog).
        *   Execution of arbitrary code within the user's browser.
        *   Keylogging and data theft.
    *   **Affected Component:**
        *   `title` parameter in various dialog creation functions (e.g., `MaterialDialog`, `show()`).
        *   `content` parameter in various dialog creation functions.
        *   `customView` parameter, *if* user input is directly used to construct the custom view's HTML without proper sanitization.
        *   Input fields within a `customView` (`input()`, etc.) if their values are directly used in other parts of the dialog or application without sanitization upon submission.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Validation:** Strictly validate all user input on the server-side *before* it's used anywhere, including within dialogs. Define allowed character sets and data types.
        *   **Output Encoding:** Use appropriate output encoding (HTML encoding, JavaScript string escaping) when displaying user-supplied data within the dialog. Use a library like `DOMPurify` to sanitize HTML content before inserting it into the `content` parameter. If using a framework like React, leverage JSX's built-in escaping.
        *   **Content Security Policy (CSP):** Implement a strong CSP to limit script sources, mitigating XSS impact even if injection occurs.
        *   **Avoid `customView` with Unsanitized Input:** Exercise extreme caution with `customView` and user input. Avoid direct construction of the custom view's HTML from user input. If unavoidable, use a robust sanitization library.

## Threat: [Unintentional Information Disclosure in Dialogs](./threats/unintentional_information_disclosure_in_dialogs.md)

*   **Description:** The application inadvertently displays sensitive information (API keys, session tokens, PII, internal error messages) within a dialog's `title`, `content`, or `customView`. This is a direct result of the application passing sensitive data to these parameters without realizing the security implications. The library displays whatever it's given.
    *   **Impact:**
        *   Exposure of sensitive data to unauthorized users.
        *   Potential for credential theft or account compromise.
        *   Privacy violations.
    *   **Affected Component:**
        *   `title` parameter.
        *   `content` parameter.
        *   `customView` (if it's designed to display data that could be sensitive).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Code Review:** Thoroughly review all code that creates dialogs, paying close attention to the data passed to `title`, `content`, and `customView`.
        *   **Data Sanitization (for Error Messages):** If displaying error messages, sanitize them to remove sensitive internal details. Display user-friendly messages, not raw technical errors.
        *   **Testing:** Implement automated tests to verify that dialogs do *not* display sensitive information under various conditions.  This is crucial.

