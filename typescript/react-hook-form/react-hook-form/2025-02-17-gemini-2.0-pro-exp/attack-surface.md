# Attack Surface Analysis for react-hook-form/react-hook-form

## Attack Surface: [Hidden Field Manipulation](./attack_surfaces/hidden_field_manipulation.md)

Attackers modify the values of hidden fields managed by `react-hook-form` before form submission.

**How `react-hook-form` Contributes:** `react-hook-form` manages the state of all registered fields, including hidden ones.  This provides a direct mechanism for the library to handle (and thus, for an attacker to potentially target) hidden field data.

**Example:** A hidden field contains a user ID. An attacker changes this ID to that of another user, potentially gaining unauthorized access or performing actions on behalf of the other user.

**Impact:** Unauthorized access, data manipulation, privilege escalation, or other security breaches depending on the purpose of the hidden field.

**Risk Severity:** High (if hidden fields contain sensitive data or control authorization).

**Mitigation Strategies:**

*   **Developer:** Avoid storing sensitive data in hidden fields if possible. If unavoidable, treat hidden field values with the *same* level of scrutiny as any other user input on the server-side.  Consider using server-side session data or digitally signed tokens instead of relying on hidden fields for security-critical information.  Validate and sanitize hidden field data on the server as rigorously as any other input.
*   **User:** (No direct mitigation).

## Attack Surface: [Client-Side Validation Bypass](./attack_surfaces/client-side_validation_bypass.md)

Attackers manipulate form data on the client to bypass validation rules defined *within* `react-hook-form`.

**How `react-hook-form` Contributes:** `react-hook-form` provides the client-side validation API (e.g., `register` with validation options, `setError`, etc.).  While this improves UX, it's inherently bypassable on the client. The library *provides* the tools for client-side validation, making this attack surface possible.

**Example:** An attacker uses browser developer tools to remove the `required` attribute from a field registered with `react-hook-form`, or they modify the `pattern` validation rule to allow invalid input.

**Impact:** Submission of invalid or malicious data to the server.  This can lead to data corruption, application errors, or security vulnerabilities if the server doesn't perform adequate validation.

**Risk Severity:** High (if server-side validation is weak or absent).

**Mitigation Strategies:**

*   **Developer:** *Always* implement robust server-side validation that mirrors and *exceeds* the client-side validation.  Never rely solely on client-side validation for security. Sanitize all input on the server.
*   **User:** (Limited direct mitigation) Use a browser with up-to-date security features and avoid untrusted extensions.

