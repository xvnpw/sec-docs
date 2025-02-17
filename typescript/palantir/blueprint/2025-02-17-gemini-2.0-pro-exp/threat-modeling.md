# Threat Model Analysis for palantir/blueprint

## Threat: [Table Data Exfiltration via Column Manipulation](./threats/table_data_exfiltration_via_column_manipulation.md)

*   **Description:** An attacker manipulates the `column` definitions passed as props to a BlueprintJS `Table` component.  This is *not* a general XSS attack, but a specific attack vector where the attacker controls the *structure* of the table itself, not just the cell content.  They could add columns that expose sensitive data fields that should not be visible to the current user, even if the underlying data *is* present in the client-side data set (but intended for different views or user roles).
    *   **Impact:** Exposure of sensitive data (PII, financial information, internal data) to unauthorized users, leading to data breaches and privacy violations.  This is a *direct* consequence of Blueprint's `Table` component's reliance on client-provided column definitions.
    *   **Affected Component:** `Table`, `EditableCell`, and related table components.
    *   **Risk Severity:** High (Critical if handling highly sensitive data).
    *   **Mitigation Strategies:**
        *   **Server-Side Validation of Column Definitions (Crucial):** The backend *must* validate the column definitions received from the client against a whitelist of allowed columns for the *specific user and context*.  Never trust the client-provided column definitions.
        *   **Strict Type Checking (TypeScript):** Use TypeScript with strictly defined interfaces for the `column` props to catch potential type mismatches and unexpected values at compile time. This helps prevent accidental misuse, but is not a primary security measure.
        *   **Avoid Dynamic Column Generation from User Input:** Do *not* construct `Table` column definitions directly from user input or any untrusted source.  Column definitions should be predefined and controlled by the application logic.
        *   **Backend Data Filtering:** Ensure that the backend API only returns data that the user is authorized to see, *regardless* of the columns requested. This is a defense-in-depth measure.

## Threat: [EditableText and InputGroup Content Manipulation Leading to Stored XSS via Blueprint Component](./threats/editabletext_and_inputgroup_content_manipulation_leading_to_stored_xss_via_blueprint_component.md)

* **Description:** While general XSS is a concern, this focuses on the *specific* scenario where a Blueprint `EditableText` or `InputGroup` component is used to *store* malicious input that is later rendered *unsafely* within *another* Blueprint component (or elsewhere in the application). The vulnerability isn't in the input component itself, but in how the application handles the data *after* it's been entered via the Blueprint component. The attacker leverages a Blueprint component as the *entry point* for a stored XSS attack.
    * **Impact:** Stored Cross-site scripting (XSS) attacks, allowing the attacker to execute arbitrary JavaScript in the context of other users' browsers. This can lead to session hijacking, data theft, and defacement.
    * **Affected Component:** `EditableText`, `InputGroup`, `TextArea`, and other input components *when used as part of a workflow that stores and later displays the input unsafely*.
    * **Risk Severity:** High (Critical if the stored input is displayed to other users without proper sanitization).
    * **Mitigation Strategies:**
        *   **Server-Side Input Sanitization (Mandatory):** *Always* sanitize user input on the server-side *before* storing it in the database. This is the primary defense against stored XSS. Use a well-vetted HTML sanitization library (like DOMPurify, but on the server).
        *   **Context-Aware Output Encoding:** When displaying the stored data (whether in a Blueprint component or elsewhere), use appropriate output encoding for the specific context (e.g., HTML encoding, JavaScript encoding).
        *   **Content Security Policy (CSP):** Implement a strict CSP to limit the sources of executable JavaScript and mitigate the impact of XSS even if sanitization fails.
        *   **Avoid `dangerouslySetInnerHTML`:** Never use `dangerouslySetInnerHTML` with user-provided content, even after client-side sanitization. Client-side sanitization is *not* a reliable primary defense.

