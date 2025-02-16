# Attack Surface Analysis for emilk/egui

## Attack Surface: [Unvalidated Text Input (Through `egui` Widgets)](./attack_surfaces/unvalidated_text_input__through__egui__widgets_.md)

*   **Description:**  The application uses data entered into `egui` text fields without proper validation or sanitization before using it in security-sensitive operations.  This is the most common and direct way `egui` contributes to vulnerabilities.
*   **How `egui` Contributes:** `egui` provides the text input widgets (e.g., `ui.text_edit_singleline()`, `ui.text_edit_multiline()`) but performs *no* validation or sanitization. The application *must* handle this.
*   **Example:** An `egui` text field collects a filename, which is then used directly in an `std::fs::File::open()` call without checking for path traversal characters ("../").
*   **Impact:**  Leads to various attacks depending on the context:
    *   Cross-Site Scripting (XSS) - if displayed unsanitized in a web context.
    *   Server-Side Request Forgery (SSRF) - if used to construct URLs.
    *   Command Injection - if used in system commands.
    *   Path Traversal - if used to construct file paths.
*   **Risk Severity:** High to Critical (depending on the specific use of the input).
*   **Mitigation Strategies:**
    *   **Developer:** Implement strict input validation *immediately after* receiving input from the `egui` widget. Use allow-lists (whitelists) whenever possible. Validate format, length, and allowed characters. Sanitize to remove or escape dangerous characters. Use a dedicated input validation library. Contextual escaping is crucial (e.g., HTML escaping for web display).  *Never* trust input from `egui` widgets directly.
    *   **User:**  No direct user mitigation; this is entirely a developer responsibility.

## Attack Surface: [Unvalidated Drag-and-Drop Data (Handled via `egui`)](./attack_surfaces/unvalidated_drag-and-drop_data__handled_via__egui__.md)

*   **Description:** The application processes data received via `egui`'s drag-and-drop functionality without *any* validation. This is a direct attack vector facilitated by `egui`.
    *   **How `egui` Contributes:** `egui` provides the drag-and-drop mechanism; the application receives the dropped data through `egui`'s API.
    *   **Example:** An `egui` application allows users to drag and drop files, and it immediately executes the dropped file without checking if it's an executable or verifying its contents.
    *   **Impact:**
        *   Execution of arbitrary code (if the dropped data is a malicious executable or script).
        *   Processing of malicious files (e.g., malware, crafted documents to exploit parser vulnerabilities).
        *   Denial of Service (DoS).
    *   **Risk Severity:** High to Critical.
    *   **Mitigation Strategies:**
        *   **Developer:** Treat *all* data received via `egui`'s drag-and-drop as *completely untrusted*. Validate file type, size, and content *before* any processing. Use appropriate security measures based on the expected data type (e.g., virus scanning, sandboxing, robust parsing libraries).  *Never* directly execute or trust dropped data.
        *   **User:** Be extremely cautious about dragging and dropping files from untrusted sources into any application.

