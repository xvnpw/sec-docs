# Attack Surface Analysis for sortablejs/sortable

## Attack Surface: [Cross-Site Scripting (XSS) via Unsafe Handling of Dragged Content in Callbacks](./attack_surfaces/cross-site_scripting__xss__via_unsafe_handling_of_dragged_content_in_callbacks.md)

*   **Description:**  Malicious HTML or JavaScript within a draggable element can be executed if developer-provided callback functions (e.g., `onAdd`, `onUpdate`) directly insert the dragged element's content into the DOM without proper sanitization.
    *   **How Sortable Contributes to the Attack Surface:** SortableJS provides the mechanism for moving elements with potentially malicious content and exposes these elements in its callback functions.
    *   **Example:** An attacker injects an `<li>` element with an inline `<script>alert('XSS')</script>` tag. When this item is dragged and dropped, the `onAdd` callback might directly append the `innerHTML` of the dropped element to another part of the page, executing the script.
    *   **Impact:**  Execution of arbitrary JavaScript code in the victim's browser, potentially leading to session hijacking, cookie theft, redirection to malicious sites, or defacement.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Input Sanitization:**  In all SortableJS callback functions that handle dragged content, use robust HTML sanitization libraries (e.g., DOMPurify) to remove any potentially malicious scripts or attributes before inserting the content into the DOM.
        *   **Content Security Policy (CSP):** Implement a strong CSP to restrict the sources from which the browser can load resources, mitigating the impact of injected scripts.
        *   **Avoid Direct `innerHTML` Manipulation:**  Instead of directly using `innerHTML`, create new DOM elements and set their `textContent` property to display the dragged content, which automatically escapes HTML entities.

## Attack Surface: [Cross-Site Scripting (XSS) via Unsafe Handling of Data Attributes](./attack_surfaces/cross-site_scripting__xss__via_unsafe_handling_of_data_attributes.md)

*   **Description:** If developers use the `setData` option to attach data to draggable elements and later render this data without proper sanitization, it can lead to XSS.
    *   **How Sortable Contributes to the Attack Surface:** SortableJS provides the `setData` and access to element attributes, making it easy for developers to attach and later retrieve potentially malicious data.
    *   **Example:** An attacker manipulates the data associated with a draggable item (e.g., via a separate vulnerability or direct DOM manipulation) to include a malicious script in a `data-description` attribute. The application then retrieves and renders this `data-description` without sanitization.
    *   **Impact:** Execution of arbitrary JavaScript code in the victim's browser, similar to the previous XSS scenario.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Sanitize Data Attributes on Rendering:** Before displaying any data retrieved from draggable elements (including `data-` attributes), sanitize it using appropriate methods.
        *   **Principle of Least Privilege for Data:** Only store necessary data in draggable elements. Avoid storing sensitive or executable content.
        *   **Careful Use of `setData`:** Be mindful of the source and nature of the data being attached using `setData`.

