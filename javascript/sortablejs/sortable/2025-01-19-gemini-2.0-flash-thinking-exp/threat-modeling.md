# Threat Model Analysis for sortablejs/sortable

## Threat: [Client-Side Order Manipulation](./threats/client-side_order_manipulation.md)

**Threat:** Client-Side Order Manipulation

**Description:** An attacker might use browser developer tools or custom JavaScript to directly modify the DOM, altering the order of sortable elements managed by SortableJS beyond the intended drag-and-drop interactions. This bypasses the intended user interaction provided by SortableJS.

**Impact:** Incorrect processing of data on the backend due to an unexpected order, unauthorized access to features or information based on element order, manipulation of displayed information leading to confusion or misinformation.

**Affected Component:** The entire SortableJS instance and the DOM elements it manages.

**Risk Severity:** High

**Mitigation Strategies:**
* **Server-Side Validation:** Always validate and sanitize the order data received on the backend.
* **Server-Side Order Verification:** Implement server-side logic to independently verify the integrity and validity of the order based on application rules.
* **Avoid Sole Reliance on Client-Side Order:** Do not solely depend on the client-provided order for critical business logic.

## Threat: [Callback Manipulation and Injection](./threats/callback_manipulation_and_injection.md)

**Threat:** Callback Manipulation and Injection

**Description:** If the application relies on data passed to SortableJS callback functions (e.g., `onAdd`, `onUpdate`) without proper sanitization or validation, an attacker might be able to inject malicious data or code through manipulated drag-and-drop actions facilitated by SortableJS or by directly triggering these callbacks.

**Impact:** Potential for client-side script injection (if callback data is directly rendered), incorrect data processing, or unexpected application behavior.

**Affected Component:** SortableJS callback functions (`onAdd`, `onUpdate`, etc.) and the application code that handles the data passed to these callbacks.

**Risk Severity:** High

**Mitigation Strategies:**
* **Input Sanitization:** Thoroughly sanitize and validate any data received through SortableJS callbacks before using it in application logic.
* **Avoid Direct Rendering of User-Controlled Data:** Avoid directly rendering user-controlled data from callbacks without proper escaping to prevent XSS.
* **Secure Callback Handling:** Ensure the logic within callback functions is secure and doesn't introduce vulnerabilities.

