# Threat Model Analysis for sortablejs/sortable

## Threat: [Element Injection (Facilitated by `onAdd`)](./threats/element_injection__facilitated_by__onadd__.md)

*   **Description:** While the core vulnerability is server-side, SortableJS's `onAdd` event provides a direct mechanism for an attacker to *attempt* to inject a new, unauthorized element into the sortable list.  If the application doesn't properly handle the `onAdd` event and blindly trusts the client-side data, the attacker can introduce malicious content. The attacker would manipulate the DOM *before* triggering the `onAdd` event, causing SortableJS to include the injected element.
*   **Impact:** XSS attacks (if the injected element contains malicious scripts), data corruption, denial of service (if the injected element disrupts application logic), unauthorized data insertion.
*   **Sortable Component Affected:** `onAdd` event handler. This is a *direct* involvement because the `onAdd` event is specifically designed to handle the addition of elements, and improper handling of this event is the core of the vulnerability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Server-Side Validation:** The server *must* verify that the user is authorized to add new elements and that the added element's data is valid. Do *not* blindly accept new elements based on client-side data, especially data originating from the `onAdd` event.
    *   **Separate Add/Remove Functionality:** Implement separate, well-secured endpoints for adding and removing elements. Don't rely *solely* on SortableJS events for these actions.  This reduces the attack surface.
    *   **Strict Content Security Policy (CSP):** A strong CSP can help mitigate XSS, even if injection occurs.

## Threat: [Element Data Tampering (via Event Manipulation)](./threats/element_data_tampering__via_event_manipulation_.md)

*   **Description:** An attacker leverages SortableJS's event handlers (like `onEnd`, `onUpdate`) to send modified element *content* to the server. While the server *should* validate this data, the attacker uses SortableJS's events as the *direct* vehicle for transmitting the tampered data. The attacker would modify the DOM element's content *before* the SortableJS event fires, or they might directly manipulate the event object's data (if possible, depending on how the application uses the event data).
*   **Impact:** Data corruption, injection of malicious content (e.g., XSS), unauthorized modification of application data.
*   **Sortable Component Affected:** Event handlers (`onEnd`, `onUpdate`, and any custom functions that extract data from these events). The vulnerability is in how the application uses these events, making it a direct involvement.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Server-Side Validation:** The server *must* rigorously validate the content of *every* element received, not just the order. Use strict whitelisting.
    *   **Minimal Data Transfer:** Send only element IDs to the server. The server should retrieve element content from its authoritative source. This significantly reduces the attack surface related to content tampering.
    *   **Input Sanitization (Server-Side):** Sanitize even the element IDs.

## Threat: [Unauthorized Reordering (Exploiting Event Data)](./threats/unauthorized_reordering__exploiting_event_data_.md)

*   **Description:** An attacker manipulates the data provided by SortableJS's event handlers (e.g., `onEnd`, `onUpdate`) to reorder elements they shouldn't have access to. This relies on the server trusting the client-provided order without proper authorization checks. The attacker directly uses the output of SortableJS (the reordered list) as the attack vector.
*   **Impact:** Unauthorized modification of data, bypassing access controls, potential for data corruption.
*   **Sortable Component Affected:** Event handlers that provide order information (`onEnd`, `onUpdate`, etc.). The core issue is server-side authorization, but SortableJS's events are the *direct* means of conveying the unauthorized reordering request.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Server-Side Authorization:** The server *must* independently verify that the user has permission to modify *all* affected elements. Do *not* trust the client-provided order without verification.
    *   **Opaque Identifiers:** Use server-generated, non-predictable identifiers.

## Threat: [Element Deletion (via Event Manipulation)](./threats/element_deletion__via_event_manipulation_.md)

*   **Description:** An attacker manipulates the data from SortableJS event handlers (specifically, the list of element IDs returned by `toArray()` or similar methods) to *remove* an element's ID before it's sent to the server. This makes SortableJS the *direct* tool used to initiate the unauthorized deletion. The attacker would modify the array of IDs *after* the drag-and-drop operation but *before* the data is sent to the server.
*   **Impact:** Data loss, disruption of application functionality, unauthorized removal of content.
*   **Sortable Component Affected:** `onEnd`, `onUpdate`, `onRemove` event handlers, and any custom functions that process the data (especially `toArray()` or similar). 
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Server-Side Validation:** The server *must* verify that the user is authorized to delete any missing elements. Compare the received list of IDs with the known, authorized list.
    *   **Separate Add/Remove Functionality:** Use dedicated, secure endpoints for deletion, separate from SortableJS's reordering functionality.

