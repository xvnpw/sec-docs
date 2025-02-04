# Attack Surface Analysis for sortablejs/sortable

## Attack Surface: [Cross-Site Scripting (XSS) via Configuration Options](./attack_surfaces/cross-site_scripting__xss__via_configuration_options.md)

*   **Description:** Attackers inject malicious JavaScript code through SortableJS configuration options, leading to script execution in the user's browser.
*   **How Sortable Contributes:** SortableJS allows dynamic configuration through JavaScript objects. If application code uses unsanitized user input to set these configuration options, particularly those related to HTML attributes or class names, it creates a direct pathway for XSS injection.
*   **Example:** Application code takes a URL parameter `sortableClass` and directly sets it as the `ghostClass` option in SortableJS: `Sortable.create(el, { ghostClass: urlParams.get('sortableClass') });`. An attacker could craft a URL with `?sortableClass="<img src=x onerror=alert('XSS')>". When SortableJS applies the ghost class, the injected JavaScript executes.
*   **Impact:** Full compromise of the user's browser session, including stealing cookies, session tokens, performing actions on behalf of the user, defacing the website, and potentially further attacks against the user's system.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Sanitization:** Never directly use unsanitized user input to set SortableJS configuration options.
    *   **Input Validation:** Validate user inputs against a strict whitelist of allowed values or patterns before using them in configuration.
    *   **Output Encoding (Context-Specific):** If dynamic configuration is absolutely necessary, carefully encode user inputs based on the context where they are used. For class names, treat them as literal strings, not HTML or JavaScript.
    *   **Content Security Policy (CSP):** Implement a strong CSP to restrict inline script execution and control script sources, mitigating the impact of XSS.

## Attack Surface: [Cross-Site Scripting (XSS) via Event Handlers](./attack_surfaces/cross-site_scripting__xss__via_event_handlers.md)

*   **Description:** Attackers inject malicious JavaScript code by exploiting vulnerabilities in application code that handles data from SortableJS event callbacks.
*   **How Sortable Contributes:** SortableJS triggers events (e.g., `onAdd`, `onUpdate`, `onSort`) and provides data related to drag and drop operations within these events. If application event handlers directly use this data to manipulate the DOM without proper sanitization, it creates a critical XSS vulnerability.
*   **Example:** An application uses the `onAdd` event to display a notification with the name of the added item. The event handler directly uses `item.textContent` from the `onAdd` event to set the `innerHTML` of a notification element. If an attacker can control the content of a draggable item (e.g., by injecting data into the application's data source), they can insert malicious HTML/JavaScript into the item's text. When the `onAdd` event fires and the application displays this unsanitized content using `innerHTML`, the injected script executes.
*   **Impact:** Full compromise of the user's browser session, similar to XSS via configuration options.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Output Sanitization:** **Always sanitize and encode data received from SortableJS event callbacks before using it to manipulate the DOM.** This is paramount.
    *   **Use Safe DOM Manipulation Methods:**  Prefer `textContent` to set text content, which automatically encodes HTML entities. Avoid `innerHTML` with unsanitized data. If `innerHTML` is unavoidable, use a robust and actively maintained HTML sanitization library.
    *   **Input Validation (Data Source):** Sanitize and validate data at the source where draggable items are created or loaded to prevent malicious content from entering the application's data.
    *   **Content Security Policy (CSP):** CSP remains a crucial defense-in-depth measure against XSS.

