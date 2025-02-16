# Attack Surface Analysis for iced-rs/iced

## Attack Surface: [Untrusted Widget Input Propagation](./attack_surfaces/untrusted_widget_input_propagation.md)

*   **Description:**  Widgets receiving and propagating unvalidated/unsanitized user input through Iced's message-passing system.
*   **How Iced Contributes:** Iced's core message-passing architecture is the *direct mechanism* for this vulnerability.  The framework's design facilitates the flow of data, and if a widget mishandles input, Iced's system propagates the problem.
*   **Example:** A custom text input widget emits raw HTML.  Another Iced widget renders this HTML directly, leading to an XSS vulnerability *within the Iced application itself*. This is distinct from a general web XSS.
*   **Impact:**  Code execution (XSS), data corruption, application compromise.
*   **Risk Severity:** High to Critical (depending on how the propagated data is used).
*   **Mitigation Strategies:**
    *   **Developer:** Implement strict input validation and sanitization *within each Iced widget* before emitting *any* messages.  Use a centralized validation layer for complex Iced message flows. Employ type-safe Iced messages. This is a *direct responsibility* when using Iced.

## Attack Surface: [Custom Widget Vulnerabilities](./attack_surfaces/custom_widget_vulnerabilities.md)

*   **Description:**  Bugs or security flaws within custom-built Iced widgets.
*   **How Iced Contributes:** Iced *directly enables* the creation of custom widgets.  These are new code components *within the Iced framework*, expanding the attack surface *because of Iced's extensibility*.
*   **Example:** A custom Iced widget designed to display images doesn't validate image data, leading to a buffer overflow *within the Iced application's rendering process*.
*   **Impact:**  Code execution, denial of service, application crash, data corruption.
*   **Risk Severity:** High to Critical (depending on the Iced widget's functionality).
*   **Mitigation Strategies:**
    *   **Developer:** Thoroughly review and test *all custom Iced widgets*. Apply secure coding practices *specifically to the Iced widget's code*. Fuzz test custom Iced widgets. This is a *direct responsibility* when extending Iced.

## Attack Surface: [Denial-of-Service (DoS) via Message Flooding](./attack_surfaces/denial-of-service__dos__via_message_flooding.md)

*   **Description:**  Overwhelming the Iced application with a large volume of messages.
*   **How Iced Contributes:** Iced's event-driven architecture, *the core of how Iced functions*, is inherently susceptible to this if message handling isn't rate-limited *within the Iced application*.
*   **Example:**  Rapidly triggering an Iced button's `on_press` event, flooding the Iced application with messages.
*   **Impact:**  Application unavailability, denial of service.
*   **Risk Severity:** High (because it directly impacts Iced's core functionality).
*   **Mitigation Strategies:**
    *   **Developer:** Implement rate limiting on Iced event handlers and message processing *within the Iced application*. Use bounded queues for Iced messages. This is a *direct responsibility* when using Iced's event system.

## Attack Surface: [Rendering Vulnerabilities (Image/Font Handling)](./attack_surfaces/rendering_vulnerabilities__imagefont_handling_.md)

*   **Description:**  Exploiting vulnerabilities in external libraries used by Iced for image and font rendering.
*   **How Iced Contributes:** Iced *directly relies* on external crates (like `image` and `font-kit`) for these tasks, and the Iced application *chooses* to use and render the output. This is a direct consequence of using Iced's rendering capabilities.
*   **Example:**  A crafted image file exploits a vulnerability in the `image` crate, leading to code execution when the *Iced application* attempts to display it *using Iced's rendering features*.
*   **Impact:**  Code execution, application compromise.
*   **Risk Severity:** High to Critical (depending on the vulnerability in the underlying library, but Iced is the direct vector).
*   **Mitigation Strategies:**
    *   **Developer:** Keep all dependencies (especially image/font libraries used by Iced) up-to-date. Validate image and font data *before passing it to Iced's rendering functions*. Consider sandboxing the rendering process (if possible within the Iced context). This is a *direct responsibility* when using Iced's rendering.

