# Threat Model Analysis for swaywm/sway

## Threat: [Input Sniffing (Keylogging)](./threats/input_sniffing__keylogging_.md)

*   **Threat:** Input Sniffing (Keylogging)

    *   **Description:** A malicious application or compromised Sway client exploits a vulnerability in Sway's input handling to register itself as a global input listener, capturing all keyboard input (including passwords, sensitive data) without the user's knowledge. This bypasses intended access controls.
    *   **Impact:** Complete compromise of user input confidentiality. Sensitive data (passwords, financial information, private communications) are exposed to the attacker.
    *   **Affected Sway Component:** `input` module, specifically functions related to input device registration, event handling, and focus management (e.g., `handle_keyboard_key`, `input_manager_handle_new_input`). Wayland protocols related to input (e.g., `wl_keyboard`, `wl_pointer`).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   Enforce strict access controls on input device registration.  Only allow trusted applications (or ideally, *no* applications) to register for global input events.  This is a fundamental design consideration.
            *   Implement robust input validation to prevent malicious applications from injecting or modifying input events.  Sanitize all input data.
            *   Regularly audit and fuzz test the `input` module for vulnerabilities, particularly focusing on edge cases and potential race conditions.
            *   Consider using a sandboxing mechanism to isolate input handling for different applications, even at the Wayland protocol level.
            *   Implement a "secure input" mode for sensitive fields (like password entry), where input is routed directly to the application and bypasses any potential listeners, enforced by the compositor.
        *   **User:**
            *   Only install and run trusted applications.  This is paramount.
            *   Keep Sway and all related components (especially libraries like `wlroots`) up-to-date with the latest security patches.
            *   Be *extremely* cautious about granting *any* application access to input devices if it's not absolutely necessary.  Review Sway configuration carefully.
            *   Use a strong, unique password for your user account, and consider using a password manager.

## Threat: [Input Injection](./threats/input_injection.md)

*   **Threat:** Input Injection

    *   **Description:** A malicious application exploits a vulnerability in Sway to inject synthetic input events (keystrokes, mouse clicks) to control other applications or Sway itself. This bypasses intended security mechanisms and user consent.
    *   **Impact:** Loss of control over the system. The attacker can potentially execute arbitrary commands, access sensitive data, or install malware by controlling other applications.
    *   **Affected Sway Component:** `input` module, functions related to event generation and dispatching (e.g., functions that create or handle synthetic input events). Wayland protocols related to input.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   Implement *very* strict validation of the source of *all* input events, including those that appear to be synthetic.  Prevent applications from injecting events into other applications' input streams *without explicit and verifiable user consent*.
            *   Provide a secure API for synthetic input (if absolutely necessary) that requires strong authentication and authorization, and is heavily rate-limited.  This API should be designed with extreme caution.
            *   Audit and fuzz test the input handling code for vulnerabilities related to event injection.
        *   **User:**
            *   Only install and run trusted applications.
            *   Be cautious about granting applications access to input devices or any permissions that might allow them to generate input events.

## Threat: [Clipboard Manipulation (Reading)](./threats/clipboard_manipulation__reading_.md)

*   **Threat:** Clipboard Manipulation (Reading)

    *   **Description:** A malicious application exploits a vulnerability in Sway's clipboard handling to read the contents of the system clipboard without the user's knowledge or consent, potentially stealing sensitive data.
    *   **Impact:** Confidentiality breach. Sensitive data copied to the clipboard is exposed to the attacker.
    *   **Affected Sway Component:** `seat` module (which manages input and clipboard), functions related to clipboard management (e.g., functions that handle `wl_data_device` requests). Wayland protocols related to data transfer (`wl_data_device`, `wl_data_offer`, `wl_data_source`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   Implement a secure clipboard mechanism that *strictly* restricts access based on application permissions and *explicit* user consent (e.g., a prompt for each access).
            *   Provide a clear visual indicator (e.g., a notification) whenever an application accesses the clipboard.
            *   Consider implementing a "clipboard history" feature with strong security controls and auditing.
            *   Use separate clipboards for different security contexts (e.g., a "primary selection" and a "clipboard"), with different access policies.
            *   Enforce sandboxing to prevent unauthorized clipboard access between applications.
        *   **User:**
            *   Be mindful of what you copy to the clipboard, especially sensitive information.
            *   Use a clipboard manager that provides security features (e.g., automatic clearing after a timeout, password protection for sensitive entries).
            *   Avoid copying sensitive data to the clipboard whenever possible.

## Threat: [Clipboard Manipulation (Writing)](./threats/clipboard_manipulation__writing_.md)

*   **Threat:** Clipboard Manipulation (Writing)

    *   **Description:** A malicious application exploits a vulnerability in Sway's clipboard handling to modify the contents of the system clipboard, potentially injecting malicious content (e.g., a malicious URL, a command to be executed).
    *   **Impact:** Integrity violation. The user may unknowingly paste malicious content, leading to code execution, phishing attacks, or other security compromises.
    *   **Affected Sway Component:** `seat` module, functions related to clipboard management. Wayland protocols related to data transfer.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   Implement *strict* access controls on clipboard writing, requiring explicit user consent or strong application sandboxing.
            *   Validate the contents of the clipboard *before* allowing applications to paste them, potentially using a whitelist of allowed data types.
            *   Consider implementing a "paste confirmation" dialog for certain types of content (e.g., URLs, executable code), especially if the source is untrusted.
        *   **User:**
            *   Be cautious about pasting content from untrusted sources.  Visually inspect pasted content before using it.
            *   Use a clipboard manager that provides security features, such as content sanitization or warnings about potentially malicious content.

## Threat: [Screen Scraping/Recording](./threats/screen_scrapingrecording.md)

*   **Threat:** Screen Scraping/Recording

    *   **Description:** A malicious application exploits a vulnerability in Sway to capture screenshots or record the entire screen without the user's knowledge or consent, potentially revealing sensitive information.
    *   **Impact:** Confidentiality breach. Sensitive information displayed on the screen is exposed to the attacker.
    *   **Affected Sway Component:** `output` module, functions related to rendering and buffer management. Wayland protocols related to screen capture (e.g., `wlr-screencopy-unstable-v1`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   Implement *very* strict access controls on screen capture APIs.  Require *explicit* user permission (e.g., a clear and unambiguous prompt) or strong application sandboxing.  Do *not* allow silent screen capture by default.
            *   Provide a persistent and prominent visual indicator whenever screen capture is active, regardless of which application initiated it.
            *   Consider implementing a "secure output" mode where certain windows (e.g., those containing sensitive data) are explicitly excluded from screen capture, enforced by the compositor.
        *   **User:**
            *   Only install and run trusted applications.
            *   Be *extremely* cautious about granting *any* application access to screen capture capabilities.  Review Sway configuration carefully.

## Threat: [Output Modification (Overlay Attack)](./threats/output_modification__overlay_attack_.md)

*   **Threat:** Output Modification (Overlay Attack)

    *   **Description:** A malicious application exploits a vulnerability in Sway's window management to create an overlay window that covers parts of another application's window, tricking the user into interacting with the malicious application instead.
    *   **Impact:** Deception and potential compromise of user input. The user may unknowingly interact with a malicious application, leading to data theft or other security breaches.
    *   **Affected Sway Component:** `output` module, `view` module, functions related to window management, layering, and input routing. Wayland protocols related to window management (e.g., `xdg-shell`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   Implement robust mechanisms to detect and prevent overlay attacks. This is a complex area, but could include:
                *   Strict restrictions on the placement, size, and transparency of windows, especially those that are not fully opaque.
                *   Providing clear and unambiguous visual cues to indicate overlapping windows, making it obvious to the user which window is on top.
                *   Allowing the user to easily inspect the window hierarchy and identify potentially malicious overlays.
                *   Implementing "clickjacking" protection mechanisms, similar to those used in web browsers.
            *   Enforce strict rules on window layering and input routing, ensuring that input events are always delivered to the topmost, visible window.
        *   **User:**
            *   Be aware of the possibility of overlay attacks.
            *   Carefully inspect windows before interacting with them, especially if they appear unexpectedly or behave strangely.  Look for visual inconsistencies or unexpected behavior.

## Threat: [Sway IPC Socket Hijacking](./threats/sway_ipc_socket_hijacking.md)

*   **Threat:** Sway IPC Socket Hijacking

    *   **Description:** A malicious process connects to Sway's IPC socket and issues unauthorized commands, exploiting a vulnerability in Sway's IPC authentication or authorization, potentially taking control of the compositor.
    *   **Impact:** Complete compromise of Sway's control. The attacker can potentially execute arbitrary commands within the context of Sway, access sensitive data, or disrupt the user's workflow.
    *   **Affected Sway Component:** `ipc` module, functions related to socket creation, connection handling, message processing, and authentication/authorization.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   Use Unix domain sockets with *very* strict file permissions for IPC (e.g., owned by a dedicated `sway` user, with permissions set to `0600`).
            *   Implement *strong* authentication and authorization for *all* IPC connections.  This could involve using authentication tokens, cryptographic challenges, or other secure mechanisms.  Do *not* rely solely on file permissions.
            *   Use fine-grained access control lists (ACLs) to restrict which processes can connect to the socket and what commands they are allowed to execute.  The principle of least privilege should be strictly enforced.
            *   Thoroughly validate and sanitize *all* incoming IPC messages, treating them as untrusted input.  Use a well-defined message format and reject any malformed or unexpected messages.
            *   Regularly audit and fuzz test the `ipc` module for vulnerabilities.
        *   **User:**
            *   Ensure that only trusted users have access to the system.
            *   Regularly audit system processes and network connections to detect any unauthorized activity.

## Threat: [Unauthorized Configuration Modification](./threats/unauthorized_configuration_modification.md)

*   **Threat:** Unauthorized Configuration Modification

    *   **Description:** A malicious application or a local user with limited privileges modifies Sway's configuration files, exploiting a vulnerability or misconfiguration, potentially changing security settings, adding malicious startup commands.
    *   **Impact:** Compromise of Sway's security configuration. The attacker can potentially weaken security settings, gain persistence, or redirect user input/output, leading to further compromise.
    *   **Affected Sway Component:** Configuration loading and parsing functions (likely within the `server` or a dedicated configuration module). File system interactions.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   Protect Sway's configuration files with *very* strict file permissions (e.g., read-only for most users, writeable *only* by root or a dedicated `sway` user, and *never* world-writable).
            *   Consider using a configuration management system to track changes and detect unauthorized modifications.  Alert on any unexpected changes.
            *   Implement integrity checks (e.g., checksums, digital signatures) for configuration files to detect tampering.
            *   Provide a secure and auditable mechanism for updating Sway's configuration, preventing unauthorized modifications during updates.
        *   **User:**
            *   Regularly review Sway's configuration files for any suspicious changes or additions.  Understand your configuration.
            *   Use a strong password for your user account and for the root account.
            *   Avoid running untrusted scripts or commands that could modify system configuration files.  Be cautious about granting root privileges.

