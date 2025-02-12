# Attack Surface Analysis for nwjs/nw.js

## Attack Surface: [1. Unrestricted Node.js Access from Renderer](./attack_surfaces/1__unrestricted_node_js_access_from_renderer.md)

*   **Description:**  Direct access to Node.js APIs (e.g., `fs`, `child_process`, `os`) from the renderer process (the Chromium window) due to improper configuration or coding practices. This is the single biggest risk, and it's *entirely* due to NW.js's design.
*   **How NW.js Contributes:** NW.js's core feature is blending Node.js and Chromium.  The `node-integration` setting (especially in older versions) and lack of `contextIsolation` make this easy to achieve unintentionally. This is a *direct* consequence of using NW.js.
*   **Example:**  An attacker injects JavaScript via an XSS vulnerability: `<img src=x onerror="require('child_process').exec('rm -rf /')">`.  If `node-integration` is enabled, this executes on the user's system.
*   **Impact:**  Complete system compromise.  Arbitrary code execution with the privileges of the NW.js application user. Data theft, system destruction, malware installation.
*   **Risk Severity:**  **Critical**
*   **Mitigation Strategies:**
    *   **Disable `node-integration` in renderers:**  Set `node-integration: false` in the `package.json` for all renderer windows. This is the *primary* defense.
    *   **Use `contextIsolation`:**  Enable `contextIsolation: true` in your `package.json`. This creates a separate JavaScript context for preload scripts, preventing direct access to Node.js from the renderer's global scope.
    *   **`contextBridge`:**  Use `contextBridge` to expose *only* necessary, pre-validated functions to the renderer, rather than entire modules.  This creates a tightly controlled API.
    *   **Strict CSP:**  Implement a strong Content Security Policy (CSP) to limit script execution, even if XSS occurs.
    *   **Input Validation/Sanitization:**  Thoroughly validate and sanitize *all* user input, even if it doesn't seem to directly interact with Node.js.  Assume all input is malicious.

## Attack Surface: [2. Command Injection via `child_process`](./attack_surfaces/2__command_injection_via__child_process_.md)

*   **Description:**  Exploiting vulnerabilities in how the application uses the `child_process` module to execute external commands.  Attackers inject malicious commands through unsanitized user input. While `child_process` is a Node.js feature, NW.js makes it *directly* accessible to the application, increasing the likelihood of misuse.
*   **How NW.js Contributes:** NW.js provides direct access to `child_process` without any intermediary security layer, making it readily available for developers to use (and potentially misuse) within the application's context. This is a *direct* consequence of the Node.js integration.
*   **Example:**  An application takes a filename as input and uses `child_process.exec('some_tool ' + filename)` to process it.  An attacker provides a filename like `"; rm -rf /; echo "`, injecting a malicious command.
*   **Impact:**  Arbitrary command execution with the privileges of the spawned process (often the same as the NW.js application).  Similar to full system compromise, but potentially limited by the privileges of the child process.
*   **Risk Severity:**  **High** (can be Critical if the child process has high privileges)
*   **Mitigation Strategies:**
    *   **Prefer `spawn` with argument arrays:**  Use `child_process.spawn('some_tool', [filename])`.  This avoids shell interpretation and prevents command injection.
    *   **Avoid `child_process` when possible:**  Consider if the functionality can be achieved using safer Node.js APIs or built-in NW.js features.
    *   **Strict Input Validation (Whitelist):**  If you *must* use `exec` or `execFile`, rigorously validate and sanitize user input.  Use a whitelist of allowed characters/patterns whenever possible.  *Never* trust user-provided data directly in a command string.
    *   **Least Privilege:**  Run spawned processes with the lowest necessary privileges.

## Attack Surface: [3. Untrusted Content in `webview` with Node.js Integration](./attack_surfaces/3__untrusted_content_in__webview__with_node_js_integration.md)

*   **Description:**  Loading untrusted web content within a `<webview>` tag *with* Node.js integration enabled.  This is essentially the same risk as `node-integration` in a renderer, but confined to the `webview`. This is *entirely* an NW.js-specific risk.
*   **How NW.js Contributes:** NW.js provides the `<webview>` tag, and the `nodeintegration` attribute *directly* controls Node.js access within it. This is a feature specific to NW.js.
*   **Example:**  An application displays user-submitted HTML within a `<webview>` that has `nodeintegration="true"`.  The attacker's HTML contains malicious JavaScript that uses Node.js to access the file system.
*   **Impact:**  Arbitrary code execution within the context of the NW.js application, with access to the user's system.
*   **Risk Severity:**  **Critical**
*   **Mitigation Strategies:**
    *   **Disable Node.js in `webview`:**  Set `nodeintegration="false"` for *all* `<webview>` tags. This is the most important mitigation.
    *   **Isolate `webview`:**  Use the `partition` attribute to isolate the `webview`'s storage and context from the main application.
    *   **Content Sanitization:**  If you *must* display user-submitted content, thoroughly sanitize it *before* rendering it in the `webview`, even with Node.js disabled. Use a robust HTML sanitizer.
    *   **CSP in `webview`:** Implement a strict CSP within the `webview` itself to further restrict script execution.

