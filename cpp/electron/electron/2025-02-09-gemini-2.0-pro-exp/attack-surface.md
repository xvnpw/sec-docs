# Attack Surface Analysis for electron/electron

## Attack Surface: [1. Node.js Integration in Renderer (Untrusted Content)](./attack_surfaces/1__node_js_integration_in_renderer__untrusted_content_.md)

*   **Description:**  Allowing renderer processes that load *untrusted remote content* to access Node.js APIs. This is the single most dangerous misconfiguration in Electron.
*   **Electron Contribution:** Electron's core design allows enabling Node.js in renderers via the `nodeIntegration` setting. This is *unique* to Electron (and similar frameworks) and is not a standard web vulnerability.
*   **Example:**  An Electron-based RSS reader loads a malicious website within a `BrowserWindow` with `nodeIntegration: true`. The website's JavaScript can then use `require('child_process').exec('rm -rf /')` to execute arbitrary shell commands.
*   **Impact:**  Complete system compromise. Arbitrary code execution with the privileges of the user running the application. Full file system access, network access, process control, etc.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Disable `nodeIntegration`:**  Set `nodeIntegration: false` for *all* `BrowserWindow` and `WebView` instances that load *any* remote or untrusted content. This is non-negotiable.
    *   **Use `contextBridge` (Strictly):**  If Node.js access is *absolutely* required in the renderer, use `contextBridge` to expose *only* the most minimal, carefully vetted, and specifically designed functions. Never expose `require` or entire Node.js modules.
    *   **Sandboxing (Advanced):** For extremely high-risk scenarios (rarely needed), consider running untrusted content in a completely separate, sandboxed process, communicating with the main process via a highly restricted, validated IPC channel.

## Attack Surface: [2. Context Isolation Bypass](./attack_surfaces/2__context_isolation_bypass.md)

*   **Description:**  Circumventing the `contextIsolation` feature, which is designed to create a separate JavaScript context for preload scripts, preventing them from directly modifying the renderer's global scope.  While XSS is a general web vulnerability, the *impact* in Electron is significantly amplified due to potential Node.js access.
*   **Electron Contribution:** Electron provides `contextIsolation` as a specific security mechanism to mitigate the risks of combining Node.js and web content. Bypassing it is an Electron-specific attack.
*   **Example:**  Even with `nodeIntegration: false`, an XSS vulnerability in a *locally* loaded HTML file (part of the Electron app) allows an attacker to inject code into the preload script's context. If `contextIsolation` is disabled or bypassed, this injected code can then potentially access or manipulate the exposed `contextBridge` APIs, leading to Node.js access.
*   **Impact:**  Potential escalation of privileges, leading to access to Node.js APIs and potentially arbitrary code execution, even without direct `nodeIntegration`.
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **Enable `contextIsolation`:**  Always set `contextIsolation: true` for *all* `BrowserWindow` and `WebView` instances. This is a fundamental security requirement.
    *   **Secure Preload Scripts:**  Thoroughly audit preload scripts for *any* vulnerabilities, including XSS and code injection. Minimize the code in preload scripts to the absolute minimum required functionality.
    *   **Content Security Policy (CSP):**  Use a strict CSP in both the main process and renderer processes to limit the execution of inline scripts and other potential attack vectors that could lead to a `contextIsolation` bypass.

## Attack Surface: [3. Insecure `contextBridge` Implementation](./attack_surfaces/3__insecure__contextbridge__implementation.md)

*   **Description:**  Exposing dangerous or overly permissive Node.js functionality to the renderer process through `contextBridge`, even if `nodeIntegration` is disabled.
*   **Electron Contribution:** `contextBridge` is Electron's recommended mechanism for inter-process communication, but it's a double-edged sword.  Its misuse is a direct Electron-specific risk.
*   **Example:**  A `contextBridge` exposes a function named `writeFile(path, data)`. An attacker, through an XSS vulnerability in the renderer, can call this function with a malicious path (e.g., overwriting a critical system file) and arbitrary data.
*   **Impact:**  Arbitrary code execution or data corruption/modification, potentially with elevated privileges, depending on the exposed functionality.
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:**  Expose *only* the absolute minimum necessary functions and data via `contextBridge`. Never expose entire Node.js modules.
    *   **Strict Input Validation:**  Thoroughly validate *all* input received from the renderer process through the `contextBridge`. Sanitize, validate data types, lengths, and expected values.  Assume all input is malicious.
    *   **Avoid Dangerous APIs:**  Never expose APIs that allow direct, unrestricted file system access, shell command execution, or other potentially dangerous operations. If such access is unavoidable, implement extremely strict whitelisting and validation.
    *   **Code Review:** Regularly and rigorously review the API exposed through `contextBridge` to ensure it remains minimal, secure, and adheres to the principle of least privilege.

## Attack Surface: [4. Vulnerable Node.js Dependencies (Impacting Main Process)](./attack_surfaces/4__vulnerable_node_js_dependencies__impacting_main_process_.md)

*   **Description:** Using Node.js modules (npm packages) within the *main process* that contain known or unknown security vulnerabilities that allow for remote code execution.
*   **Electron Contribution:** While dependency vulnerabilities are a general concern, the impact is amplified in Electron because a compromised main process grants full system access. This is a direct consequence of Electron's architecture.
*   **Example:** An Electron app uses an outdated version of a networking library in its *main process* that has a known remote code execution (RCE) vulnerability. An attacker exploits this vulnerability by sending a crafted network request to the application, gaining control of the main process.
*   **Impact:** Arbitrary code execution in the *main process*, leading to complete system compromise.
*   **Risk Severity:** High (can be Critical depending on the specific vulnerability)
*   **Mitigation Strategies:**
    *   **Dependency Management:** Use `npm` or `yarn` and keep dependencies *strictly* updated to their latest secure versions.
    *   **Vulnerability Scanning:** Employ tools like `npm audit`, `snyk`, or `Dependabot` to automatically and continuously scan for known vulnerabilities in all dependencies.
    *   **Software Composition Analysis (SCA):** Use SCA tools for deeper insights into dependencies and their vulnerabilities, including transitive dependencies.
    *   **Prompt Patching:** Address identified vulnerabilities *immediately*. Do not delay patching.

