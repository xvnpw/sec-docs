# Attack Surface Analysis for jdg/mbprogresshud

## Attack Surface: [Main Thread Blocking (DoS)](./attack_surfaces/main_thread_blocking__dos_.md)

*   **Description:** Long-running operations triggered by or associated with the HUD block the main thread, making the application unresponsive. This is a direct consequence of how `MBProgressHUD` is designed to be used on the main thread.
*   **How MBProgressHUD Contributes:** The library is designed for main thread use.  Showing, hiding, and updating the HUD *must* happen on the main thread.  If the operations that *trigger* these actions are slow, the UI freezes. This is the core issue.
*   **Example:**
    *   A network request is initiated, and an `MBProgressHUD` is shown. The network request hangs (server issue, malicious server, network interruption). The HUD remains visible, and the entire application becomes unresponsive because the main thread is blocked, waiting for the network request (which `MBProgressHUD` is visually representing).
    *   Heavy data processing is started, and `MBProgressHUD` is used to show progress. If this processing is done *synchronously* on the main thread, the UI will freeze until it's complete. The HUD itself becomes part of the problem.
*   **Impact:** Denial of Service (DoS) – The application becomes completely unusable until the blocking operation completes (or never, if it hangs indefinitely).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Asynchronous Operations:** *All* long-running operations (network, data processing, file I/O) *must* be performed on background threads. Use Grand Central Dispatch (GCD) or `OperationQueue`. This is non-negotiable.
    *   **Main Thread Updates Only:** Only update the `MBProgressHUD` itself (show, hide, update text/progress) on the main thread: `DispatchQueue.main.async { ... }`.
    *   **Timeouts:** Implement strict timeouts for *all* network requests and other potentially long-running operations. Use `URLSession`'s timeout properties.  This prevents indefinite hangs.
    *   **Rate Limiting:** If user actions or network requests trigger the HUD-related operations, implement rate limiting to prevent an attacker from flooding the app and causing blocking.
    *   **Background Task Management:** If operations must continue in the background, use appropriate background task APIs (e.g., `beginBackgroundTask(withName:expirationHandler:)`) to prevent premature termination.
    * **Developer Training:** Ensure all developers *thoroughly* understand threading and how to use GCD or `OperationQueue` correctly. This is a fundamental iOS development skill.

