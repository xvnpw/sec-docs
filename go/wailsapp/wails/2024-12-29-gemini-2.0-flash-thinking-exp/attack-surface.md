*   **Exposed Go Functions to Frontend:**
    *   **Description:** Developers can expose Go functions directly to the frontend JavaScript, allowing the frontend to invoke backend logic.
    *   **How Wails Contributes:** Wails provides the mechanism (`wails.Bind`) to explicitly expose these functions, creating a direct bridge between the frontend and backend.
    *   **Example:** A Go function `GetUserProfile(userID string)` is exposed. A malicious frontend script could call this function with arbitrary user IDs, potentially accessing sensitive data of other users if proper authorization isn't implemented in the Go function.
    *   **Impact:** Arbitrary code execution on the backend, data breaches, privilege escalation, denial of service.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Input Validation and Sanitization:** Thoroughly validate and sanitize all input received by exposed Go functions on the backend.
        *   **Authorization and Authentication:** Implement robust authentication and authorization checks within the Go functions to ensure only authorized users can perform specific actions.
        *   **Principle of Least Privilege:** Only expose the necessary functions and with the minimum required permissions. Avoid exposing functions that interact directly with sensitive system resources if possible.
        *   **Careful Function Design:** Design exposed functions with security in mind, avoiding complex logic that could introduce vulnerabilities.

*   **Data Serialization/Deserialization Between Frontend and Backend:**
    *   **Description:** Data exchanged between the Go backend and the JavaScript frontend needs to be serialized and deserialized. Vulnerabilities can arise in how this process is handled.
    *   **How Wails Contributes:** Wails handles the underlying serialization and deserialization of data passed through the exposed functions. While Wails uses standard Go encoding, improper handling of data structures or types can introduce risks.
    *   **Example:** A Go struct containing sensitive information is passed to the frontend. If the frontend code is compromised (e.g., through XSS), the attacker can access this sensitive data. Conversely, if the backend doesn't properly validate data received from the frontend, malicious data could cause issues.
    *   **Impact:** Information disclosure, data corruption, potential for code execution if deserialization vulnerabilities exist in custom data handling.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Secure Data Structures:** Design data structures to minimize the exposure of sensitive information.
        *   **Strict Type Checking:** Enforce strict type checking on both the frontend and backend to prevent unexpected data types from being processed.
        *   **Avoid Custom Serialization/Deserialization (if possible):** Rely on well-vetted standard libraries for serialization and deserialization. If custom logic is necessary, ensure it's thoroughly reviewed for security vulnerabilities.
        *   **Data Sanitization on Both Ends:** Sanitize data on both the frontend (before sending) and backend (after receiving) to prevent injection attacks.

*   **Custom Protocol Handlers (if implemented):**
    *   **Description:** Wails allows developers to register custom protocol handlers. If these handlers are not carefully implemented, they can be exploited.
    *   **How Wails Contributes:** Wails provides the functionality to register these custom protocols, extending the application's interaction with the operating system.
    *   **Example:** A custom protocol handler `myapp://openfile?path=/etc/passwd` is registered. If not properly secured, an attacker could craft a malicious link that, when clicked, attempts to access sensitive files on the user's system.
    *   **Impact:** Local file access, command execution on the user's machine.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Strict Input Validation for Protocol Handlers:** Thoroughly validate and sanitize any input received by custom protocol handlers.
        *   **Principle of Least Privilege for Protocol Handlers:** Only allow protocol handlers to perform the necessary actions and access the minimum required resources.
        *   **Avoid Executing Shell Commands Directly:** If possible, avoid directly executing shell commands within protocol handlers. If necessary, carefully sanitize inputs to prevent command injection.
        *   **Inform Users About Custom Protocols:** If using custom protocols, inform users about their purpose and potential risks.