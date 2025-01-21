# Attack Surface Analysis for walkor/workerman

## Attack Surface: [Unvalidated Input from Sockets](./attack_surfaces/unvalidated_input_from_sockets.md)

*   **Description:** The application receives data directly from network sockets (TCP, UDP, WebSocket) without proper validation or sanitization.
    *   **How Workerman Contributes:** Workerman's core functionality is handling raw socket connections and delivering the raw data to the application's event handlers. It doesn't inherently provide input validation mechanisms, making it the direct conduit for potentially malicious data.
    *   **Example:** A malicious client sends a TCP packet with an excessively long string intended to overflow a buffer in the application's data processing logic, which is directly triggered by the data received through Workerman's socket handling.
    *   **Impact:**  Can lead to buffer overflows, format string vulnerabilities, injection attacks within custom protocols, denial of service, or even remote code execution.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Implement robust input validation:**  Thoroughly validate all data received from sockets *within the Workerman event handlers* against expected formats, lengths, and types.
        *   **Use prepared statements or parameterized queries:** If the application interacts with databases based on socket input handled by Workerman, use these techniques to prevent SQL injection.
        *   **Sanitize input:**  Escape or remove potentially harmful characters from user-provided data *immediately after receiving it through Workerman*.
        *   **Set maximum input lengths:**  Limit the size of data accepted from sockets *at the Workerman level or within the initial processing*.

## Attack Surface: [Deserialization of Untrusted Data](./attack_surfaces/deserialization_of_untrusted_data.md)

*   **Description:** The application uses PHP's `unserialize()` function on data received from clients without verifying its integrity or origin.
    *   **How Workerman Contributes:** Workerman facilitates receiving serialized data over sockets, making it the direct entry point for this vulnerability if the application uses `unserialize()` directly on data received through Workerman.
    *   **Example:** A malicious client sends a crafted serialized object through a Workerman socket connection that, when unserialized, triggers a magic method (`__wakeup`, `__destruct`, etc.) leading to arbitrary code execution.
    *   **Impact:** Remote code execution, allowing the attacker to gain full control of the server.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid `unserialize()` on untrusted data received via Workerman:** If possible, use safer data formats like JSON and use `json_decode()` on data received through Workerman.
        *   **Implement signature verification:**  Sign serialized data before sending and verify the signature *immediately after receiving it through Workerman* before unserializing.
        *   **Use whitelisting for allowed classes:** If `unserialize()` is unavoidable on data received via Workerman, implement a whitelist of allowed classes to prevent the instantiation of malicious objects.

## Attack Surface: [Custom Protocol Vulnerabilities](./attack_surfaces/custom_protocol_vulnerabilities.md)

*   **Description:** Applications implementing custom protocols on top of Workerman may introduce vulnerabilities due to insecure design or implementation of the protocol.
    *   **How Workerman Contributes:** Workerman provides the low-level socket handling that forms the foundation for these custom protocols. The framework itself doesn't enforce any security measures on the protocol logic.
    *   **Example:** A custom protocol, handled by a Workerman worker, lacks proper authentication, allowing any client connecting through Workerman to send commands. Another example is a protocol where commands are constructed by concatenating user input received via Workerman without sanitization, leading to command injection.
    *   **Impact:**  Wide range of impacts depending on the protocol's functionality, including unauthorized access, data breaches, remote code execution, and denial of service.
    *   **Risk Severity:** High to Critical (depending on the protocol's complexity and sensitivity)
    *   **Mitigation Strategies:**
        *   **Design protocols with security in mind:**  Implement robust authentication and authorization mechanisms *within the Workerman event handlers for the custom protocol*.
        *   **Avoid constructing commands directly from user input received via Workerman:** Use safe methods for command execution or data manipulation.
        *   **Implement input validation and sanitization specific to the protocol's format *within the Workerman event handlers* .**
        *   **Consider using established and well-vetted protocols where possible instead of creating custom ones on top of Workerman**.

## Attack Surface: [Running Workers with Elevated Privileges](./attack_surfaces/running_workers_with_elevated_privileges.md)

*   **Description:** Workerman worker processes are run with unnecessary root or elevated privileges.
    *   **How Workerman Contributes:** Workerman allows configuring the user under which worker processes run. Incorrect configuration directly leads to this vulnerability.
    *   **Example:** A vulnerability in the application logic, triggered by data received through Workerman, allows an attacker to execute arbitrary code within a worker process that is running as root, granting the attacker full control of the server.
    *   **Impact:** Complete system compromise if a vulnerability is exploited in a privileged worker process.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Run worker processes with the least necessary privileges:**  Configure Workerman to run worker processes under a dedicated user with minimal permissions.
        *   **Avoid running workers as root.**  This is a direct Workerman configuration concern.

