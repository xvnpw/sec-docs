# Attack Surface Analysis for wailsapp/wails

## Attack Surface: [Exposed Go Functions](./attack_surfaces/exposed_go_functions.md)

*   **Description:** Wails' fundamental feature is the ability to call Go functions directly from JavaScript in the frontend. This creates a direct, powerful communication channel that must be meticulously secured.
*   **How Wails Contributes:** This is the *defining* characteristic of Wails. The framework provides the binding, invocation, and data marshalling mechanisms.
*   **Example:** A Go function `executeSystemCommand(command string)` is inadvertently exposed. An attacker crafts a JavaScript call: `window.go.main.App.executeSystemCommand("rm -rf /");` to execute a destructive command.
*   **Impact:** Unauthorized execution of arbitrary backend logic, data modification/deletion, complete system compromise, denial of service.
*   **Risk Severity:** **Critical** (if sensitive functions are exposed) / **High** (if less sensitive but still unauthorized actions are possible).
*   **Mitigation Strategies:**
    *   **Strict Whitelisting:** Expose *only* the absolute minimum set of Go functions required for frontend interaction.  Use a "deny-by-default" approach.
    *   **Backend Input Validation:** Implement comprehensive input validation *within the Go function itself*. Validate all parameters: types, ranges, formats, and authorization.  Never trust frontend validation alone.
    *   **Authorization Checks:** Before executing *any* action, verify that the frontend context (and potentially the user) has the necessary permissions. Use session tokens, roles, or other authorization mechanisms.
    *   **Code Reviews:** Mandatory, rigorous code reviews must specifically focus on identifying and scrutinizing *all* exposed Go functions and their security implications.
    *   **Least Privilege:** Run the Wails application with the least necessary operating system privileges.

## Attack Surface: [Data Serialization/Deserialization Issues](./attack_surfaces/data_serializationdeserialization_issues.md)

*   **Description:** Data passed between the Go backend and JavaScript frontend is serialized and deserialized, typically using JSON. Vulnerabilities in this process, especially with custom data structures, can lead to severe consequences.
*   **How Wails Contributes:** Wails manages the serialization/deserialization process. The framework's choice of libraries and its handling of Go's `interface{}` type are particularly relevant.
*   **Example:** A custom Go struct with an `interface{}` field is used for communication. An attacker crafts a malicious JSON payload that, upon deserialization, instantiates a type with a method that executes arbitrary code (a classic deserialization vulnerability).
*   **Impact:** Remote Code Execution (RCE), data corruption, denial of service.
*   **Risk Severity:** **Critical** (if RCE is possible) / **High** (if data corruption or DoS is possible).
*   **Mitigation Strategies:**
    *   **Prefer Standard Libraries:** Use Go's built-in `encoding/json` package and keep it updated. Avoid custom serialization implementations unless absolutely necessary and thoroughly vetted.
    *   **Schema Validation:** Employ a schema validation library (e.g., JSON Schema) to enforce the expected structure and data types of all data exchanged. This prevents unexpected or malicious data from being processed.
    *   **Type Safety (interface{}):** Exercise *extreme caution* when using `interface{}` fields in Go structs. Implement rigorous type checking and whitelisting of allowed types during deserialization. Consider more type-safe alternatives if feasible.
    *   **Regular Security Updates:** Keep Go and all serialization-related libraries updated to patch known vulnerabilities.

## Attack Surface: [Malicious Events](./attack_surfaces/malicious_events.md)

*   **Description:** Wails' event system allows the frontend to trigger actions in the Go backend. Unsecured event handlers can be exploited to perform unauthorized actions.
*   **How Wails Contributes:** Wails provides the entire event system infrastructure – the mechanism for emitting and receiving events between the frontend and backend.
*   **Example:** An event handler `grantAdminPrivileges(eventData)` is intended for internal use. An attacker emits a crafted event with manipulated `eventData` to gain administrator privileges.
*   **Impact:** Unauthorized data modification, privilege escalation, denial of service, potentially triggering other vulnerabilities.
*   **Risk Severity:** **High** (due to the potential for unauthorized actions and privilege escalation).
*   **Mitigation Strategies:**
    *   **Event Source Validation:** Verify the origin of the event within the Go event handler. Wails may provide mechanisms to identify the source (e.g., frontend window ID).
    *   **Rigorous Event Data Validation:** Thoroughly validate *all* data contained within the event payload *within the Go event handler*. Never assume the data is safe or trustworthy.
    *   **Authorization Checks (Event Handlers):** Implement authorization checks within the event handler to ensure the event trigger has the necessary permissions.
    *   **Limit Event Usage:** Use events judiciously, especially for sensitive operations. Prefer direct, validated function calls when possible.
    *   **Rate Limiting:** Implement rate limiting on event handling to prevent attackers from flooding the backend with malicious events.

