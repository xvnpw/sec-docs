### High and Critical Threats Directly Involving Jackson-Core

This list details high and critical security threats that directly involve the `jackson-core` library.

*   **Threat:** Type Confusion during Deserialization
    *   **Description:** An attacker crafts a malicious JSON payload that, when parsed by `jackson-core`, is then used by `jackson-databind` (which relies on `jackson-core` for parsing) to instantiate an object of an unexpected type. While the type confusion manifests in `jackson-databind`, the initial parsing of the malicious structure is handled by `jackson-core`. The attacker manipulates the JSON structure to exploit how `jackson-databind` interprets the parsed data.
    *   **Impact:**  Depending on the application logic and the instantiated class, this can lead to:
        *   **Information Disclosure:** Accessing or exposing data that should not be accessible.
        *   **Logic Errors:** Causing the application to behave in an unintended and harmful way.
        *   **Denial of Service:** Triggering resource-intensive operations or crashes.
    *   **Affected Component:**
        *   `jackson-core` (specifically the parsing module, `JsonParser`, responsible for reading and interpreting the JSON structure that facilitates the type confusion in `jackson-databind`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Input Validation:** Implement robust validation on the deserialized objects in the `jackson-databind` layer to ensure they conform to the expected types and constraints.
        *   **Avoid Deserializing Untrusted Data Directly:** Sanitize or transform untrusted JSON data before deserialization in the `jackson-databind` layer.
        *   **Use Specific Type References:** When deserializing using `jackson-databind`, explicitly specify the expected class type.
        *   **Consider Using Schemas:** Employ JSON schema validation to enforce the structure and types of incoming JSON data before it's parsed by `jackson-core` and processed by `jackson-databind`.

*   **Threat:** Polymorphic Deserialization Exploits
    *   **Description:** If the application uses Jackson's polymorphic deserialization features (handled by `jackson-databind` but relying on the parsing from `jackson-core`), an attacker can manipulate the type information within the JSON payload. `jackson-core` parses this malicious type information, which `jackson-databind` then uses to attempt to instantiate arbitrary classes. This is dangerous if the application's classpath contains classes with dangerous side effects.
    *   **Impact:**
        *   **Remote Code Execution (RCE):** The attacker can execute arbitrary code on the server or client.
        *   **Complete System Compromise:** RCE can lead to full control over the affected system.
    *   **Affected Component:**
        *   `jackson-core` (specifically the parsing module, `JsonParser`, responsible for reading and interpreting the type information within the JSON structure that is then used by `jackson-databind` for polymorphic deserialization).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Disable Default Typing:** Avoid using Jackson's default typing mechanism in `jackson-databind`.
        *   **Use Whitelists for Polymorphic Types:** If polymorphic deserialization is necessary, explicitly define a whitelist of allowed classes in `jackson-databind`.
        *   **Minimize Dependencies:** Reduce the number of third-party libraries to minimize potential gadget classes.
        *   **Regularly Update Dependencies:** Keep Jackson and all other dependencies updated.
        *   **Security Audits:** Conduct regular security audits and penetration testing.