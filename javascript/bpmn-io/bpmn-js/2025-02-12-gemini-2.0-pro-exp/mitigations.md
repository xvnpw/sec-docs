# Mitigation Strategies Analysis for bpmn-io/bpmn-js

## Mitigation Strategy: [Safe BPMN XML Import and Configuration](./mitigation_strategies/safe_bpmn_xml_import_and_configuration.md)

**Description:**

1.  **Disable External Entities (Verify):** Although typically the default, *explicitly verify* that the XML parser used by `bpmn-js` (and any underlying libraries it depends on for XML parsing) is configured to *disable* the resolution of external entities. This is crucial for preventing XXE (XML External Entity) attacks.  This might involve checking the configuration options of the underlying XML parsing library if `bpmn-js` doesn't expose this directly.  If you are using a custom `moddle` extension, ensure that *it* also disables external entities.
2.  **Use `importXML` with Error Handling:** When importing BPMN XML into `bpmn-js` (typically using the `importXML` method), always include robust error handling.  The `importXML` method can call a callback with an error if the XML is invalid or if there are other issues during the import process.  *Never* ignore these errors.  Display a user-friendly error message to the user and prevent the diagram from being rendered if an error occurs.  Do *not* attempt to partially render a diagram from invalid XML.
3. **Import Warnings:** Check for *warnings* during the import process as well. `importXML` can also provide warnings, which might indicate potential issues with the BPMN XML, even if it's not strictly invalid. Log these warnings and consider displaying them to the user (or an administrator) for review.
4. **Disable DTD loading:** Ensure that Document Type Definitions (DTDs) are not loaded.

*   **Threats Mitigated:**
    *   **XML External Entity (XXE) Attacks:** (Severity: High) - Prevents attackers from including external files or resources, potentially leading to information disclosure or other attacks.
    *   **Malicious BPMN XML:** (Severity: High) - Prevents the rendering of diagrams based on invalid or maliciously crafted XML, which could exploit vulnerabilities in the parsing or rendering logic.
    *   **BPMN Specification Violations (Partial):** (Severity: Low to Medium) - Helps detect and prevent issues caused by BPMN XML that doesn't fully conform to the specification.

*   **Impact:**
    *   **XXE:** Risk reduced to near zero (if external entities are correctly disabled).
    *   **Malicious XML:** Risk significantly reduced (by preventing rendering of invalid XML).
    *   **BPMN Spec Violations:** Risk reduced (by detecting and handling import errors and warnings).

*   **Currently Implemented:**
    *   *Example:* "The `importXML` method is used with error handling.  Warnings are logged but not displayed to the user.  Verification of external entity disabling needs to be confirmed."
    *   *Placeholder:* [Describe where and how this is implemented in your project.]

*   **Missing Implementation:**
    *   *Example:* "Explicit verification that external entities are disabled in the underlying XML parser is missing.  User-friendly error messages for import failures need improvement."
    *   *Placeholder:* [Describe where this is missing or incomplete in your project.]

## Mitigation Strategy: [Read-Only Mode and Feature Disabling](./mitigation_strategies/read-only_mode_and_feature_disabling.md)

**Description:**

1.  **Identify Read-Only Scenarios:** Determine if there are use cases where users only need to *view* the BPMN diagram, not modify it.
2.  **Enable Read-Only Mode:** Use `bpmn-js`'s built-in read-only mode (typically by passing `{ readOnly: true }` as an option when creating the viewer or modeler instance). This disables all editing features, preventing any client-side modifications through the UI.
3.  **Disable Unnecessary Modules:** `bpmn-js` is modular. Identify any modules or features that are not required for your application (e.g., specific modeling tools, context pads, overlays, custom renderers). Disable these modules during the initialization of the `bpmn-js` viewer or modeler.  This reduces the attack surface by removing code that could potentially contain vulnerabilities.  This is typically done by *not* including the modules in the `modules` array when creating the `bpmn-js` instance.
4. **Disable specific interactions:** If you need editing capabilities, but want to restrict certain actions, you can disable specific interactions or features even in editable mode. For example, you might disable the ability to create certain types of elements or connections, or to modify specific attributes. This can be achieved through custom modules or by overriding default behaviors.

*   **Threats Mitigated:**
    *   **Client-Side Diagram Manipulation (Read-Only):** (Severity: Medium) - Prevents users from modifying the diagram through the `bpmn-js` UI in read-only scenarios.
    *   **Exploitation of Unused Features:** (Severity: Low to Medium) - Reduces the attack surface by removing unnecessary code and functionality that could potentially contain vulnerabilities.

*   **Impact:**
    *   **Client-Side Manipulation (Read-Only):** Risk reduced to near zero in read-only scenarios.
    *   **Exploitation of Unused Features:** Risk reduced (the degree of reduction depends on the number of features disabled).

*   **Currently Implemented:**
    *   *Example:* "Read-only mode is enabled for users with the 'viewer' role.  The context pad and minimap are disabled for all users."
    *   *Placeholder:* [Describe where and how this is implemented in your project.]

*   **Missing Implementation:**
    *   *Example:* "Several `bpmn-js` modules that are not used (e.g., `bpmn-js-token-simulation`) are still included in the build.  These should be removed to reduce the attack surface."
    *   *Placeholder:* [Describe where this is missing or incomplete in your project.]

## Mitigation Strategy: [Secure Handling of Custom Extensions and Modules](./mitigation_strategies/secure_handling_of_custom_extensions_and_modules.md)

**Description:**

1. **Review Custom Code:** If you are using custom `bpmn-js` extensions (e.g., custom renderers, moddle extensions, custom modeling behaviors), thoroughly review the code for security vulnerabilities. Pay close attention to:
    *   **Input Validation:** Validate any input received by your custom extensions, especially if it comes from the BPMN XML or user interactions.
    *   **Data Handling:** Ensure that data is handled securely within your extensions, avoiding potential XSS or injection vulnerabilities.
    *   **Error Handling:** Implement robust error handling to prevent unexpected behavior or crashes.
2. **Sanitize Custom Properties:** If you are using custom properties (attributes) in your BPMN diagrams (e.g., through moddle extensions), ensure that the values of these properties are properly sanitized *before* they are used by `bpmn-js` or your custom extensions. This is especially important if these properties are displayed in the UI or used in any calculations or logic.
3. **Avoid `eval` and Similar Constructs:** Do *not* use `eval()` or similar constructs (e.g., `new Function()`) within your custom extensions, as these can introduce significant security risks.
4. **Principle of Least Privilege:** Design your custom extensions to have only the minimum necessary permissions and access to `bpmn-js` APIs. Avoid granting excessive privileges.

* **Threats Mitigated:**
    * **Vulnerabilities in Custom Code:** (Severity: Varies, from Low to High) - Reduces the risk of introducing security vulnerabilities through your own custom `bpmn-js` extensions.
    * **XSS via Custom Properties:** (Severity: High) - Prevents attackers from injecting malicious code into custom properties that could be executed by `bpmn-js` or your extensions.
    * **Code Injection:** (Severity: High) - Prevents attackers from injecting and executing arbitrary code through your custom extensions.

* **Impact:**
    * **Custom Code Vulnerabilities:** Risk significantly reduced (depending on the thoroughness of the code review and security practices).
    * **XSS via Custom Properties:** Risk significantly reduced (with proper sanitization).
    * **Code Injection:** Risk significantly reduced (by avoiding `eval` and similar constructs).

* **Currently Implemented:**
    * *Example:* "Custom renderers are used to display additional information. Input validation is performed on data received from the server, but sanitization of custom properties from the BPMN XML is not yet implemented."
    * *Placeholder:* [Describe where and how this is implemented in your project.]

* **Missing Implementation:**
    * *Example:* "Sanitization of custom properties read from the BPMN XML is missing. A thorough security review of all custom extensions needs to be conducted."
    * *Placeholder:* [Describe where this is missing or incomplete in your project.]

