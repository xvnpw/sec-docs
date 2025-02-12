# Mitigation Strategies Analysis for fastify/fastify

## Mitigation Strategy: [Strict Input Sanitization and Validation for Decorators and Plugins (Fastify-Specific)](./mitigation_strategies/strict_input_sanitization_and_validation_for_decorators_and_plugins__fastify-specific_.md)

*   **Description:**
    1.  **Identify Fastify Decorator/Plugin Usage:**  Specifically identify all uses of `fastify.decorate`, `fastify.decorateRequest`, `fastify.decorateReply`, and plugin registration (`fastify.register`) where user-supplied data (directly or indirectly) influences the *names* or *values* being decorated or the plugin's options.
    2.  **Whitelist Allowed Characters/Patterns:**  For decorator *keys*, define a very strict whitelist (e.g., `^[a-zA-Z0-9_]+$`).  Reject anything that doesn't match.  This is crucial because these keys become properties on Fastify objects.
    3.  **Validate Decorator Values:**  Even if the *key* is safe, the *value* being decorated could be malicious.  Apply appropriate validation based on the expected type and usage of the decorated value.  If it's a function, ensure it's not dynamically generated from user input.
    4.  **Plugin Options Validation:**  If a plugin accepts options, and those options are influenced by user input, define a JSON Schema to validate the options object *before* passing it to `fastify.register`.  Use `additionalProperties: false`.
    5.  **`Object.create(null)` for Internal Objects:** Within your *own* plugins or decorators, if you create objects to store data related to user input, use `Object.create(null)` to create them. This prevents prototype pollution attacks targeting your internal data structures.
    6.  **Fastify-Specific Testing:**  Write tests that specifically target the Fastify decorator and plugin registration mechanisms with malicious input designed to trigger prototype pollution or code injection.

*   **Threats Mitigated:**
    *   **Prototype Pollution (via Fastify Decorators/Plugins):** (Severity: **Critical**) - Directly prevents attackers from exploiting Fastify's decorator and plugin system to pollute the prototype chain.
    *   **Code Injection (Indirectly, via Plugins):** (Severity: **High**) - Reduces the risk of malicious code execution if a compromised plugin misuses Fastify's API due to improper input handling.
    *   **Fastify-Specific Unexpected Behavior:** (Severity: **Medium**) - Prevents unexpected behavior caused by invalid input used in Fastify's core features.

*   **Impact:**
    *   **Prototype Pollution:** Risk significantly reduced. This is the primary focus of this mitigation.
    *   **Code Injection:** Risk reduced, but relies on the security of the plugins themselves.
    *   **Fastify-Specific Unexpected Behavior:** Risk significantly reduced.

*   **Currently Implemented:** *[Example: No specific validation for decorator keys or values. Plugin options are validated using JSON Schema for some plugins, but not all.]*

*   **Missing Implementation:** *[Example: Need to add explicit validation for all decorator keys and values. Need to review all plugin registrations and ensure options are validated with JSON Schema.]*

## Mitigation Strategy: [Enforce Request Body Size Limits with `bodyLimit`](./mitigation_strategies/enforce_request_body_size_limits_with__bodylimit_.md)

*   **Description:**
    1.  **Determine Appropriate Limits:** Analyze application usage to determine reasonable maximum request body sizes.
    2.  **Configure `bodyLimit`:** Set the `bodyLimit` option in the Fastify server configuration (in bytes). This is a *Fastify-specific* setting.
        ```javascript
        const fastify = require('fastify')({
            bodyLimit: 1048576 // 1MB limit
        });
        ```
    3.  **Route-Specific Overrides (using `preHandler`):**  For routes needing different limits, use a `preHandler` hook to check `Content-Length` *before* Fastify parses the body. This leverages Fastify's hook system.
    4.  **Fastify-Specific Testing:** Test with payloads exceeding the `bodyLimit` to ensure Fastify correctly rejects them.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) via Large Payloads (Fastify-Handled):** (Severity: **High**) - Directly prevents Fastify from processing excessively large request bodies.
    *   **Resource Exhaustion (within Fastify):** (Severity: **High**) - Prevents Fastify from allocating excessive memory for large requests.

*   **Impact:**
    *   **DoS via Large Payloads:** Risk significantly reduced. This is a direct mitigation using a Fastify feature.
    *   **Resource Exhaustion:** Risk significantly reduced within the context of Fastify's request handling.

*   **Currently Implemented:** *[Example: `bodyLimit` is set globally to 5MB.]*

*   **Missing Implementation:** *[Example: Missing route-specific overrides for file upload routes using `preHandler`.]*

## Mitigation Strategy: [Rigorous JSON Schema Validation using Fastify's Built-in Features](./mitigation_strategies/rigorous_json_schema_validation_using_fastify's_built-in_features.md)

*   **Description:**
    1.  **Comprehensive Schemas (for Fastify Routes):**  For *every* Fastify route that accepts JSON input, define a detailed JSON Schema *using Fastify's built-in schema validation*.  Use specific data types, formats, and constraints.  Always use `additionalProperties: false`.
    2.  **`ajv-formats` and `ajv-errors` (with Fastify):** Integrate these plugins *within Fastify's configuration* to enhance validation and error messages.
    3.  **Custom Validation (using Fastify Hooks):** For complex logic, use Fastify's `preValidation` or `preHandler` hooks to implement custom validation *after* Fastify's schema validation.
    4.  **Fastify-Specific Testing:**  Write tests that specifically target Fastify's request validation with various invalid inputs.

*   **Threats Mitigated:**
    *   **Schema Validation Bypass (within Fastify):** (Severity: **High**) - Reduces the risk of bypassing Fastify's built-in validation.
    *   **Data Injection (into Fastify Handlers):** (Severity: **High**) - Prevents malicious data from reaching your route handlers *through Fastify's validation*.
    *   **Fastify-Related Unexpected Behavior:** (Severity: **Medium**) - Prevents unexpected behavior caused by invalid input processed by Fastify.

*   **Impact:**
    *   **Schema Validation Bypass:** Risk significantly reduced within Fastify's request handling.
    *   **Data Injection:** Risk reduced for data processed by Fastify's request handling.
    *   **Fastify-Related Unexpected Behavior:** Risk significantly reduced.

*   **Currently Implemented:** *[Example: JSON Schemas are defined for all routes using Fastify's validation. `ajv-formats` is used.]*

*   **Missing Implementation:** *[Example: Missing custom validation using `preValidation` for a specific field.]*

## Mitigation Strategy: [Secure Fastify Hook Implementation](./mitigation_strategies/secure_fastify_hook_implementation.md)

*   **Description:**
    1.  **Identify All Fastify Hooks:** List all custom Fastify hooks used (e.g., `onRequest`, `preValidation`, `preHandler`, `onSend`, `onError`).
    2.  **Review Hook Code (for Fastify-Specific Issues):** Review each hook, focusing on:
        *   **Fastify API Misuse:** Ensure the hook correctly uses Fastify's API and doesn't introduce vulnerabilities through improper usage.
        *   **Request/Response Modification:** Avoid direct modification of `request` or `reply` objects unless absolutely necessary, and do so carefully.
        *   **Error Handling (within Fastify Context):** Ensure errors within hooks are handled correctly and don't expose sensitive information or disrupt Fastify's request processing.
        *   **Asynchronous Operations (within Fastify):** Ensure asynchronous operations are properly awaited and errors are handled, preventing unhandled rejections that could affect Fastify.
    3.  **Minimize Hook Complexity (within Fastify):** Keep hook logic simple to reduce the risk of Fastify-related errors.
    4.  **Centralized Error Handling (using `onError`):** Use Fastify's `onError` hook to centrally handle errors.
    5.  **Fastify-Specific Testing:** Create tests that specifically exercise the Fastify hooks with various inputs and scenarios.

*   **Threats Mitigated:**
    *   **Injection Attacks (through Fastify Hooks):** (Severity: **High**) - Prevents vulnerabilities introduced by improperly implemented Fastify hooks.
    *   **Data Leakage (via Fastify Hooks):** (Severity: **Medium**) - Reduces the risk of sensitive information being leaked through errors or logging within Fastify hooks.
    *   **Fastify-Specific Unexpected Behavior:** (Severity: **Medium**) - Prevents unexpected behavior caused by errors or logic flaws in Fastify hooks.
    *   **DoS (via Fastify Hooks):** (Severity: **Medium**) - Prevents poorly written hooks from causing performance issues within Fastify.

*   **Impact:**
    *   **Injection Attacks:** Risk reduced, depending on the specific hook and the type of injection.
    *   **Data Leakage:** Risk reduced within the context of Fastify's hook execution.
    *   **Fastify-Specific Unexpected Behavior:** Risk significantly reduced.
    *   **DoS:** Risk reduced for issues caused by Fastify hook execution.

*   **Currently Implemented:** *[Example: Basic error handling in most hooks.]*

*   **Missing Implementation:** *[Example: Need a thorough security review of all Fastify hooks, focusing on Fastify API misuse, data modification, and error handling.]*

## Mitigation Strategy: [Correct `trustProxy` Configuration in Fastify](./mitigation_strategies/correct__trustproxy__configuration_in_fastify.md)

*   **Description:**
    1.  **Understand Network Topology:** Clearly document your network architecture, including all proxy servers.
    2.  **Identify Trusted Proxies:** Determine the IP addresses or CIDR ranges of *all* trusted proxy servers.
    3.  **Configure `trustProxy` (in Fastify):** Configure Fastify's `trustProxy` option *correctly*:
        *   **Specific IPs/CIDRs:**  Provide an array of trusted IP addresses or CIDR ranges. This is the most secure and Fastify-specific approach.
        *   **`true` (AVOID if possible):** Only use `true` if *absolutely* certain about trusted proxies *and* the proxy's configuration.
        *   **Number (hop count):** Use a number if you know the exact number of trusted proxies.
        *   **Function:** Use a custom function for complex scenarios.
    4.  **Fastify-Specific Testing:** Test with and without the proxy to ensure `trustProxy` in Fastify works as expected.

*   **Threats Mitigated:**
    *   **IP Spoofing (affecting Fastify):** (Severity: **High**) - Prevents attackers from forging their IP address as seen by Fastify.
    *   **Incorrect Rate Limiting (within Fastify):** (Severity: **Medium**) - Ensures Fastify's rate limiting (if used) is based on the correct client IP.
    *   **Fastify-Related Security Misconfigurations:** (Severity: **Medium**) - Reduces misconfigurations related to Fastify's proxy handling.

*   **Impact:**
    *   **IP Spoofing:** Risk significantly reduced with specific IP/CIDR configuration in Fastify.
    *   **Incorrect Rate Limiting:** Risk significantly reduced within Fastify's context.
    *   **Fastify-Related Security Misconfigurations:** Risk reduced.

*   **Currently Implemented:** *[Example: `trustProxy` is set to `true`.]*

*   **Missing Implementation:** *[Example: Need to change `trustProxy` to use the specific IP addresses of the proxy servers.]*

