# Attack Surface Analysis for dromara/hutool

## Attack Surface: [Deserialization of Untrusted Data (via `SerializeUtil`)](./attack_surfaces/deserialization_of_untrusted_data__via__serializeutil__.md)

*   **Description:**  Deserializing data from untrusted sources using Hutool's `SerializeUtil` can lead to arbitrary code execution.
*   **How Hutool Contributes:**  `hutool-core`'s `SerializeUtil` provides the vulnerable functionality.
*   **Example:**  An attacker sends a crafted serialized object; `SerializeUtil.deserialize()` executes the malicious payload.
*   **Impact:**  Complete system compromise.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Avoid Deserialization of Untrusted Data:**  The *only* truly safe approach.
    *   **Use Safer Data Formats:**  JSON/XML with strict schema validation.
    *   **Strict Whitelisting (Last Resort):**  A custom `ObjectInputStream` with an extremely limited, pre-approved class whitelist (complex and error-prone).

## Attack Surface: [Command Injection (via `RuntimeUtil`)](./attack_surfaces/command_injection__via__runtimeutil__.md)

*   **Description:**  Executing system commands with user-influenced input using `RuntimeUtil.exec()`.
*   **How Hutool Contributes:**  `hutool-core`'s `RuntimeUtil` provides the command execution functionality.
*   **Example:**  `RuntimeUtil.exec("command " + userInput)`; attacker provides malicious input.
*   **Impact:**  Complete system compromise.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Avoid User Input in Commands:**  The best and safest approach.
    *   **Strict Input Validation/Sanitization (Extremely Difficult):**  Whitelist allowed characters, escape dangerous ones (very error-prone).
    *   **Parameterized Commands (If Possible):** Use a secure API that separates commands from data.

## Attack Surface: [SQL Injection (via `hutool-db`)](./attack_surfaces/sql_injection__via__hutool-db__.md)

*   **Description:**  Constructing SQL queries without using parameterized queries in `hutool-db`.
*   **How Hutool Contributes:**  `hutool-db` provides database interaction; incorrect usage enables SQL injection.
*   **Example:**  `DbUtil.use().query("... WHERE field = '" + userInput + "'")`; attacker manipulates the query.
*   **Impact:**  Data breach, modification, deletion; potential server compromise.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Parameterized Queries/Prepared Statements:**  *Always* use them.  Hutool supports this; use it *exclusively*.
    *   **ORM (with Caution):**  ORMs often handle parameterization, but still require careful review.

## Attack Surface: [Server-Side Request Forgery (SSRF) (via `hutool-http`)](./attack_surfaces/server-side_request_forgery__ssrf___via__hutool-http__.md)

*   **Description:**  Making HTTP requests to user-controlled URLs using `HttpUtil`.
*   **How Hutool Contributes:**  `hutool-http`'s `HttpUtil` provides the HTTP request functionality.
*   **Example:**  `HttpUtil.get(userInput)`; attacker provides an internal or malicious URL.
*   **Impact:**  Access to internal services, data exposure, further attacks.
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **Avoid User-Provided URLs:**  The best approach.
    *   **Strict Whitelist:**  Allow only specific, pre-approved domains and protocols.
    *   **Input Validation:**  Validate URL format and prevent access to internal resources.

## Attack Surface: [Path Traversal (via `ResourceUtil`)](./attack_surfaces/path_traversal__via__resourceutil__.md)

*   **Description:**  Loading resources with user-controlled paths using `ResourceUtil`.
*   **How Hutool Contributes:** `hutool-core`'s `ResourceUtil` handles resource loading.
*   **Example:** `ResourceUtil.getResource(userInput)`; attacker provides a path like `../../etc/passwd`.
*   **Impact:** Disclosure of sensitive files.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid User-Provided Paths:** The safest option.
    *   **Sanitize and Validate:** Remove ".." sequences, validate the path is within the expected directory, and use canonicalization.

## Attack Surface: [Reflection-Based Attacks (via `ReflectUtil`)](./attack_surfaces/reflection-based_attacks__via__reflectutil__.md)

*   **Description:** Using `ReflectUtil` with user-influenced class names, method names, or arguments.
*   **How Hutool Contributes:** `hutool-core`'s `ReflectUtil` provides reflection capabilities.
*   **Example:** `ReflectUtil.invoke(userInput1, userInput2, userInput3)`; attacker controls the reflection process.
*   **Impact:** Bypass security checks, access private data, potential code execution.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid Reflection with Untrusted Input:** The primary mitigation.
    *   **Strict Whitelisting:** If unavoidable, allow only specific, pre-approved classes and methods.

