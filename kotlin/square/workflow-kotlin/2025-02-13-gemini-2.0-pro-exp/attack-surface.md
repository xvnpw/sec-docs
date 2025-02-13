# Attack Surface Analysis for square/workflow-kotlin

## Attack Surface: [1. Input Manipulation: Unexpected Action Sequences](./attack_surfaces/1__input_manipulation_unexpected_action_sequences.md)

*Description:* Attackers send actions in an order or at times not intended by the workflow design, leading to unexpected state transitions.
*Workflow-kotlin Contribution:* `workflow-kotlin`'s core functionality is based on state transitions triggered by actions. The library provides the framework, but the developer defines the valid transitions. Insufficiently restrictive transition rules create this vulnerability.
*Example:* A workflow for processing orders has states: `Pending`, `PaymentReceived`, `Shipped`, `Delivered`. An attacker sends a `Shipped` action *before* a `PaymentReceived` action, bypassing payment.
*Impact:* Bypass of business logic, data inconsistency, potential financial loss, unauthorized actions.
*Risk Severity:* High
*Mitigation Strategies:*
    *   **Developer:** Rigorously define all valid state transitions in the workflow definition. Use a state diagram or formal method (like TLA+) to model and verify the workflow's logic. Implement guard conditions within the workflow to prevent transitions based on invalid preconditions.

## Attack Surface: [2. Input Manipulation: Malformed Action Payloads](./attack_surfaces/2__input_manipulation_malformed_action_payloads.md)

*Description:* Attackers send actions with intentionally corrupted, oversized, or otherwise invalid data payloads.
*Workflow-kotlin Contribution:* `workflow-kotlin` allows actions to carry arbitrary data payloads. The library itself doesn't enforce any specific payload structure or validation.
*Example:* An action to update a user profile accepts a `name` field. An attacker sends a multi-gigabyte string in the `name` field, attempting a denial-of-service. Or, they inject special characters hoping to trigger an injection vulnerability in a downstream system.
*Impact:* Denial-of-service, code injection, data corruption, unexpected application behavior.
*Risk Severity:* High
*Mitigation Strategies:*
    *   **Developer:** Implement strict input validation and sanitization for *all* action payloads. Use a schema validation library (e.g., Kotlin serialization with schema, JSON Schema) to define and enforce the expected structure and data types of payloads. Limit the maximum size of payloads.

## Attack Surface: [3. Input Manipulation: Action Injection](./attack_surfaces/3__input_manipulation_action_injection.md)

*Description:* Attackers inject arbitrary, unauthorized actions into the workflow.
*Workflow-kotlin Contribution:* `workflow-kotlin` processes actions received from a source (e.g., message queue, API). The library itself doesn't handle authentication or authorization of the action source.
*Example:* An attacker gains access to the message queue used to send actions to the workflow and injects a `DeleteUser` action with administrative privileges.
*Impact:* Complete compromise of the workflow, unauthorized execution of arbitrary actions, data loss, system compromise.
*Risk Severity:* Critical
*Mitigation Strategies:*
    *   **Developer:** Implement strong authentication and authorization for *all* sources of actions. Use message signing (e.g., HMAC, digital signatures) to verify the integrity and authenticity of actions. Ensure that only trusted systems can send actions.

## Attack Surface: [4. State Manipulation: State Deserialization Vulnerabilities](./attack_surfaces/4__state_manipulation_state_deserialization_vulnerabilities.md)

*Description:* Attackers exploit vulnerabilities in the deserialization process to inject malicious data and potentially execute arbitrary code.
*Workflow-kotlin Contribution:* `workflow-kotlin` uses serialization/deserialization to persist and restore workflow state. The choice of serialization library and its configuration directly impact this vulnerability.
*Example:* The workflow uses a vulnerable version of a serialization library. An attacker crafts a malicious serialized payload that, when deserialized, executes arbitrary code on the server.
*Impact:* Remote code execution, complete system compromise, data theft.
*Risk Severity:* Critical
*Mitigation Strategies:*
    *   **Developer:** Use a secure serialization library (e.g., Kotlin serialization with appropriate security configurations). Avoid inherently unsafe serialization formats (e.g., Java's default serialization). Implement whitelisting of allowed classes during deserialization. Regularly update serialization libraries to patch known vulnerabilities. Consider using a context-aware deserialization approach that validates the deserialized data against the expected workflow state.

