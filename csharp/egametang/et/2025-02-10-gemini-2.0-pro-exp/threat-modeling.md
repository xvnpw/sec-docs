# Threat Model Analysis for egametang/et

## Threat: [Rogue Scene Injection](./threats/rogue_scene_injection.md)

*   **Description:** An attacker crafts a malicious "Scene" (a core organizational unit in `ET`) and injects it into the server's running instance.  This could be done by exploiting a vulnerability in the `ET.NetworkComponent` or `ET.Scene` management logic, bypassing authentication checks during scene creation or registration. The attacker might send a specially crafted message that mimics a legitimate scene registration request.
*   **Impact:** The attacker gains control over a portion of the game world, potentially intercepting messages, manipulating game state for all players within that scene, or launching further attacks.  Could lead to complete server compromise.
*   **Affected ET Component:** `ET.Scene` (creation/management logic), `ET.NetworkComponent` (message handling for scene registration), potentially `ET.EntitySystem` if scene registration bypasses entity validation.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strong Authentication:** Implement robust authentication for all scene creation/registration requests.  Use cryptographic signatures or shared secrets to verify the origin of these requests.
    *   **Service Discovery Hardening:** If `ET` uses a service discovery mechanism, secure it to prevent unauthorized scene registration.
    *   **Input Validation:** Rigorously validate all data received during scene registration, checking for unexpected values or malicious payloads.
    *   **Code Review:**  Thoroughly review the `ET.Scene` and `ET.NetworkComponent` code for vulnerabilities related to scene management.

## Threat: [Unit Component Hijacking](./threats/unit_component_hijacking.md)

*   **Description:** An attacker exploits a vulnerability in the `ET.Unit` component's message handling or state management to take control of an existing Unit (e.g., a player character or NPC). This might involve sending a malformed message that overwrites the Unit's internal data or triggers unexpected behavior.  The attacker could target specific `ET.Component` instances attached to the Unit (e.g., `MoveComponent`, `AttributeComponent`).
*   **Impact:** The attacker gains control of a specific game entity, allowing them to cheat, disrupt other players, or potentially escalate privileges by exploiting further vulnerabilities within the hijacked Unit.
*   **Affected ET Component:** `ET.Unit`, specific `ET.Component` instances (e.g., `MoveComponent`, `AttributeComponent`), `ET.MessageHandler` (if message handling is vulnerable).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:**  Strictly validate all messages sent to `ET.Unit` components, ensuring data types and values are within expected ranges.
    *   **State Management Security:**  Protect the internal state of `ET.Unit` components from unauthorized modification.  Use access control mechanisms and consider immutable data structures where appropriate.
    *   **Server-Side Authority:**  Enforce server-side authority for all actions performed by Units.  Don't trust client-provided data without validation.
    *   **Fuzzing:** Fuzz test the message handlers for `ET.Unit` and its components to identify potential vulnerabilities.

## Threat: [Message Interception and Modification (KCP/TCP)](./threats/message_interception_and_modification__kcptcp_.md)

*   **Description:** `ET` supports both KCP (a reliable UDP protocol) and TCP.  If encryption is not properly implemented or configured for either protocol, an attacker could use a network sniffer to intercept messages and potentially modify them in transit.  This is particularly relevant for messages handled by `ET.NetworkComponent` and its associated protocol-specific handlers (e.g., `ET.KChannel`, `ET.TChannel`).
*   **Impact:** The attacker can eavesdrop on game communication, potentially revealing sensitive information (player positions, chat messages, etc.).  Modification of messages could allow cheating, data corruption, or denial-of-service attacks.
*   **Affected ET Component:** `ET.NetworkComponent`, `ET.KChannel` (for KCP), `ET.TChannel` (for TCP), `ET.AService` (base class for network services).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Mandatory TLS:** Enforce the use of TLS (Transport Layer Security) for *all* network communication, both KCP and TCP.  Do not allow unencrypted connections.
    *   **Certificate Validation:**  Implement strict certificate validation to prevent man-in-the-middle attacks.
    *   **Configuration Review:**  Carefully review the network configuration settings in `ET` to ensure that encryption is enabled and properly configured.

## Threat: [Message Flooding (DoS)](./threats/message_flooding__dos_.md)

*   **Description:** An attacker sends a large volume of messages to the server, targeting specific `ET.MessageHandler` instances or the `ET.NetworkComponent` in general.  This could overwhelm the server's processing capacity, leading to a denial of service.  The attacker might exploit the lack of rate limiting in `ET.MessageDispatcher`.
*   **Impact:** The game server becomes unresponsive, preventing legitimate players from connecting or playing the game.
*   **Affected ET Component:** `ET.NetworkComponent`, `ET.MessageDispatcher`, `ET.MessageHandler` instances, potentially `ET.AService`.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Rate Limiting:** Implement rate limiting at multiple levels: per IP address, per client session, and per message type.  Use `ET`'s built-in mechanisms if available, or implement custom rate limiting logic.
    *   **Connection Throttling:** Limit the number of concurrent connections from a single IP address or client.
    *   **Resource Monitoring:** Monitor server resource usage (CPU, memory, network bandwidth) to detect and respond to potential DoS attacks.

