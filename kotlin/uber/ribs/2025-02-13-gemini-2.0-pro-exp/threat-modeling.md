# Threat Model Analysis for uber/ribs

## Threat: [Rogue RIB Injection](./threats/rogue_rib_injection.md)

*   **Threat:** Rogue RIB Injection
    *   **Description:** An attacker exploits a vulnerability in the RIB attachment mechanism (e.g., a misconfigured `Builder`, a flaw in the `Router`'s attachment logic, or a compromised dependency injection setup) to inject a maliciously crafted RIB into the application's RIB tree.  This is *not* about XSS in a webview *within* a RIB, but rather the injection of the *entire RIB itself*.
    *   **Impact:**
        *   Data theft (accessing data from other RIBs).
        *   User impersonation (performing actions on behalf of the user).
        *   Complete control of a portion of the application's flow.
        *   Potential for privilege escalation (if the injected RIB can attach to a higher-privilege parent).
    *   **Affected RIBs Component:** `Router` (attachment logic), `Builder` (creation logic), Dependency Injection framework (e.g., Dagger configuration).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict RIB Builder Validation:** Implement rigorous validation within *all* `Builder` classes to ensure only authorized RIBs can be created and attached.  This includes verifying the caller's context and permissions, *not just input data*.
        *   **Secure Dependency Injection:** Harden the dependency injection configuration (e.g., Dagger modules) to prevent attackers from injecting malicious components that could facilitate RIB injection.  Avoid dynamic loading of modules from untrusted sources.
        *   **Runtime Hierarchy Monitoring:** Implement a mechanism to monitor the RIB tree at runtime and detect unexpected attachments. This is a *defense-in-depth* measure, assuming other controls might fail.
        *   **Code Reviews:** Conduct thorough code reviews, focusing specifically on RIB creation, attachment, and the security of the dependency injection setup.

## Threat: [Message Bus Sniffing/Tampering (RIB-to-RIB Communication)](./threats/message_bus_sniffingtampering__rib-to-rib_communication_.md)

*   **Threat:** Message Bus Sniffing/Tampering (RIB-to-RIB Communication)
    *   **Description:** An attacker gains access to the message bus (e.g., RxJava stream) used for *inter-RIB communication*. This is *not* about general network sniffing, but about a compromised RIB or a flaw in the RIBs-specific message bus implementation allowing unauthorized access to messages *between RIBs*. The attacker can eavesdrop on messages (sniffing) or modify them in transit (tampering).
    *   **Impact:**
        *   Information disclosure (reading sensitive data passed *between RIBs*).
        *   Data corruption (modifying data in transit *between RIBs*).
        *   Unexpected application behavior (triggering unintended actions within other RIBs).
        *   Bypassing security checks (if messages are used for authorization between RIBs).
    *   **Affected RIBs Component:** `Interactor` (message sending/receiving logic), `Router` (if messages are used for navigation between RIBs), Message Bus implementation (e.g., RxJava, specifically how it's used *within* the RIBs framework).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Message Encryption:** Encrypt sensitive data transmitted over the RIBs message bus using a strong encryption algorithm. This is crucial for *inter-RIB* communication.
        *   **Message Authentication:** Implement message signing or MAC (Message Authentication Code) to ensure message integrity and authenticity *between RIBs*. Verify signatures before processing messages within a RIB.
        *   **Access Control Lists (ACLs):** Define strict ACLs for the RIBs message bus. Only authorized RIBs should be able to publish or subscribe to specific message types. This is a *RIBs-specific* access control mechanism.
        *   **Secure Message Bus Implementation:** Ensure the message bus implementation used *within* the RIBs framework is configured securely and provides built-in security features (if available).
        *   **Minimize Sensitive Data:** Avoid transmitting highly sensitive data directly over the message bus. Consider passing references or identifiers instead, and retrieving the actual data within the receiving RIB using appropriate security checks.

## Threat: [Interactor State Corruption (Direct Manipulation)](./threats/interactor_state_corruption__direct_manipulation_.md)

*   **Threat:** Interactor State Corruption (Direct Manipulation)
    *   **Description:** An attacker *directly* modifies the internal state of an `Interactor`, bypassing the intended business logic. This is *not* about typical input validation failures, but about exploiting a vulnerability that allows direct access to the Interactor's memory or using reflection to bypass access modifiers. This is a RIBs-specific concern because the Interactor is a core architectural component.
    *   **Impact:**
        *   Data inconsistency within the RIB's scope.
        *   Violation of business rules enforced by the Interactor.
        *   Unauthorized actions performed by the Interactor.
        *   Potential for privilege escalation (if the Interactor controls access to sensitive resources).
    *   **Affected RIBs Component:** `Interactor` (specifically, its internal state variables and methods).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Immutability:** Make the `Interactor`'s state immutable whenever possible. This is the *most effective* mitigation. Use immutable data structures.
        *   **Encapsulation:** Strictly enforce encapsulation. Make state variables `private` and provide access only through well-defined methods. Avoid exposing mutable objects. This is a fundamental principle, but crucial in the RIBs context.
        *   **Defensive Programming:** Use defensive programming techniques (e.g., assertions, preconditions, postconditions) to ensure the `Interactor`'s state remains valid, even if unexpected input is received.
        *   **Code Reviews:** Thoroughly review `Interactor` code, specifically looking for any potential ways to bypass the intended access controls and modify the state directly.

## Threat: [Router Hijacking (RIB Navigation Control)](./threats/router_hijacking__rib_navigation_control_.md)

*   **Threat:** Router Hijacking (RIB Navigation Control)
    *   **Description:** An attacker manipulates the `Router`'s state (e.g., the navigation stack) to redirect the user to a malicious RIB or bypass security checks *within the RIBs hierarchy*. This is *not* about general deep link vulnerabilities, but about exploiting flaws in the `Router`'s logic or tampering with data passed *between RIBs* that affects routing decisions.
    *   **Impact:**
        *   Redirection to malicious RIBs (potentially leading to phishing or data theft).
        *   Bypassing authentication or authorization checks implemented within the RIBs flow.
        *   Accessing unauthorized features or data within other RIBs.
    *   **Affected RIBs Component:** `Router` (specifically, its state management and navigation logic).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Secure Navigation Stack:** Treat the `Router`'s navigation stack as highly sensitive data. Protect it from unauthorized modification. This is a *RIBs-specific* concern.
        *   **Input Validation (Internal):** Validate all input that affects the `Router`'s state, *even data passed from other RIBs*. Do not assume that data from other RIBs is trustworthy.
        *   **Whitelist Navigation Targets:** Maintain a whitelist of allowed navigation targets (RIBs) and prevent navigation to unauthorized destinations. This is a *RIBs-specific* whitelist.
        *   **Avoid Exposing Router Internals:** Do not expose the `Router`'s internal state or implementation details. Provide a well-defined and secure API for interacting with the Router *from other RIBs*.
        *   **Code Reviews:** Focus code reviews on the `Router`'s navigation logic and state management, paying particular attention to how it handles data received from other RIBs.

