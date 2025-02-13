# Threat Model Analysis for bang590/jspatch

## Threat: [Malicious Script Injection via MitM](./threats/malicious_script_injection_via_mitm.md)

*   **Description:** An attacker intercepts the network communication between the app and the JSPatch script server. The attacker replaces the legitimate JSPatch script with a malicious one during the download process. This leverages JSPatch's core functionality of downloading and executing scripts.
    *   **Impact:** Complete application compromise. The attacker's script can execute arbitrary Objective-C code, leading to data theft, resource abuse, and full control over the app's behavior within its granted permissions.
    *   **JSPatch Component Affected:** The script download and execution mechanism. Specifically, `[JPEngine startWithAppKey:]` and related methods, culminating in the `evalString:` function.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **HTTPS with Certificate Pinning:** Enforce HTTPS and implement certificate pinning to ensure the app only communicates with the legitimate server, preventing MitM attacks.
        *   **Code Signing and Verification:** Digitally sign JSPatch scripts. The app must verify the signature against a trusted, embedded public key *before* execution.
        *   **Hash Verification:** Calculate a strong cryptographic hash (e.g., SHA-256) of the legitimate script. The app downloads the hash via a *separate*, secure channel (with certificate pinning) and compares it to the downloaded script's hash before execution.

## Threat: [Malicious Script Injection via Server Compromise](./threats/malicious_script_injection_via_server_compromise.md)

*   **Description:** An attacker gains unauthorized access to the server hosting the JSPatch scripts and replaces a legitimate script with a malicious one. This directly impacts JSPatch's script delivery mechanism.
    *   **Impact:** Widespread application compromise, affecting all users who download the compromised script.  This leads to the same severe consequences as the MitM attack.
    *   **JSPatch Component Affected:** The server-side script storage and delivery. The client-side `evalString:` function is the ultimate execution point.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Server Security Best Practices:** Implement robust server security (access controls, audits, intrusion detection, vulnerability scanning).
        *   **Code Signing and Verification (as above):** Code signing prevents malicious script deployment even with server compromise, *unless* the private key is also stolen.
        *   **Patch Revocation (Kill Switch):** Implement a mechanism to remotely disable JSPatch functionality (e.g., a server-side flag).
        *   **Versioned Patches:** Allow the app to request a specific patch version, enabling rollback to a known-good version.

## Threat: [Unauthorized Patch Deployment (Insider Threat)](./threats/unauthorized_patch_deployment__insider_threat_.md)

*   **Description:** A malicious or negligent developer with access to the JSPatch deployment system pushes a malicious script. This bypasses standard app update processes and directly utilizes JSPatch's deployment capabilities.
    *   **Impact:** Application compromise, potentially affecting all users, with the severity depending on the malicious script's actions.
    *   **JSPatch Component Affected:** The patch management and deployment process. The `evalString:` function is the execution point.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Access Controls:** Limit access to the JSPatch deployment system.
        *   **Mandatory Code Review:** Require code review and approval from multiple developers *before* any JSPatch deployment.
        *   **Audit Logging:** Maintain a detailed audit log of all deployments.
        *   **Two-Factor Authentication:** Enforce two-factor authentication for access to the deployment system.

