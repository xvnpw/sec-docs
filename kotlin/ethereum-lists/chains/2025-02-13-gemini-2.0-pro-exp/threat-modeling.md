# Threat Model Analysis for ethereum-lists/chains

## Threat: [Malicious RPC Endpoint Injection](./threats/malicious_rpc_endpoint_injection.md)

*   **1. Threat: Malicious RPC Endpoint Injection**

    *   **Description:** An attacker (malicious maintainer, compromised repository, or MITM) modifies the `rpc` field in a chain's JSON entry to point to a malicious RPC server. The attacker can then:
        *   Return fake transaction confirmations.
        *   Return incorrect balance information.
        *   Steal private keys (if signing requests are sent to the RPC).
        *   Submit malicious transactions (if the RPC is used for broadcasting).
        *   Conduct denial-of-service.
        *   Phish users via the RPC.

    *   **Impact:**
        *   Loss of user funds.
        *   Compromise of user private keys.
        *   Application malfunction.
        *   Exposure of sensitive data.
        *   Reputational damage.

    *   **Affected Component:**
        *   The `rpc` array within individual chain objects in the JSON files (e.g., `_data/chains/eip155-1.json`).
        *   The application's RPC connection module/function.

    *   **Risk Severity:** Critical

    *   **Mitigation Strategies:**
        *   **Cross-Verification:** Validate RPC endpoints against *multiple* independent, trusted sources.
        *   **Endpoint Allowlisting:** Maintain a separate, secure allowlist of trusted RPC endpoints.
        *   **Regular Audits:** Periodically audit the chain data.
        *   **RPC Monitoring:** Implement monitoring and rate limiting on RPC calls.
        *   **User Confirmation:** Require explicit user confirmation for sensitive operations, showing the RPC endpoint.
        *   **Sandboxing:** Isolate RPC communication (if feasible).
        *   **Dynamic Validation:** After connecting, query the node for its `chainId` and compare it to expected values.

## Threat: [Incorrect Chain ID](./threats/incorrect_chain_id.md)

*   **2. Threat: Incorrect Chain ID**

    *   **Description:** An attacker (or through error) modifies the `chainId` field. The goal is to cause replay attacks or application malfunction. They might:
        *   Set the `chainId` to match another chain to enable replay attacks.
        *   Set it to a non-existent value to cause connection errors.

    *   **Impact:**
        *   Replay attacks (loss of funds).
        *   Application malfunction.
        *   Inability to connect to the intended chain.

    *   **Affected Component:**
        *   The `chainId` field within individual chain objects.
        *   The application's chain selection and connection logic.

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **EIP-155 Protection:** *Always* sign transactions using EIP-155.
        *   **Chain ID Validation:** After connecting, verify the chain ID returned by the node (`eth_chainId`) against the expected ID. Do *not* rely solely on the `chainId` from `ethereum-lists/chains`.
        *   **Cross-Verification:** Verify the `chainId` against multiple sources.

## Threat: [DNS Hijacking / Man-in-the-Middle (MITM) - Leading to Malicious Chain Data Injection](./threats/dns_hijacking__man-in-the-middle__mitm__-_leading_to_malicious_chain_data_injection.md)

*   **3. Threat: DNS Hijacking / Man-in-the-Middle (MITM) - Leading to Malicious Chain Data Injection**

    *   **Description:**  While not *directly* manipulating the repository, a MITM attack allows an attacker to *inject* malicious chain data (like a bad RPC or incorrect Chain ID) *as if* it came from the repository. This is a *delivery mechanism* for the above two threats. The attacker intercepts network traffic and provides altered data.

    *   **Impact:** Identical to the impacts of Malicious RPC Endpoint Injection or Incorrect Chain ID, depending on what data the attacker modifies.

    *   **Affected Component:**
        *   Network communication between the application and GitHub/DNS.
        *   Potentially *any* field within the chain data.

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **HTTPS:** Ensure HTTPS communication with GitHub.
        *   **Certificate Pinning:** Consider certificate pinning (advanced).
        *   **DNSSEC:** Encourage DNSSEC (outside application control).
        *   **Local Caching with Integrity Checks:** Cache data locally and use checksums/signatures to verify integrity.
        *   **Out-of-Band Verification:** For very high security, verify data through a separate channel.

## Threat: [Supply Chain Attack on Dependencies - Leading to Malicious Chain Data Injection](./threats/supply_chain_attack_on_dependencies_-_leading_to_malicious_chain_data_injection.md)

*    **4. Threat: Supply Chain Attack on Dependencies - Leading to Malicious Chain Data Injection**
    *   **Description:** A compromised dependency used to fetch/parse chain data injects malicious information (like a bad RPC or incorrect Chain ID) *before* the application can validate it. This is another *delivery mechanism*.

    *   **Impact:** Identical to the impacts of Malicious RPC Endpoint Injection or Incorrect Chain ID, depending on the injected data.

    *   **Affected Component:**
        *   Libraries used to fetch/parse data from `ethereum-lists/chains`.
        *   Potentially *any* field within the chain data.

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Dependency Auditing:** Regularly audit dependencies.
        *   **Dependency Pinning:** Pin dependencies to specific versions.
        *   **SBOM:** Maintain a Software Bill of Materials.
        *   **Vulnerability Scanning:** Use vulnerability scanning tools.
        *   **Code Review:** Thoroughly review in-house fetching/parsing code.

