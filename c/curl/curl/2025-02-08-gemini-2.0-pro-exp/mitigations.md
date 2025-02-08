# Mitigation Strategies Analysis for curl/curl

## Mitigation Strategy: [Protocol Restrictions](./mitigation_strategies/protocol_restrictions.md)

*   **Description:**
    1.  **Identify Required Protocols:** Determine the specific protocols your application *absolutely* needs (e.g., only HTTPS).
    2.  **Configure `libcurl`:**  In your application code, use the `CURLOPT_PROTOCOLS` option with `curl_easy_setopt`.  Pass a bitmask of allowed protocols (e.g., `CURLPROTO_HTTPS`).  Example (C):
        ```c
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        ```
    3.  **Command-Line (if applicable):** If using the `curl` command-line tool, use the `--proto` option: `curl --proto https ...`.
    4.  **Regular Review:** Periodically review the allowed protocols and update the configuration if requirements change.
    5. **Redirection Protocol Control:** If redirects are allowed, use `CURLOPT_REDIR_PROTOCOLS` to restrict the protocols allowed *after* a redirect. This prevents a redirect from HTTPS to a less secure protocol like HTTP. Example (C):
        ```c
        curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
        ```

*   **Threats Mitigated:**
    *   **Protocol Downgrade Attacks:** (Severity: High)
    *   **Unexpected Protocol Exploitation:** (Severity: Medium to High)
    *   **Server-Side Request Forgery (SSRF) via Protocol Smuggling:** (Severity: High)

*   **Impact:**
    *   **Protocol Downgrade Attacks:** Risk reduced to near zero.
    *   **Unexpected Protocol Exploitation:** Risk significantly reduced.
    *   **SSRF via Protocol Smuggling:** Risk significantly reduced.

*   **Currently Implemented:**  (Example) Implemented in `network_module.c` using `CURLOPT_PROTOCOLS`.  Restricted to HTTPS only.

*   **Missing Implementation:** (Example) Missing implementation for command-line scripts. Missing restriction of redirect protocols.

## Mitigation Strategy: [Hostname Verification and Certificate Pinning](./mitigation_strategies/hostname_verification_and_certificate_pinning.md)

*   **Description:**
    1.  **Enable Hostname Verification:** Ensure `CURLOPT_SSL_VERIFYHOST` is set to 2 (the default).  Example (C):
        ```c
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        ```
    2.  **(Optional) Certificate Pinning:**
        *   **Obtain Public Key Hash:** Obtain the SHA256 hash of the expected public key.
        *   **Configure Pinning:** Use `CURLOPT_PINNEDPUBLICKEY`.  Example (C):
            ```c
            curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, "sha256//your_public_key_hash");
            ```
        *   **Update Mechanism:** Implement a secure update mechanism.

*   **Threats Mitigated:**
    *   **Man-in-the-Middle (MitM) Attacks:** (Severity: High)
    *   **Certificate Authority (CA) Compromise:** (Severity: High)

*   **Impact:**
    *   **MitM Attacks:** Hostname verification significantly reduces risk.  Pinning provides stronger protection.
    *   **CA Compromise:** Pinning significantly reduces risk for pinned domains.

*   **Currently Implemented:** (Example) Hostname verification is enabled.

*   **Missing Implementation:** (Example) Certificate pinning is not implemented.

## Mitigation Strategy: [Handling Redirects Securely](./mitigation_strategies/handling_redirects_securely.md)

*   **Description:**
    1.  **Limit Redirects:** Set a limit with `CURLOPT_MAXREDIRS`.  Example (C):
        ```c
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
        ```
    2.  **Disable Automatic Redirects (Optional):** Use `CURLOPT_FOLLOWLOCATION` set to 0.
    3.  **Manual Redirect Handling (If Necessary):**
        *   Use `curl_easy_getinfo` with `CURLINFO_REDIRECT_URL`.
    4. **Restrict Redirect Protocols:** Use `CURLOPT_REDIR_PROTOCOLS`.

*   **Threats Mitigated:**
    *   **Open Redirects:** (Severity: Medium)
    *   **Protocol Downgrade Attacks (via Redirects):** (Severity: High)
    *   **Infinite Redirect Loops:** (Severity: Low)

*   **Impact:**
    *   **Open Redirects:** Risk reduced.
    *   **Protocol Downgrade Attacks:** Risk reduced.
    *   **Infinite Redirect Loops:** Risk eliminated.

*   **Currently Implemented:** (Example) `CURLOPT_MAXREDIRS` is set to 10.

*   **Missing Implementation:** (Example) Automatic redirects are enabled. Redirect protocols are not restricted.

## Mitigation Strategy: [Timeout Management](./mitigation_strategies/timeout_management.md)

*   **Description:**
    1.  **Connection Timeout:** Set with `CURLOPT_CONNECTTIMEOUT`.  Example (C):
        ```c
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        ```
    2.  **Total Request Timeout:** Set with `CURLOPT_TIMEOUT`.  Example (C):
        ```c
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        ```
    3.  **(Optional) Low-Speed Timeouts:** Use `CURLOPT_LOW_SPEED_LIMIT` and `CURLOPT_LOW_SPEED_TIME`.

*   **Threats Mitigated:**
    *   **Denial-of-Service (DoS) Attacks:** (Severity: Medium)

*   **Impact:**
    *   **DoS Attacks:** Risk significantly reduced.

*   **Currently Implemented:** (Example) `CURLOPT_TIMEOUT` is set to 60 seconds.

*   **Missing Implementation:** (Example) `CURLOPT_CONNECTTIMEOUT` is not set.  Low-speed timeouts are not implemented.

## Mitigation Strategy: [Disable Unnecessary Features](./mitigation_strategies/disable_unnecessary_features.md)

*   **Description:**
    1.  **Review `libcurl` Options:** Review all `libcurl` options.
    2.  **Disable Unused Options:**  Disable any options that are not strictly necessary.  Examples:
        *   Cookies: `CURLOPT_COOKIEFILE` set to "" or unset.
        *   Custom Headers: Avoid `CURLOPT_HTTPHEADER` if not needed.
        *   HTTP Authentication: Avoid `CURLOPT_USERPWD` and `CURLOPT_HTTPAUTH` if not needed.
    3.  **Principle of Least Privilege:** Only enable required features.

*   **Threats Mitigated:**
    *   **Various (depending on the disabled feature):** (Severity: Low to Medium)

*   **Impact:**
    *   **Various:** Reduces the overall attack surface.

*   **Currently Implemented:** (Example) No specific effort has been made.

*   **Missing Implementation:** (Example) A comprehensive review of `libcurl` options is needed.

## Mitigation Strategy: [Keep `libcurl` Updated](./mitigation_strategies/keep__libcurl__updated.md)

*   **Description:**
    1.  **Package Manager:** Use a package manager with security updates.
    2.  **Monitor Advisories:** Monitor `curl` security advisories.
    3.  **Prompt Updates:** Apply updates promptly.
    4.  **Dependency Management:** Consider a dependency management system.

*   **Threats Mitigated:**
    *   **Known Vulnerabilities:** (Severity: Varies, potentially High)

*   **Impact:**
    *   **Known Vulnerabilities:** Risk significantly reduced.

*   **Currently Implemented:** (Example) The system uses a package manager.

*   **Missing Implementation:** (Example)  No automated system for monitoring advisories.

