# Attack Surface Analysis for apache/httpcomponents-client

## Attack Surface: [Insecure SSL/TLS Configuration](./attack_surfaces/insecure_ssltls_configuration.md)

*   **Description:** Failure to properly configure SSL/TLS settings within HttpComponents Client, leading to weakened or bypassed encryption and verification. This is the most direct and critical risk.
    *   **HttpComponents-Client Contribution:** The library provides the mechanisms for SSL/TLS configuration.  Misuse of these mechanisms *directly* creates the vulnerability.
    *   **Example:**
        ```java
        // DANGEROUS: Disables hostname verification AND trusts all certificates
        CloseableHttpClient client = HttpClients.custom()
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .setSSLContext(new SSLContextBuilder()
                        .loadTrustMaterial(null, new TrustAllStrategy())
                        .build())
                .build();
        ```
    *   **Impact:** Man-in-the-Middle (MITM) attacks.  Complete compromise of communication confidentiality and integrity, allowing attackers to intercept, modify, or steal sensitive data.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Use `DefaultHostnameVerifier`:**  Always use the `DefaultHostnameVerifier`.  Avoid `NoopHostnameVerifier`.
        *   **Enable Certificate Validation:** Never disable certificate validation.  Avoid `TrustAllStrategy` or custom `TrustStrategy` implementations that bypass validation.
        *   **Use Strong Cipher Suites:** Rely on the library's default cipher suite selection (which prioritizes strong ciphers in modern versions) or explicitly configure a list of known-good, strong cipher suites.
        *   **Enforce TLS 1.2 or 1.3:** Explicitly configure the client to use TLS 1.2 or 1.3.  Disable older, vulnerable protocols.
        *   **Implement Certificate Revocation Checks:** Configure OCSP or CRL checking.
        *   **Proper Truststore/Keystore Management:** If using custom truststores/keystores, ensure they are correctly configured and protected.

## Attack Surface: [Connection Pool Misconfiguration (Resource Exhaustion)](./attack_surfaces/connection_pool_misconfiguration__resource_exhaustion_.md)

*   **Description:** Incorrect configuration of the connection pool *within HttpComponents Client*, leading to resource exhaustion and denial-of-service.
    *   **HttpComponents-Client Contribution:** The library's connection pool is the direct source of this vulnerability if misconfigured.
    *   **Example:**
        ```java
        // DANGEROUS: Unlimited connections and long timeouts
        PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager();
        cm.setMaxTotal(Integer.MAX_VALUE);
        cm.setDefaultMaxPerRoute(Integer.MAX_VALUE);
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(Timeout.ofMinutes(30)) // Extremely long timeout
                .setConnectionRequestTimeout(Timeout.ofMinutes(30))
                .setSocketTimeout(Timeout.ofMinutes(30))
                .build();
        CloseableHttpClient client = HttpClients.custom()
                .setConnectionManager(cm)
                .setDefaultRequestConfig(config)
                .build();
        ```
    *   **Impact:** Denial-of-Service (DoS). The application becomes unresponsive due to exhausted connection resources.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Set Reasonable Connection Limits:** Configure `setMaxTotal` and `setDefaultMaxPerRoute` to appropriate values based on expected load and server capacity.
        *   **Configure Timeouts:** Set appropriate, *non-excessive* connection timeouts (`setConnectTimeout`, `setSocketTimeout`, `setConnectionRequestTimeout`).
        *   **Enable Stale Connection Checks:** Use `setValidateAfterInactivity` to periodically check for and close stale connections.

