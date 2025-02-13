# Attack Surface Analysis for square/okhttp

## Attack Surface: [TLS/SSL Misconfiguration](./attack_surfaces/tlsssl_misconfiguration.md)

*Description:* Incorrect TLS/SSL settings within OkHttp can expose communications to interception and manipulation.  This is the most critical area.
*OkHttp Contribution:* OkHttp provides extensive TLS/SSL configuration options (e.g., `ConnectionSpec`, `CertificatePinner`, custom `TrustManager`, custom `HostnameVerifier`).  Incorrect use of *any* of these creates the vulnerability.
*Example:* Using a custom `TrustManager` that doesn't properly validate certificates (e.g., accepts all certificates), or allowing weak cipher suites via an improperly configured `ConnectionSpec`, or a flawed `HostnameVerifier`.
*Impact:*  Man-in-the-middle (MitM) attacks, data interception, data modification.  Complete compromise of communication security.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Strongly prefer** using the system's default `TrustManager` and `HostnameVerifier`.  Avoid custom implementations unless absolutely necessary and you have deep expertise in TLS.
    *   Explicitly configure `ConnectionSpec` to use *only* strong cipher suites and TLS 1.2 or 1.3.  *Never* allow known weak ciphers or outdated TLS versions.  Use `ConnectionSpec.RESTRICTED_TLS` as a starting point.
    *   If using certificate pinning (via `CertificatePinner`), implement it *correctly* and thoroughly test it.  Have a robust plan for pin updates and handling pin failures.  Incorrect pinning is worse than no pinning.
    *   Regularly review and update TLS configurations based on current best practices and security advisories.
    *   Ensure the underlying platform (Android, Java) is up-to-date and configured securely, as OkHttp relies on platform-provided TLS capabilities.

## Attack Surface: [Protocol Downgrade Attacks (Controlled by OkHttp Configuration)](./attack_surfaces/protocol_downgrade_attacks__controlled_by_okhttp_configuration_.md)

*Description:* While the environment plays a role, OkHttp's configuration can *prevent* downgrades, making this a direct OkHttp concern.
*OkHttp Contribution:* OkHttp's `protocols()` method allows developers to explicitly control which HTTP versions are allowed.
*Example:*  The application doesn't explicitly set allowed protocols, allowing a MitM to force a downgrade to HTTP/1.1.
*Impact:* Increased susceptibility to request smuggling and other HTTP/1.1-specific attacks.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   Use `OkHttpClient.Builder.protocols()` to *explicitly* restrict the allowed protocols to `Protocol.HTTP_2` and/or `Protocol.H2_PRIOR_KNOWLEDGE` (if appropriate) and `Protocol.HTTP_3`.  *Do not* include `Protocol.HTTP_1_1` in the list unless absolutely necessary for compatibility with a specific, trusted server.  If you *must* support HTTP/1.1, ensure the server is well-configured to mitigate HTTP/1.1 vulnerabilities.

## Attack Surface: [Proxy Misconfiguration (Directly via OkHttp)](./attack_surfaces/proxy_misconfiguration__directly_via_okhttp_.md)

*Description:* Incorrect proxy settings *within OkHttp* can lead to traffic interception.
*OkHttp Contribution:* OkHttp allows configuring proxies via `OkHttpClient.Builder.proxy()` and `proxySelector()`.  The vulnerability lies in how these are used.
*Example:*  The application is configured to use a user-supplied proxy without validation, and the user provides a malicious proxy address.  Or, a hardcoded proxy is used without proper authentication.
*Impact:*  Traffic interception, data modification, redirection to malicious sites.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   *Never* allow users to directly configure the proxy used by OkHttp without *strict* validation and sanitization.  Ideally, avoid user-configurable proxies entirely.
    *   If a proxy is required, use a *known, trusted, and authenticated* proxy server.  Hardcode the proxy configuration if possible, and ensure the proxy server itself is secure.
    *   If using `proxySelector()`, ensure it handles proxy failures gracefully and *never* falls back to an insecure configuration (e.g., direct connection when a proxy is expected).

## Attack Surface: [Redirect Handling Vulnerabilities (Controlled by OkHttp)](./attack_surfaces/redirect_handling_vulnerabilities__controlled_by_okhttp_.md)

*Description:* OkHttp's redirect handling can be misused to follow malicious redirects.
*OkHttp Contribution:* OkHttp follows redirects by default, controlled by `followRedirects()` and `followSslRedirects()`.
*Example:*  A server returns a 302 redirect to a malicious URL, and OkHttp automatically follows it because redirects are enabled.
*Impact:*  Phishing attacks, malware distribution, exploitation of open redirects on trusted servers.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   If redirects are *not* needed, disable them with `followRedirects(false)` and `followSslRedirects(false)`. This is the safest option.
    *   If redirects *are* necessary, *validate* the `Location` header in the response *before* OkHttp follows the redirect.  Implement whitelisting of allowed redirect domains if possible.  Do *not* blindly follow redirects.
    *   Limit the number of redirects followed to prevent infinite loops (OkHttp has a default limit, but consider lowering it if appropriate).

## Attack Surface: [Header Injection (via OkHttp's Header Handling)](./attack_surfaces/header_injection__via_okhttp's_header_handling_.md)

*Description:*  Injecting malicious HTTP headers through OkHttp's request building.
*OkHttp Contribution:* OkHttp provides methods for setting request headers (e.g., `Headers.Builder`).  The vulnerability is in how user input is used with these methods.
*Example:*  An attacker provides a username containing newline characters and malicious header values, which are then included in a request header using `Headers.Builder.add()`.
*Impact:*  Request smuggling, response splitting, cache poisoning, session fixation.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   *Strictly* validate and sanitize *all* user-provided data *before* using it in HTTP headers.  Use OkHttp's `Headers.Builder` correctly, and ensure header names and values conform to RFC specifications.  *Never* construct headers from raw, unsanitized strings.
    *   Consider using a dedicated library for header sanitization to ensure thoroughness.  Assume *all* user input is potentially malicious.

