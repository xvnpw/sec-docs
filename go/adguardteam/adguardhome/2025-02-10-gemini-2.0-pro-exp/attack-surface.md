# Attack Surface Analysis for adguardteam/adguardhome

## Attack Surface: [DNS Cache Poisoning (Targeting AdGuard Home's Resolver)](./attack_surfaces/dns_cache_poisoning__targeting_adguard_home's_resolver_.md)

*   **Description:** An attacker injects forged DNS records into AdGuard Home's cache, causing it to return incorrect IP addresses for domain names.
*   **AdGuard Home Contribution:** AdGuard Home acts as a recursive DNS resolver, making its cache a target.  Vulnerabilities in *its* DNS handling logic are the key concern.
*   **Example:** An attacker sends specially crafted DNS responses to AdGuard Home, causing it to cache a malicious IP address for `bank.com`.
*   **Impact:** Users are redirected to a phishing site, potentially leading to credential theft or malware infection.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **(Developers):** Rigorous input validation and sanitization of DNS responses within the resolver.  Thorough testing for cache poisoning vulnerabilities.  Ensure DNSSEC validation is correctly implemented and robust.
    *   **(Users):** Keep AdGuard Home updated to the latest version.  Use reputable upstream DNS servers with DoT/DoH enabled.  Monitor for unusual DNS resolution behavior.

## Attack Surface: [Upstream DNS Server Compromise](./attack_surfaces/upstream_dns_server_compromise.md)

*   **Description:** An attacker compromises or manipulates one of the upstream DNS servers that AdGuard Home uses.
*   **AdGuard Home Contribution:** AdGuard Home relies on external DNS servers for resolution. It's a *conduit* for the compromised data, and its configuration choices directly impact this risk.
*   **Example:** An attacker compromises a public DNS server, causing it to return malicious records.  AdGuard Home, using that server, propagates the malicious data.
*   **Impact:** Widespread redirection of traffic to malicious sites, affecting all users relying on AdGuard Home.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **(Developers):** Provide clear guidance and tools for users to configure multiple, diverse, and trusted upstream servers.  Promote the use of DoT/DoH and make configuration straightforward.
    *   **(Users):** Use a diverse set of reputable upstream DNS servers (e.g., Quad9, Cloudflare, Google).  Enable DoT/DoH for all upstream connections.  Avoid relying solely on a single provider.

## Attack Surface: [Filter List Poisoning/Manipulation](./attack_surfaces/filter_list_poisoningmanipulation.md)

*   **Description:** An attacker provides a malicious filter list to AdGuard Home, causing it to block legitimate sites or allow malicious ones.
*   **AdGuard Home Contribution:** AdGuard Home's core function is to apply filter lists to DNS queries.  The *mechanism for fetching and applying lists* is the attack surface, directly within AdGuard Home's control.
*   **Example:** An attacker compromises a filter list provider, inserting rules that block access to security update servers or allow access to known phishing domains.
*   **Impact:** Disruption of legitimate services, increased exposure to malware, or circumvention of security controls.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **(Developers):** Implement integrity checks (e.g., checksums, signatures) for downloaded filter lists.  Provide a curated list of trusted filter list sources.  Implement robust error handling for malformed filter lists.
    *   **(Users):** Use only reputable and well-maintained filter list sources.  Be cautious about adding custom filter lists from untrusted sources.  Monitor for unexpected blocking or allowing of websites.

## Attack Surface: [Authentication Bypass (Web Interface/API)](./attack_surfaces/authentication_bypass__web_interfaceapi_.md)

*   **Description:** An attacker gains unauthorized access to AdGuard Home's web interface or API, bypassing authentication.
*   **AdGuard Home Contribution:** AdGuard Home provides a web interface and API for management.  Vulnerabilities in *these interfaces'* authentication mechanisms are the concern, directly within AdGuard Home's code.
*   **Example:** An attacker exploits a vulnerability in the web interface's login form to gain administrative access.
*   **Impact:** Complete control over AdGuard Home's configuration, allowing the attacker to redirect traffic, disable filtering, or exfiltrate data.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **(Developers):** Implement strong authentication mechanisms (e.g., using well-vetted libraries).  Enforce strong password policies.  Implement multi-factor authentication (MFA).  Regularly audit the authentication code.  Rate-limit login attempts.
    *   **(Users):** Use strong, unique passwords.  Enable MFA if available.  Consider placing the web interface behind a reverse proxy with additional security measures.

## Attack Surface: [API Abuse/Configuration Manipulation](./attack_surfaces/api_abuseconfiguration_manipulation.md)

*   **Description:** An attacker uses the AdGuard Home API to modify its configuration without authorization.
*   **AdGuard Home Contribution:** The API provides programmatic access to AdGuard Home's functionality.  Weaknesses in *API security* are the issue, directly within AdGuard Home's design and implementation.
*   **Example:** An attacker discovers an exposed API key and uses it to add malicious entries to the filter lists.
*   **Impact:** Similar to authentication bypass – control over DNS resolution, filtering, and settings.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **(Developers):** Secure API keys and authentication.  Implement strict access controls and authorization for API endpoints.  Validate all API input.  Implement rate limiting.
    *   **(Users):** Protect API keys carefully.  Regularly review API usage logs.

## Attack Surface: [Denial-of-Service (DoS) against AdGuard Home](./attack_surfaces/denial-of-service__dos__against_adguard_home.md)

*   **Description:** An attacker floods AdGuard Home with requests, making it unresponsive and disrupting DNS resolution for the network.
*   **AdGuard Home Contribution:** AdGuard Home is the central DNS server.  Its *availability* is critical, and its internal handling of requests determines its resilience to DoS.
*   **Example:** An attacker sends a large number of DNS queries to AdGuard Home, overwhelming its resources.
*   **Impact:** Loss of DNS resolution, preventing users from accessing the internet.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **(Developers):** Implement rate limiting for DNS queries, API requests, and web interface access.  Optimize code for performance and resource usage.  Implement robust error handling.
    *   **(Users):** Configure a firewall to limit incoming DNS traffic to trusted sources.  Monitor AdGuard Home's resource usage.  Consider using a load balancer or other infrastructure to improve resilience (although this is less *direct* involvement).

## Attack Surface: [Dependency Vulnerabilities](./attack_surfaces/dependency_vulnerabilities.md)

*   **Description:** Vulnerabilities in third-party libraries or components used by AdGuard Home.
*   **AdGuard Home Contribution:** AdGuard Home, like any software, relies on external dependencies. The choice and management of these dependencies are directly within the AdGuard Home project's control.
*   **Example:** A vulnerability is discovered in a networking library used by AdGuard Home, allowing for remote code execution.
*   **Impact:** Varies depending on the specific vulnerability, but could range from information disclosure to complete system compromise.
*   **Risk Severity:** **High** to **Critical** (depending on the dependency vulnerability)
*   **Mitigation Strategies:**
    *   **(Developers):** Regularly update dependencies to their latest secure versions. Use software composition analysis (SCA) tools to identify and track vulnerable dependencies. Implement a robust vulnerability management process.
    *   **(Users):** Keep AdGuard Home updated to the latest version, which should include updated dependencies.

