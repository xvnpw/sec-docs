# Threat Model Analysis for adguardteam/adguardhome

## Threat: [DNS Spoofing/Cache Poisoning via AdGuard Home Vulnerability](./threats/dns_spoofingcache_poisoning_via_adguard_home_vulnerability.md)

**Description:** An attacker exploits a vulnerability in AdGuard Home's DNS resolver to inject false DNS records into its cache. This can redirect users to malicious websites when they attempt to access legitimate domains.

**Impact:** Users are redirected to phishing sites, malware distribution points, or other malicious content, leading to data theft, malware infection, or financial loss.

**Affected Component:** DNS Resolver module

**Risk Severity:** High

**Mitigation Strategies:**
* Keep AdGuard Home updated to the latest version to patch known vulnerabilities.
* Implement DNSSEC validation within AdGuard Home if supported and applicable.
* Monitor AdGuard Home logs for suspicious DNS activity.

## Threat: [Filter List Injection/Manipulation via API Vulnerability](./threats/filter_list_injectionmanipulation_via_api_vulnerability.md)

**Description:** An attacker exploits an API vulnerability to inject malicious entries into AdGuard Home's filter lists or modify existing entries. This could allow malicious domains to bypass blocking or block legitimate resources.

**Impact:**  Malware and trackers are no longer blocked, exposing users to threats. Legitimate services or websites might become inaccessible, disrupting application functionality.

**Affected Component:** API, Filtering Engine module

**Risk Severity:** High

**Mitigation Strategies:**
* Implement strong authentication and authorization for AdGuard Home's API.
* Regularly audit and validate the integrity of the configured filter lists.
* Sanitize and validate any external input used to manage filter lists via the API.
* Keep AdGuard Home updated to patch API vulnerabilities.

## Threat: [Unauthorized Access to AdGuard Home Web Interface](./threats/unauthorized_access_to_adguard_home_web_interface.md)

**Description:** An attacker gains unauthorized access to AdGuard Home's web interface through weak credentials, brute-force attacks, or exploiting vulnerabilities in the authentication mechanism.

**Impact:** The attacker can modify AdGuard Home's settings, including disabling filtering, adding exceptions for malicious domains, accessing DNS query logs, or potentially gaining control over the server hosting AdGuard Home.

**Affected Component:** Web Interface, Authentication module

**Risk Severity:** Critical

**Mitigation Strategies:**
* Use strong, unique passwords for the AdGuard Home web interface.
* Enable two-factor authentication (if available).
* Limit access to the web interface to trusted networks or IP addresses.
* Keep AdGuard Home updated to patch web interface vulnerabilities.
* Implement account lockout policies to prevent brute-force attacks.

## Threat: [Denial of Service (DoS) Against AdGuard Home DNS Resolver](./threats/denial_of_service__dos__against_adguard_home_dns_resolver.md)

**Description:** An attacker floods AdGuard Home's DNS resolver with a large volume of malicious or legitimate DNS queries, overwhelming its resources and making it unable to respond to legitimate requests.

**Impact:** The application relying on AdGuard Home for DNS resolution will experience DNS resolution failures, leading to inability to access external resources and potentially causing application downtime.

**Affected Component:** DNS Resolver module

**Risk Severity:** High

**Mitigation Strategies:**
* Implement rate limiting on DNS queries within AdGuard Home's configuration if available.
* Deploy AdGuard Home behind a firewall with DDoS protection capabilities.
* Monitor AdGuard Home's resource usage and network traffic for signs of a DoS attack.

## Threat: [Exploitation of Vulnerabilities in AdGuard Home's Dependency Libraries](./threats/exploitation_of_vulnerabilities_in_adguard_home's_dependency_libraries.md)

**Description:** AdGuard Home relies on various third-party libraries. Vulnerabilities in these dependencies could be exploited to compromise AdGuard Home itself.

**Impact:** Depending on the vulnerability, an attacker could achieve remote code execution, gain unauthorized access, or cause a denial of service.

**Affected Component:** Various modules depending on the vulnerable dependency

**Risk Severity:** Medium to High (depending on the vulnerability, can be critical)

**Mitigation Strategies:**
* Keep AdGuard Home updated, as updates often include patches for dependency vulnerabilities.
* Monitor security advisories for AdGuard Home and its dependencies.

