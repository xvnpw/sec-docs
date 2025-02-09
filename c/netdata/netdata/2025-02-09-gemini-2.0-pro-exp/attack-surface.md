# Attack Surface Analysis for netdata/netdata

## Attack Surface: [Network Exposure and Unauthorized Access](./attack_surfaces/network_exposure_and_unauthorized_access.md)

**Description:** Direct, unrestricted access to the Netdata web interface and API.
**How Netdata Contributes:** Netdata listens on port 19999 by default and provides a web interface and API without built-in authentication, making it accessible to anyone who can reach the port.
**Example:** An attacker scans the network, finds port 19999 open, and accesses the Netdata dashboard without credentials, viewing all system metrics.
**Impact:**
    *   Exposure of sensitive system information.
    *   Reconnaissance for further attacks.
    *   Potential DoS of the Netdata service.
**Risk Severity:** **Critical** (if exposed to public internet/untrusted networks) / **High** (if exposed on internal network without segmentation).
**Mitigation Strategies:**
    *   **Firewall Rules (Essential):**  Strictly limit access to port 19999 via host-based and network firewalls. Allow *only* authorized IPs/networks.
    *   **Reverse Proxy with Authentication (Highly Recommended):** Use a reverse proxy (Nginx, Apache) to handle TLS *and* implement authentication (basic auth, OAuth, etc.). This is the *primary* defense.
    *   **Network Segmentation:** Isolate the Netdata server on a separate network segment.
    *   **VPN/Tunneling:** For remote access, use a VPN or secure tunnel instead of direct exposure.

## Attack Surface: [Unencrypted Communication (MitM Vulnerability)](./attack_surfaces/unencrypted_communication__mitm_vulnerability_.md)

**Description:** Data transmitted between the browser and Netdata server is unencrypted.
**How Netdata Contributes:** Netdata does *not* enforce HTTPS by default. If TLS/SSL is not configured (typically via a reverse proxy), communication is vulnerable.
**Example:** An attacker on the same network captures unencrypted HTTP traffic to/from the Netdata server, revealing system metrics.
**Impact:**
    *   Man-in-the-Middle (MitM) attacks.
    *   Eavesdropping on sensitive data.
    *   Potential session hijacking.
**Risk Severity:** **Critical** (on untrusted networks) / **High** (even on internal networks).
**Mitigation Strategies:**
    *   **Mandatory TLS/SSL via Reverse Proxy (Essential):** Use a reverse proxy to handle TLS termination with strong ciphers and valid certificates.  This is non-negotiable for secure operation.
    *   **HSTS (HTTP Strict Transport Security):** Configure the reverse proxy to send HSTS headers.

## Attack Surface: [Vulnerable Plugins and Collectors](./attack_surfaces/vulnerable_plugins_and_collectors.md)

**Description:** Exploitable vulnerabilities within Netdata's data collection plugins.
**How Netdata Contributes:** Netdata uses plugins to collect data.  Vulnerabilities in these plugins are *directly* related to Netdata's attack surface.
**Example:** A buffer overflow in a Netdata plugin allows an attacker to gain code execution.
**Impact:**
    *   Remote code execution (RCE).
    *   System compromise.
    *   Data breaches.
**Risk Severity:** **High**.
**Mitigation Strategies:**
    *   **Regular Updates (Essential):** Keep Netdata updated to the latest stable version. This is the *primary* defense against known plugin vulnerabilities.
    *   **Disable Unnecessary Plugins:** Only enable required plugins to reduce the attack surface.
    *   **Plugin Auditing (Advanced):** Audit the source code of custom or less common plugins.
    *  **Principle of Least Privilege:** Run Netdata with minimum necessary privileges (not as root).

## Attack Surface: [API Exploitation](./attack_surfaces/api_exploitation.md)

**Description:** Unauthorized access or malicious use of the Netdata REST API.
**How Netdata Contributes:** Netdata provides a REST API for data retrieval and (potentially) configuration.  This API is a *direct* part of Netdata's attack surface.
**Example:** An attacker uses the API to extract data or, if write access is enabled, modify Netdata's configuration.
**Impact:**
    *   Data exfiltration.
    *   DoS via excessive API requests.
    *   Configuration tampering (if write access is enabled).
**Risk Severity:** **High** (if write access is enabled) / **Medium** (if read-only, but still a significant risk). *Note: We are only including High/Critical, so this qualifies.*
**Mitigation Strategies:**
    *   **Restrict API Access (Essential):** Use firewall rules to limit API access to authorized IPs/networks.
    *   **Authentication and Authorization (Highly Recommended):** Implement strong authentication (API keys, tokens) via a reverse proxy. Netdata does *not* have built-in API authentication.
    *   **Disable Write Access:** Disable API write access unless absolutely necessary (controlled via the reverse proxy).
    *   **Rate Limiting:** Implement rate limiting at the reverse proxy to prevent DoS.

