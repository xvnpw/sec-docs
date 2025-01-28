# Attack Surface Analysis for adguardteam/adguardhome

## Attack Surface: [Weak Web Interface Authentication](./attack_surfaces/weak_web_interface_authentication.md)

*   **Description:**  Vulnerabilities related to insecure authentication and authorization mechanisms in the AdGuard Home web interface, allowing unauthorized access.
*   **AdGuard Home Contribution:** AdGuard Home provides a web interface for configuration and management. Weaknesses in its authentication implementation directly expose this interface.
*   **Example:**  Using default administrator credentials (`admin`/`password`) after installation allows anyone to log in and completely control AdGuard Home settings.
*   **Impact:** Full compromise of AdGuard Home configuration, including disabling filtering, modifying DNS settings, accessing logs, and potentially gaining control over the underlying system.
*   **Risk Severity:** **High** (Critical if default credentials are used and exposed to the internet).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Enforce strong password policies during initial setup.
        *   Implement account lockout and rate limiting to prevent brute-force attacks.
        *   Use secure password hashing algorithms.
        *   Consider multi-factor authentication (MFA) options.
    *   **Users:**
        *   **Immediately change default administrator credentials upon installation.**
        *   Use strong, unique passwords for administrator accounts.
        *   Enable MFA if available.
        *   Restrict access to the web interface to trusted networks (e.g., using firewall rules).

## Attack Surface: [Cross-Site Scripting (XSS) in Web Interface](./attack_surfaces/cross-site_scripting__xss__in_web_interface.md)

*   **Description:**  Vulnerabilities that allow attackers to inject malicious scripts into the AdGuard Home web interface, which are then executed in the browsers of administrators accessing the interface.
*   **AdGuard Home Contribution:** AdGuard Home's web interface takes user input in various fields (filters, DNS rewrites, client names, etc.). If these inputs are not properly sanitized by AdGuard Home, XSS vulnerabilities can arise.
*   **Example:** An attacker injects a malicious JavaScript payload into a custom filter rule. When an administrator views this rule in the web interface, the script executes, potentially stealing session cookies or redirecting the administrator to a malicious site.
*   **Impact:** Session hijacking, account takeover, defacement of the web interface, redirection to malicious websites, and potentially further exploitation of the administrator's browser and system.
*   **Risk Severity:** **High**.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Implement robust input sanitization and output encoding for all user-supplied data in the web interface.
        *   Use a Content Security Policy (CSP) to mitigate the impact of XSS vulnerabilities.
        *   Regularly perform security testing and code reviews to identify and fix XSS vulnerabilities.
    *   **Users:**
        *   Keep AdGuard Home updated to benefit from security patches.
        *   Use a modern web browser with built-in XSS protection.

## Attack Surface: [Command Injection via Web Interface](./attack_surfaces/command_injection_via_web_interface.md)

*   **Description:**  Vulnerabilities that allow attackers to execute arbitrary system commands on the server hosting AdGuard Home, typically by injecting malicious commands through input fields in the web interface.
*   **AdGuard Home Contribution:** If AdGuard Home's web interface interacts with the underlying operating system (e.g., for running scripts, managing lists, or through configuration options) and input is not properly validated by AdGuard Home, command injection is possible.
*   **Example:**  An attacker crafts a malicious filter rule that includes shell commands. If AdGuard Home processes this rule without proper sanitization and executes it in a shell context, the attacker's commands will be executed on the server.
*   **Impact:** Full compromise of the server hosting AdGuard Home, including data theft, malware installation, denial of service, and use of the server for further attacks.
*   **Risk Severity:** **Critical**.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Avoid executing system commands based on user input whenever possible.**
        *   If system commands are necessary, implement strict input validation and sanitization within AdGuard Home to prevent command injection.
        *   Use parameterized commands or safe APIs instead of directly constructing shell commands from user input.
        *   Apply the principle of least privilege – run AdGuard Home with minimal necessary permissions.
    *   **Users:**
        *   Keep AdGuard Home updated to benefit from security patches.
        *   Avoid using custom scripts or features that might introduce command injection risks if not properly vetted.

## Attack Surface: [DNS Server Vulnerabilities (Amplification, DoS)](./attack_surfaces/dns_server_vulnerabilities__amplification__dos_.md)

*   **Description:**  Vulnerabilities within the DNS server component of AdGuard Home that could be exploited for DNS amplification attacks or denial of service against the DNS service itself.
*   **AdGuard Home Contribution:** AdGuard Home *is* a DNS server. Vulnerabilities in its DNS server implementation directly contribute to this attack surface.
*   **Example:**
    *   **Amplification:**  AdGuard Home is misconfigured or vulnerable, allowing attackers to send queries that result in large responses, which are then directed towards a victim in a DDoS attack.
    *   **DoS:** Attackers flood AdGuard Home with a massive number of DNS queries, overwhelming the server and preventing it from responding to legitimate requests.
*   **Impact:**
    *   **Amplification:** Contribution to large-scale DDoS attacks, potential legal repercussions if your server is used in attacks.
    *   **DoS:**  Disruption of DNS resolution for users relying on AdGuard Home.
*   **Risk Severity:** **High**.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Implement robust DNS server security practices, including protection against amplification attacks and DoS.
        *   Regularly update the DNS server component and dependencies to patch known vulnerabilities.
        *   Follow security best practices for DNS server development.
    *   **Users:**
        *   Keep AdGuard Home updated to benefit from security patches.
        *   Configure rate limiting on the DNS server if available.
        *   If not needed, avoid exposing the DNS server directly to the public internet. Use it within a protected network.
        *   Monitor DNS server logs for suspicious activity.

## Attack Surface: [Insecure Update Mechanism](./attack_surfaces/insecure_update_mechanism.md)

*   **Description:**  Vulnerabilities in the process by which AdGuard Home updates itself, potentially allowing attackers to inject malicious updates.
*   **AdGuard Home Contribution:** AdGuard Home has an update mechanism to fetch new versions. If this mechanism is insecurely implemented by AdGuard Home, it becomes a critical attack vector.
*   **Example:**  AdGuard Home downloads updates over unencrypted HTTP without proper signature verification. An attacker performs a Man-in-the-Middle (MitM) attack and replaces the legitimate update with a malicious version containing malware.
*   **Impact:**  Complete compromise of the AdGuard Home instance and potentially the underlying system if the malicious update contains malware or exploits vulnerabilities.
*   **Risk Severity:** **Critical**.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Use HTTPS for all update downloads.**
        *   **Implement cryptographic signature verification for updates.** Ensure that updates are signed by a trusted authority and that the signature is verified before installation.
        *   Use a secure and reliable update server infrastructure.
    *   **Users:**
        *   Ensure AdGuard Home is configured to automatically check for and install updates (if desired, balancing with stability concerns).
        *   Monitor for unusual update behavior or errors.

## Attack Surface: [Insecure Configuration File Permissions (Sensitive Data Exposure)](./attack_surfaces/insecure_configuration_file_permissions__sensitive_data_exposure_.md)

*   **Description:**  Configuration files containing sensitive information (passwords, API keys) are stored with overly permissive file permissions, allowing unauthorized access to sensitive data managed by AdGuard Home.
*   **AdGuard Home Contribution:** AdGuard Home stores its configuration in files (e.g., `AdGuardHome.yaml`). If AdGuard Home does not properly handle or protect sensitive data within these files, and they are not properly secured by the user, it leads to risk.
*   **Example:** The `AdGuardHome.yaml` file, containing administrator credentials or API keys, is readable by all users on the system due to default permissions or misconfiguration. A local attacker gains access to these credentials and compromises AdGuard Home.
*   **Impact:**  Unauthorized access to AdGuard Home configuration, potential account takeover, and exposure of sensitive information.
*   **Risk Severity:** **High** (if sensitive information is stored in plaintext or weakly protected by AdGuard Home and file permissions are weak).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Store sensitive information securely (e.g., using encryption or secure key storage mechanisms instead of plaintext in configuration files).
        *   Document and recommend secure file permissions for configuration files.
    *   **Users:**
        *   **Ensure that configuration files (e.g., `AdGuardHome.yaml`) have restrictive file permissions (e.g., readable only by the AdGuard Home process user and administrator).**
        *   Regularly review file permissions and system security.

