# Threat Model Analysis for freedombox/freedombox

## Threat: [Plinth Configuration Manipulation](./threats/plinth_configuration_manipulation.md)

*   **Description:** An attacker gains access to the Plinth web interface (e.g., through credential stuffing, phishing, or exploiting a vulnerability in another service on the network) and modifies the FreedomBox configuration. They could disable security features (firewall, intrusion detection), change network settings, install malicious packages, or alter user accounts. This gives the attacker near-total control over the FreedomBox.
*   **Impact:** Complete compromise of the FreedomBox instance, including the application and any data it manages. The attacker could gain full control of the network, exfiltrate data, or use the FreedomBox as a launchpad for further attacks.
*   **Affected FreedomBox Component:** Plinth (web interface and backend API).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strong Passwords & 2FA:** Enforce strong, unique passwords for all FreedomBox user accounts, especially the administrator account. Mandate the use of two-factor authentication (2FA) for Plinth access.
    *   **Network Restrictions:** Limit access to Plinth to specific IP addresses or trusted networks using firewall rules. Avoid exposing Plinth to the public internet unless absolutely necessary and then only with extreme caution and additional security measures.
    *   **Regular Audits:** Regularly audit Plinth access logs and configuration changes for suspicious activity. Implement automated alerting for critical configuration changes.
    *   **Principle of Least Privilege:** Ensure that user accounts have only the necessary permissions within Plinth.  Avoid using the default administrator account for routine tasks.
    *   **Web Application Firewall (WAF):** Consider deploying a WAF in front of Plinth to provide an additional layer of protection against web-based attacks, especially if Plinth is exposed to the internet.

## Threat: [Service Misconfiguration Exploitation (e.g., SSH, Database)](./threats/service_misconfiguration_exploitation__e_g___ssh__database_.md)

*   **Description:** An attacker exploits a misconfigured *core* service managed by FreedomBox (e.g., SSH with weak passwords or password authentication enabled, a database with default credentials or exposed to the network). This is distinct from an application *using* a correctly configured service insecurely. The attacker leverages this *FreedomBox-level* misconfiguration to gain access to the service and potentially the underlying system.
*   **Impact:** Compromise of the specific *core* service, potentially leading to data breaches, privilege escalation, or lateral movement within the FreedomBox instance. The impact is high because these are core services, not just application-level dependencies.
*   **Affected FreedomBox Component:** Any *core* FreedomBox-managed service (e.g., SSH, PostgreSQL, MySQL, Apache, Nginx, etc.). Specifically, the configuration files and running processes of these services *as managed by FreedomBox*.
*   **Risk Severity:** High to Critical (depending on the service)
*   **Mitigation Strategies:**
    *   **Secure Defaults:** FreedomBox *must* ship with secure defaults for all core services. This is a primary responsibility of the FreedomBox project.
    *   **Configuration Hardening:** The FreedomBox setup process and documentation *must* guide users through security hardening steps for each core service.
    *   **Regular Updates:** Keep all FreedomBox *core* services and the FreedomBox system itself up-to-date to patch known vulnerabilities. This is a critical responsibility of both the FreedomBox project and the user.
    *   **Least Privilege (System Level):** FreedomBox should be designed to run core services with the least possible privileges.
    *   **Monitoring:** FreedomBox should include built-in monitoring of core service logs for suspicious activity, with alerts for critical events.

## Threat: [FreedomBox API Abuse (Plinth API)](./threats/freedombox_api_abuse__plinth_api_.md)

*   **Description:** An attacker, either authenticated or unauthenticated (if the API is exposed), sends malicious requests to the *Plinth API* to manipulate the FreedomBox configuration, extract information, or disrupt services. This could involve injecting commands, exploiting vulnerabilities in the API's input validation, or exceeding rate limits. This is a direct attack on a core FreedomBox component.
*   **Impact:** Depending on the API endpoint and the attacker's privileges, this could range from minor configuration changes to complete system compromise. The attacker could potentially disable security features, exfiltrate data, or disrupt services managed by FreedomBox.
*   **Affected FreedomBox Component:** Plinth API (specifically, the API endpoints and their underlying logic).
*   **Risk Severity:** High to Critical (depending on the API endpoint)
*   **Mitigation Strategies:**
    *   **Input Validation:** The Plinth API *must* strictly validate all input, including data types, lengths, and formats. Use a whitelist approach whenever possible.
    *   **Authentication & Authorization:** Require strong authentication for *all* Plinth API access. Implement fine-grained authorization to ensure that users and applications only have access to the necessary API endpoints.
    *   **Rate Limiting:** Implement rate limiting on the Plinth API to prevent attackers from overwhelming it with requests.
    *   **API Security Testing:** The FreedomBox project *must* regularly test the Plinth API for security vulnerabilities, including injection flaws, authentication bypasses, and authorization issues.
    *   **Least Privilege for Applications:** If an application uses the Plinth API, grant it only the minimum necessary permissions. This is a shared responsibility between the application developer and the FreedomBox administrator.

## Threat: [Bypassing Firewall via *FreedomBox* Misconfiguration](./threats/bypassing_firewall_via_freedombox_misconfiguration.md)

* **Description:** The *FreedomBox itself* is misconfigured, allowing attackers to bypass the intended firewall protections. This is distinct from an *application* causing a bypass. Examples include: incorrect default firewall rules, a disabled firewall, or a misconfigured VPN setup.
* **Impact:** Attackers can directly access services running on the FreedomBox, bypassing the intended firewall protections. This could lead to data breaches, privilege escalation, or other attacks. The impact is high because the firewall is a fundamental security control.
* **Affected FreedomBox Component:** FreedomBox's firewall (iptables or nftables) and its configuration within Plinth.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * **Secure Default Firewall:** FreedomBox *must* ship with a secure default firewall configuration that blocks all incoming traffic except for explicitly allowed services.
    * **Firewall Rule Review:** The FreedomBox setup process and documentation *must* guide users through reviewing and understanding the default firewall rules.
    * **Automated Firewall Management (Plinth):** Plinth *must* provide a user-friendly interface for managing firewall rules and *must* enforce secure configurations by default.
    * **Regular Audits:** Regularly audit the firewall configuration for any unintended changes or misconfigurations.

