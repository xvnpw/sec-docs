# Attack Surface Analysis for apache/tomcat

## Attack Surface: [Exposed Management Interfaces (Manager & Host Manager)](./attack_surfaces/exposed_management_interfaces__manager_&_host_manager_.md)

*   **Description:** Tomcat's Manager and Host Manager web applications provide administrative interfaces. If accessible without proper authentication, they are a major attack vector.
*   **Tomcat Contribution:** Tomcat deploys these applications by default and often leaves them accessible via HTTP on standard ports.
*   **Example:** An attacker accesses the `/manager/html` interface using default credentials and deploys a malicious web application (WAR file) containing a web shell.
*   **Impact:** Full server compromise, data breach, service disruption, malware deployment.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   Disable or remove default management applications.
    *   Restrict access by IP address.
    *   Enforce strong authentication and authorization.
    *   Use HTTPS for management interfaces.

## Attack Surface: [Exposed AJP Connector](./attack_surfaces/exposed_ajp_connector.md)

*   **Description:** The Apache JServ Protocol (AJP) connector is for communication with front-end web servers. If exposed to untrusted networks, it can be exploited.
*   **Tomcat Contribution:** Tomcat enables the AJP connector by default on port 8009, which can be exposed due to misconfiguration.
*   **Example:** Exploiting the "Ghostcat" vulnerability (CVE-2020-1938) on an exposed AJP connector to read sensitive files within the web application.
*   **Impact:** Information disclosure, potential Remote Code Execution, unauthorized access to application resources.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   Disable AJP connector if not needed.
    *   Bind AJP connector to the loopback interface (127.0.0.1).
    *   Use firewall restrictions on the AJP port.
    *   Utilize the `requiredSecret` attribute for AJP connector authentication (Tomcat 9.0.31+).

## Attack Surface: [Default Credentials](./attack_surfaces/default_credentials.md)

*   **Description:** Tomcat's default `tomcat-users.xml` includes example users and roles. If not changed, these are easily exploitable.
*   **Tomcat Contribution:** Tomcat provides a default `tomcat-users.xml` file with example user credentials.
*   **Example:** An attacker uses the default username "tomcat" and password "s3cret" to log in to the Manager application.
*   **Impact:** Unauthorized access to management interfaces, server compromise, data breach.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   Change or remove all default users and passwords in `tomcat-users.xml`.
    *   Implement strong password policies.
    *   Use external authentication systems.

## Attack Surface: [Weak SSL/TLS Configuration on HTTPS Connector](./attack_surfaces/weak_ssltls_configuration_on_https_connector.md)

*   **Description:** Using outdated SSL/TLS protocols or weak cipher suites for HTTPS connectors exposes communication to attacks.
*   **Tomcat Contribution:** Tomcat's HTTPS connector configuration allows for insecure SSL/TLS settings if not properly configured.
*   **Example:** Using SSLv3 or weak cipher suites allows man-in-the-middle attacks to decrypt communication and steal sensitive data.
*   **Impact:** Eavesdropping, man-in-the-middle attacks, data breaches.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   Enforce strong SSL/TLS configuration (TLS 1.2+ and secure cipher suites).
    *   Disable weak protocols like SSLv3 and TLS 1.0/1.1.
    *   Regularly update SSL/TLS libraries.

## Attack Surface: [Unsecured JMX Interface](./attack_surfaces/unsecured_jmx_interface.md)

*   **Description:** An unsecured Java Management Extensions (JMX) remote interface allows unauthorized control over the JVM and Tomcat.
*   **Tomcat Contribution:** Tomcat can be configured to expose JMX for remote management, which if unsecured, is a critical vulnerability.
*   **Example:** An attacker connects to an unsecured JMX port and executes arbitrary code within the Tomcat JVM using JMX MBeans.
*   **Impact:** Remote Code Execution, full server compromise, data breach.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   Disable JMX remote if not needed.
    *   Enable JMX authentication and authorization.
    *   Restrict access to the JMX port by IP address.
    *   Use JMX over SSL/TLS for encrypted communication.

## Attack Surface: [Outdated Tomcat Version](./attack_surfaces/outdated_tomcat_version.md)

*   **Description:** Using an outdated Tomcat version exposes the application to known, unpatched vulnerabilities.
*   **Tomcat Contribution:** Tomcat, like all software, has vulnerabilities. Using older versions means missing critical security fixes provided in newer versions.
*   **Example:** Exploiting a publicly disclosed Remote Code Execution vulnerability (CVE) specific to the outdated Tomcat version in use.
*   **Impact:** Varies, potentially including Remote Code Execution, information disclosure, and server compromise.
*   **Risk Severity:** **High to Critical**
*   **Mitigation Strategies:**
    *   Regularly update Tomcat to the latest stable version or apply security patches promptly.
    *   Establish a patch management process for Tomcat and related components.

