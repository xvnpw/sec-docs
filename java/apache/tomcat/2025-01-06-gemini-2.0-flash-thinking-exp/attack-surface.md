# Attack Surface Analysis for apache/tomcat

## Attack Surface: [Unsecured HTTP Connector](./attack_surfaces/unsecured_http_connector.md)

- **Description:** Tomcat is configured to listen for HTTP requests on a non-encrypted port (default 8080).
    - **How Tomcat Contributes to the Attack Surface:** Tomcat's core functionality is to act as a web server, and by default, it enables an HTTP connector. This makes it immediately accessible for unencrypted communication.
    - **Example:** A user logs into the application, and their credentials are sent over the network in plain text, which can be intercepted by an attacker using network sniffing tools.
    - **Impact:** Confidential data transmitted between the user and the server (including credentials, session tokens, personal information) can be intercepted and read by attackers.
    - **Risk Severity:** Critical
    - **Mitigation Strategies:**
        - **Developers/Users:**  Configure Tomcat to use an HTTPS connector (port 443) with a valid SSL/TLS certificate. Disable or restrict access to the HTTP connector. Enforce HTTPS redirection to ensure all traffic is encrypted.

## Attack Surface: [Tomcat Manager Application with Default Credentials](./attack_surfaces/tomcat_manager_application_with_default_credentials.md)

- **Description:** The Tomcat Manager application, used for deploying and managing web applications, is accessible with default usernames and passwords (e.g., `tomcat/tomcat`).
    - **How Tomcat Contributes to the Attack Surface:** Tomcat provides the Manager application as a built-in tool for administration. If not properly secured, it becomes a direct entry point for attackers.
    - **Example:** An attacker accesses the `/manager/html` page using the default credentials and deploys a malicious WAR file containing a backdoor.
    - **Impact:** Full compromise of the Tomcat server and potentially the underlying operating system. Attackers can deploy, undeploy, and modify web applications, leading to data breaches, service disruption, and further attacks.
    - **Risk Severity:** Critical
    - **Mitigation Strategies:**
        - **Developers/Users:** Immediately change the default usernames and passwords for the Tomcat Manager application in the `tomcat-users.xml` file. Restrict access to the Manager application based on IP address or require strong authentication mechanisms. Consider disabling the Manager application if not actively used.

## Attack Surface: [Exposed AJP Connector](./attack_surfaces/exposed_ajp_connector.md)

- **Description:** The Apache JServ Protocol (AJP) connector (default port 8009) is exposed to untrusted networks.
    - **How Tomcat Contributes to the Attack Surface:** Tomcat includes the AJP connector for communication with reverse proxies like Apache HTTP Server. If not properly secured, it can be exploited directly.
    - **Example:** Exploiting the "Ghostcat" vulnerability (CVE-2020-1938) on an exposed AJP port allows an attacker to read arbitrary files on the server or potentially execute code.
    - **Impact:**  Reading sensitive files, potential remote code execution, and gaining control over the Tomcat server.
    - **Risk Severity:** Critical
    - **Mitigation Strategies:**
        - **Developers/Users:**  Disable the AJP connector if not needed. If required, bind the AJP connector to the loopback address (127.0.0.1) to restrict access to the local machine. Use a firewall to block external access to the AJP port. Ensure Tomcat is updated to a version that patches known AJP vulnerabilities.

## Attack Surface: [Insecure Session Management](./attack_surfaces/insecure_session_management.md)

- **Description:** Tomcat's session management is not configured securely, leading to vulnerabilities like session fixation or predictable session IDs.
    - **How Tomcat Contributes to the Attack Surface:** Tomcat handles session creation and management. Weaknesses in this process can be exploited.
    - **Example:** An attacker performs a session fixation attack by forcing a user to use a known session ID, allowing the attacker to hijack the user's session after they log in.
    - **Impact:** Unauthorized access to user accounts and sensitive data.
    - **Risk Severity:** High
    - **Mitigation Strategies:**
        - **Developers:** Configure Tomcat to invalidate sessions upon logout and after a period of inactivity. Use HTTPS to protect session cookies. Implement HTTPOnly and Secure flags for session cookies. Regenerate session IDs after successful login to prevent session fixation.
        - **Users:** Ensure Tomcat is configured with strong session ID generation algorithms.

## Attack Surface: [Deployment of Malicious WAR Files](./attack_surfaces/deployment_of_malicious_war_files.md)

- **Description:**  Unauthorized users are able to deploy web application archive (WAR) files to the Tomcat server.
    - **How Tomcat Contributes to the Attack Surface:** Tomcat's Manager application or other deployment mechanisms can be misused if access controls are weak.
    - **Example:** An attacker gains access to the Tomcat Manager application (through compromised credentials or an open port) and deploys a WAR file containing a web shell, granting them remote command execution.
    - **Impact:** Complete compromise of the Tomcat server and potentially the underlying system.
    - **Risk Severity:** Critical
    - **Mitigation Strategies:**
        - **Developers/Users:**  Restrict access to deployment mechanisms (e.g., Tomcat Manager). Implement strong authentication and authorization for deployment. Regularly audit deployed applications. Consider using a CI/CD pipeline with security checks before deployment.

