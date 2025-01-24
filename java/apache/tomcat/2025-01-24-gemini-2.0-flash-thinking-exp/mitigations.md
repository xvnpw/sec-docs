# Mitigation Strategies Analysis for apache/tomcat

## Mitigation Strategy: [Harden Default Ports](./mitigation_strategies/harden_default_ports.md)

*   **Mitigation Strategy:** Change Default Ports
*   **Description:**
    1.  **Edit `server.xml`:** Access the `server.xml` configuration file located in the Tomcat `conf` directory.
    2.  **Modify Connector Ports:** Locate the `<Connector>` elements for HTTP (default port 8080) and HTTPS (default port 8443). Change the `port` attribute values to non-standard ports (above 1024). For example, use 8090 for HTTP and 8450 for HTTPS.
    3.  **Modify Shutdown Port (Optional):** Find the `<Server port="8005" shutdown="SHUTDOWN">` element and change the `port` attribute to a non-standard port or disable it by setting `port="-1"`.
    4.  **Restart Tomcat:** Restart the Tomcat server for the port changes to take effect.
    5.  **Update External Configurations:** If firewalls or load balancers are used, update their configurations to reflect the new Tomcat ports.
*   **List of Threats Mitigated:**
    *   **Automated Scanning and Default Exploitation (Medium Severity):** Reduces the effectiveness of automated scans targeting default Tomcat ports, making it slightly harder for attackers to discover and exploit default configurations.
    *   **Information Disclosure (Low Severity):** Obscures the fact that a Tomcat server might be running on default ports, offering a minor layer of obfuscation.
*   **Impact:**
    *   **Automated Scanning and Default Exploitation:** High reduction in risk for automated attacks.
    *   **Information Disclosure:** Low reduction in risk, primarily obfuscation.
*   **Currently Implemented:** Yes, implemented in `Production` and `Staging` environments. Ports are changed to 8090 (HTTP) and 8450 (HTTPS) in `server.xml` configuration managed by Ansible. Shutdown port is disabled.
*   **Missing Implementation:** Not applicable, implemented across all relevant environments.

## Mitigation Strategy: [Disable Unnecessary Connectors (AJP)](./mitigation_strategies/disable_unnecessary_connectors__ajp_.md)

*   **Mitigation Strategy:** Disable Unnecessary Connectors (AJP)
*   **Description:**
    1.  **Edit `server.xml`:** Open the `server.xml` file in the Tomcat `conf` directory.
    2.  **Locate AJP Connector:** Find the `<Connector port="8009" protocol="AJP/1.3" ...>` element, which defines the AJP connector.
    3.  **Comment Out or Remove Connector:** Comment out the entire `<Connector>` element using `<!-- -->` tags or completely remove it from the `server.xml` file if the AJP protocol is not required by your application architecture.
    4.  **Restart Tomcat:** Restart the Tomcat server to disable the AJP connector.
    5.  **Verify Application Functionality:** After disabling AJP, ensure that your application still functions correctly, especially if you are unsure whether it relies on AJP.
*   **List of Threats Mitigated:**
    *   **AJP Request Smuggling/Injection Vulnerabilities (High Severity):** Eliminates vulnerabilities like Ghostcat (CVE-2020-1938) that exploit weaknesses in the AJP protocol.
    *   **Unnecessary Attack Surface (Medium Severity):** Reduces the attack surface by closing an unused network port and disabling a potentially vulnerable protocol.
*   **Impact:**
    *   **AJP Request Smuggling/Injection Vulnerabilities:** High reduction in risk (complete mitigation if AJP is not needed).
    *   **Unnecessary Attack Surface:** Medium reduction in risk.
*   **Currently Implemented:** Yes, implemented in `Production` and `Staging` environments. AJP connector is commented out in `server.xml` managed by Ansible.
*   **Missing Implementation:** Not applicable, implemented across all relevant environments.

## Mitigation Strategy: [Restrict Manager and Host Manager Access (IP Restriction via Tomcat Valves)](./mitigation_strategies/restrict_manager_and_host_manager_access__ip_restriction_via_tomcat_valves_.md)

*   **Mitigation Strategy:** Restrict Manager and Host Manager Access (IP Restriction via Tomcat Valves)
*   **Description:**
    1.  **Locate Manager `context.xml`:** Find the `context.xml` file for the Tomcat Manager application, typically located at `$CATALINA_BASE/webapps/manager/META-INF/context.xml`.
    2.  **Add Remote Address Valve:** Inside the `<Context>` element, add a `<Valve>` element of class `org.apache.catalina.valves.RemoteAddrValve` to restrict access based on IP addresses. Use the `allow` attribute with a comma-separated list of allowed IP addresses or regular expressions for network ranges.
        ```xml
        <Valve className="org.apache.catalina.valves.RemoteAddrValve"
               allow="127\.0\.0\.1,192\.168\.1\.[0-9]{1,3}"/>
        ```
    3.  **Repeat for Host Manager:** If Host Manager is enabled, repeat steps 1 and 2 for its `context.xml` file (typically at `$CATALINA_BASE/webapps/host-manager/META-INF/context.xml`).
    4.  **Restart Tomcat:** Restart the Tomcat server for the access restrictions to be applied.
*   **List of Threats Mitigated:**
    *   **Unauthorized Access to Manager/Host Manager (Critical Severity):** Prevents unauthorized users from accessing Tomcat's administrative web applications, which could lead to server compromise.
    *   **Credential Brute-Force Attacks (High Severity):** Reduces the risk of brute-force attacks against Manager/Host Manager login pages by limiting the accessible network locations.
*   **Impact:**
    *   **Unauthorized Access to Manager/Host Manager:** High reduction in risk by limiting access to trusted sources.
    *   **Credential Brute-Force Attacks:** Medium reduction in risk by limiting exposure, but strong authentication is still essential.
*   **Currently Implemented:** Partially implemented in `Production`. IP restriction is configured in `manager/META-INF/context.xml` to allow access only from the internal management network (range 192.168.1.0/24).
*   **Missing Implementation:** IP restriction needs to be implemented in `Staging` environment for both Manager and Host Manager applications. Host Manager access restriction is also missing in `Production` and needs to be configured.

## Mitigation Strategy: [Customize Error Pages (Tomcat Specific Error Handling)](./mitigation_strategies/customize_error_pages__tomcat_specific_error_handling_.md)

*   **Mitigation Strategy:** Customize Error Pages (Tomcat Specific Error Handling)
*   **Description:**
    1.  **Edit `web.xml`:** Modify the `web.xml` file for your web application (in `WEB-INF/web.xml`) or the global Tomcat `web.xml` (`$CATALINA_BASE/conf/web.xml`). Global configuration applies to all web applications.
    2.  **Define Error Pages in `web.xml`:** Add `<error-page>` elements within the `<web-app>` element to map HTTP error codes and exception types to custom error pages. Ensure these pages are designed to *avoid revealing Tomcat-specific information*.
        ```xml
        <error-page>
            <error-code>404</error-code>
            <location>/error/404.jsp</location>
        </error-page>
        <error-page>
            <error-code>500</error-code>
            <location>/error/500.jsp</location>
        </error-page>
        ```
    3.  **Create Custom Error Pages:** Develop JSP files (e.g., `404.jsp`, `500.jsp`) located at the specified paths within your web application. These pages should display generic, user-friendly error messages without exposing server details, Tomcat versions, or stack traces.
    4.  **Restart Tomcat/Redeploy Application:** Restart Tomcat or redeploy your web application for the custom error pages to be active.
*   **List of Threats Mitigated:**
    *   **Information Disclosure via Tomcat Error Messages (Low to Medium Severity):** Prevents default Tomcat error pages from revealing sensitive information about the server environment, Tomcat version, internal paths, and stack traces, which could aid attackers in reconnaissance.
*   **Impact:**
    *   **Information Disclosure via Tomcat Error Messages:** Medium reduction in risk by preventing leakage of server-specific information.
*   **Currently Implemented:** Partially implemented in the `Production` environment. Custom 404 and 500 error pages are configured in the application's `web.xml`. However, generic exception handling is not yet implemented.
*   **Missing Implementation:** Generic exception handling error page needs to be implemented in the application's `web.xml` for both `Production` and `Staging` environments. Custom error pages should also be reviewed to ensure no Tomcat specific details are leaked.

## Mitigation Strategy: [Disable Directory Listing (Tomcat Default Servlet Configuration)](./mitigation_strategies/disable_directory_listing__tomcat_default_servlet_configuration_.md)

*   **Mitigation Strategy:** Disable Directory Listing (Tomcat Default Servlet Configuration)
*   **Description:**
    1.  **Edit `web.xml`:** Open the `web.xml` file for your web application (in `WEB-INF/web.xml`) or the global Tomcat `web.xml` (`$CATALINA_BASE/conf/web.xml`). Global configuration is recommended for consistent security.
    2.  **Configure Default Servlet in `web.xml`:** Locate the `<servlet>` element for the `default` servlet.
    3.  **Set `listings` Parameter:** Within the `<servlet>` element, add an `<init-param>` to disable directory listing by setting the `listings` parameter to `false`.
        ```xml
        <servlet>
            <servlet-name>default</servlet-name>
            <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
            <init-param>
                <param-name>listings</param-name>
                <param-value>false</param-value>
            </init-param>
        </servlet>
        ```
    4.  **Restart Tomcat/Redeploy Application:** Restart Tomcat or redeploy your web application for the directory listing setting to take effect.
*   **List of Threats Mitigated:**
    *   **Information Disclosure via Directory Listing (Medium Severity):** Prevents attackers from browsing directory structures served by Tomcat's default servlet, which could expose sensitive files, configuration files, or application code.
*   **Impact:**
    *   **Information Disclosure via Directory Listing:** High reduction in risk by preventing unauthorized directory browsing.
*   **Currently Implemented:** Yes, implemented in the global Tomcat `web.xml` (`$CATALINA_BASE/conf/web.xml`) for both `Production` and `Staging` environments. `listings` parameter is set to `false`.
*   **Missing Implementation:** Not applicable, implemented globally. It's advisable to verify individual application `web.xml` files to ensure no overrides re-enable directory listing.

## Mitigation Strategy: [Enforce HTTPS for Session Cookies (Tomcat `context.xml` Configuration)](./mitigation_strategies/enforce_https_for_session_cookies__tomcat__context_xml__configuration_.md)

*   **Mitigation Strategy:** Enforce HTTPS for Session Cookies (Tomcat `context.xml` Configuration)
*   **Description:**
    1.  **Edit `context.xml`:** Open the `context.xml` file for your web application (in `META-INF/context.xml`) or the global Tomcat `context.xml` (`$CATALINA_BASE/conf/context.xml`). Global configuration is recommended for consistency.
    2.  **Configure `sessionCookieConfig` in `context.xml`:** Within the `<Context>` element, add or modify the `<sessionCookieConfig>` element to set the `<secure>` attribute to `true`. This instructs Tomcat to set the `Secure` flag on session cookies, ensuring they are only transmitted over HTTPS.
        ```xml
        <Context>
            <sessionCookieConfig>
                <secure>true</secure>
            </sessionCookieConfig>
            ...
        </Context>
        ```
    3.  **Ensure HTTPS is Enabled on Tomcat Connectors:** Verify that HTTPS connectors are properly configured in `server.xml` and that your application is accessible over HTTPS.
    4.  **Restart Tomcat/Redeploy Application:** Restart Tomcat or redeploy your web application for the session cookie configuration to be applied.
*   **List of Threats Mitigated:**
    *   **Session Hijacking via Man-in-the-Middle (MitM) Attacks (High Severity):** Prevents session cookies from being transmitted in plaintext over HTTP, mitigating the risk of session hijacking by attackers performing MitM attacks on unencrypted connections.
*   **Impact:**
    *   **Session Hijacking via MitM Attacks:** High reduction in risk by ensuring session cookies are only transmitted over encrypted HTTPS connections.
*   **Currently Implemented:** Yes, implemented in the global Tomcat `context.xml` (`$CATALINA_BASE/conf/context.xml`) for both `Production` and `Staging` environments. `<secure>true</secure>` is configured.
*   **Missing Implementation:** Not applicable, implemented globally. Ensure the entire application is served over HTTPS to fully leverage this mitigation.

## Mitigation Strategy: [Regular Tomcat Updates and Patching](./mitigation_strategies/regular_tomcat_updates_and_patching.md)

*   **Mitigation Strategy:** Regular Tomcat Updates and Patching
*   **Description:**
    1.  **Monitor Tomcat Security Announcements:** Regularly monitor the Apache Tomcat Security Reports page and subscribe to security mailing lists for notifications about new vulnerabilities and security updates released for Tomcat.
    2.  **Download Latest Tomcat Version/Patches:** When a security update is available, download the latest stable version of Tomcat or the specific patch from the official Apache Tomcat website.
    3.  **Test Updates in Staging Environment:** Before applying updates to production, deploy the updated Tomcat version or patches to a staging environment that mirrors your production setup. Thoroughly test your application in staging to identify any compatibility issues or regressions.
    4.  **Apply Updates to Production Tomcat Servers:** After successful testing in staging, schedule a maintenance window to apply the updates to your production Tomcat servers. Follow the Apache Tomcat upgrade instructions for your specific version.
    5.  **Verify Tomcat Version Post-Update:** After updating, verify that the correct Tomcat version is running in production to confirm successful patching.
    6.  **Document Update Process:** Maintain documentation of all Tomcat updates and patches applied, including dates, versions, and any specific steps taken.
*   **List of Threats Mitigated:**
    *   **Exploitation of Known Tomcat Vulnerabilities (Critical to High Severity):** Addresses and mitigates publicly known security vulnerabilities in Tomcat that could be exploited by attackers if running outdated versions.
*   **Impact:**
    *   **Exploitation of Known Tomcat Vulnerabilities:** High reduction in risk by proactively addressing known vulnerabilities.
*   **Currently Implemented:** Partially implemented. We have a process for monitoring security advisories and downloading updates. Staging environment is used for testing.
*   **Missing Implementation:** The process for applying updates to production is currently manual and needs to be automated using configuration management tools (Ansible). Documentation of updates needs to be formalized and consistently maintained.

## Mitigation Strategy: [Run Tomcat with Least Privilege User](./mitigation_strategies/run_tomcat_with_least_privilege_user.md)

*   **Mitigation Strategy:** Run Tomcat with Least Privilege User
*   **Description:**
    1.  **Create Dedicated System User for Tomcat:** Create a dedicated, non-privileged system user account (e.g., `tomcat`) specifically for running the Tomcat process. This user should not have root or administrative privileges.
    2.  **Configure Tomcat Startup Scripts:** Modify the Tomcat startup scripts (e.g., `catalina.sh`, `service.sh`) to ensure that the Tomcat process is launched under the newly created `tomcat` user account. This often involves setting a `RUN_AS_USER` variable in the scripts.
    3.  **Set File System Permissions for Tomcat User:** Configure file system permissions for the Tomcat installation directory, configuration files, log directories, and web application directories to grant the `tomcat` user only the necessary permissions to operate. Restrict write access to sensitive files and directories.
    4.  **Verify Tomcat User in Running Process:** After restarting Tomcat, use system monitoring tools (e.g., `ps aux | grep tomcat`) to verify that the Tomcat process is indeed running under the designated `tomcat` user account.
*   **List of Threats Mitigated:**
    *   **Privilege Escalation after Tomcat Compromise (High Severity):** Limits the potential damage if Tomcat is compromised. An attacker gaining control of the Tomcat process running under a low-privilege user will have restricted access to the system, hindering privilege escalation attempts.
    *   **Accidental System Damage from Tomcat Process (Medium Severity):** Reduces the risk of accidental damage to the system if the Tomcat process malfunctions or is misconfigured, as the low-privilege user has limited system-wide permissions.
*   **Impact:**
    *   **Privilege Escalation after Tomcat Compromise:** High reduction in risk by limiting attacker's potential impact.
    *   **Accidental System Damage from Tomcat Process:** Medium reduction in risk.
*   **Currently Implemented:** Yes, implemented in both `Production` and `Staging` environments. Tomcat is configured to run under a dedicated `tomcat` user account created during server provisioning. Ansible scripts manage user creation and file permissions.
*   **Missing Implementation:** Not applicable, implemented across all relevant environments.

