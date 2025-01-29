# Mitigation Strategies Analysis for apache/tomcat

## Mitigation Strategy: [Harden Default Ports](./mitigation_strategies/harden_default_ports.md)

### 1. Harden Default Ports

*   **Mitigation Strategy:** Change Default Ports
*   **Description:**
    1.  **Locate `server.xml`:** Open the `server.xml` file located in the `conf` directory of your Tomcat installation (e.g., `$CATALINA_HOME/conf/server.xml`).
    2.  **Modify HTTP Connector Port:** Find the `<Connector port="8080" ...>` element. Change the `port` attribute from `8080` to a non-standard port above 1024 (e.g., `8090`, `8888`).
    3.  **Modify HTTPS Connector Port:** Find the `<Connector port="8443" ... secure="true" scheme="https" ...>` element. Change the `port` attribute from `8443` to a non-standard port above 1024 (e.g., `8453`, `9443`).
    4.  **Save `server.xml`:** Save the changes to the `server.xml` file.
    5.  **Restart Tomcat:** Restart the Tomcat server for the changes to take effect.
*   **Threats Mitigated:**
    *   **Automated Scanning and Probing (Low Severity):** Attackers often use automated tools to scan for default ports. Changing ports reduces the likelihood of being targeted by generic scans.
    *   **Information Disclosure (Low Severity):** Using default ports can subtly hint at the technology stack being used.
*   **Impact:**
    *   **Automated Scanning and Probing:** High reduction. Makes the application less visible to basic automated scans.
    *   **Information Disclosure:** Low reduction. Does not completely hide the technology but adds a minor obstacle.
*   **Currently Implemented:** Partially implemented. HTTP port is changed to `8090` in development and staging environments. HTTPS port remains `8443` across all environments.
*   **Missing Implementation:** HTTPS port needs to be changed to a non-standard port in production and staging environments.

## Mitigation Strategy: [Disable HTTP Connector (if using HTTPS only)](./mitigation_strategies/disable_http_connector__if_using_https_only_.md)

### 2. Disable Unnecessary Connectors

*   **Mitigation Strategy:** Disable HTTP Connector (if using HTTPS only)
*   **Description:**
    1.  **Locate `server.xml`:** Open the `server.xml` file in the Tomcat `conf` directory.
    2.  **Comment out HTTP Connector:** Find the `<Connector port="8080" ...>` element. Comment it out by enclosing it within `<!--` and `-->` tags: `<!-- <Connector port="8080" ... /> -->`.
    3.  **Verify HTTPS Connector:** Ensure the HTTPS connector `<Connector port="8443" ... secure="true" scheme="https" ...>` is present and correctly configured.
    4.  **Save `server.xml`:** Save the changes.
    5.  **Restart Tomcat:** Restart Tomcat.
    6.  **Test HTTPS Access:** Verify that the application is accessible via HTTPS on the configured port and that HTTP access is blocked or redirects to HTTPS (if redirection is configured elsewhere).
*   **Threats Mitigated:**
    *   **Forced Downgrade Attacks (Medium Severity):** Prevents attackers from forcing users to connect over insecure HTTP when HTTPS is available, potentially exposing sensitive data.
    *   **Accidental HTTP Exposure (Low Severity):** Eliminates the risk of accidentally accessing the application over HTTP, especially during development or testing.
*   **Impact:**
    *   **Forced Downgrade Attacks:** High reduction. Eliminates the HTTP endpoint, removing the attack vector.
    *   **Accidental HTTP Exposure:** High reduction. Prevents unintentional insecure access.
*   **Currently Implemented:** Not implemented. HTTP connector is enabled in all environments for redirection purposes handled by the application.
*   **Missing Implementation:**  Consider implementing HTTPS redirection at the web server level (e.g., Apache HTTP Server, Nginx) instead of relying on Tomcat's HTTP connector. If redirection is moved to the web server, the HTTP connector in Tomcat can be disabled.

## Mitigation Strategy: [Restrict Manager and Host Manager Access](./mitigation_strategies/restrict_manager_and_host_manager_access.md)

### 3. Restrict Access to Management Interfaces

*   **Mitigation Strategy:** Restrict Manager and Host Manager Access
*   **Description:**
    1.  **Locate `context.xml` for Manager App:** Find the `context.xml` file for the Manager application. This is typically located in `$CATALINA_BASE/webapps/manager/META-INF/context.xml` or `$CATALINA_HOME/webapps/manager/META-INF/context.xml`.
    2.  **Add `RemoteAddrValve`:** Inside the `<Context>` element, add a `<Valve>` element to restrict access by IP address. For example, to allow access only from `192.168.1.0/24` and `127.0.0.1`:
        ```xml
        <Context ...>
          <Valve className="org.apache.catalina.valves.RemoteAddrValve"
                 allow="192\.168\.1\.\d+|127\.0\.0\.1"/>
        </Context>
        ```
        Replace `192\.168\.1\.\d+` with your allowed IP address range or specific IP addresses. Use `|` to separate multiple allowed patterns.
    3.  **Repeat for Host Manager:** Repeat steps 1 and 2 for the Host Manager application. Its `context.xml` is usually in `$CATALINA_BASE/webapps/host-manager/META-INF/context.xml` or `$CATALINA_HOME/webapps/host-manager/META-INF/context.xml`.
    4.  **Change Default Credentials:**  Edit `$CATALINA_HOME/conf/tomcat-users.xml`. Change the default usernames and passwords for roles like `manager-gui`, `manager-script`, `admin-gui`, `admin-script`. Use strong, unique passwords.
    5.  **Restart Tomcat:** Restart Tomcat.
    6.  **Test Access:** Verify that access to `/manager/html` and `/host-manager/html` is restricted to the allowed IP addresses and that login attempts with default credentials fail.
*   **Threats Mitigated:**
    *   **Unauthorized Access to Management Console (High Severity):**  Default credentials and unrestricted access to management applications can allow attackers to deploy malicious web applications, modify Tomcat configuration, and potentially gain full control of the server.
    *   **Brute-Force Attacks on Management Console (Medium Severity):**  If access is not restricted, attackers can attempt brute-force attacks to guess administrative credentials.
*   **Impact:**
    *   **Unauthorized Access to Management Console:** High reduction. IP restriction and strong credentials significantly reduce the risk of unauthorized access.
    *   **Brute-Force Attacks on Management Console:** Medium reduction. Strong passwords make brute-force attacks more difficult, and IP restriction limits the attack surface.
*   **Currently Implemented:** Partially implemented. Access to `/manager` and `/host-manager` is restricted by IP address in production and staging environments using `RemoteAddrValve`. Default credentials have been changed in all environments.
*   **Missing Implementation:**  Review and refine the allowed IP address ranges for management interfaces to ensure they are as restrictive as possible. Consider disabling these applications entirely in production if they are not actively used for remote management.

## Mitigation Strategy: [Disable Directory Listing](./mitigation_strategies/disable_directory_listing.md)

### 4. Disable Directory Listing

*   **Mitigation Strategy:** Disable Directory Listing
*   **Description:**
    1.  **Locate `web.xml`:** Open the global `web.xml` file located in `$CATALINA_HOME/conf/web.xml`.
    2.  **Configure `DefaultServlet`:** Find the `<servlet>` element for the `DefaultServlet`.
    3.  **Set `listings` Parameter:** Within the `<servlet>` element, add an `<init-param>` element to disable directory listing:
        ```xml
        <servlet>
            <servlet-name>default</servlet-name>
            <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
            <init-param>
                <param-name>listings</param-name>
                <param-value>false</param-value>
            </init-param>
            <load-on-startup>1</load-on-startup>
        </servlet>
        ```
    4.  **Save `web.xml`:** Save the changes.
    5.  **Restart Tomcat:** Restart Tomcat.
    6.  **Test Directory Access:** Attempt to access a directory in your web application without an index file (e.g., `/your-app/images/`). Verify that you receive a 404 error or a custom error page instead of a directory listing.
*   **Threats Mitigated:**
    *   **Information Disclosure (Medium Severity):** Directory listing can expose directory structures, filenames, and potentially sensitive files to attackers, aiding in reconnaissance and vulnerability discovery.
*   **Impact:**
    *   **Information Disclosure:** Medium reduction. Prevents attackers from easily browsing directory contents.
*   **Currently Implemented:** Implemented in all environments by default Tomcat configuration. Verified in `conf/web.xml`.
*   **Missing Implementation:** No missing implementation. Regularly review `conf/web.xml` after Tomcat upgrades to ensure the setting persists.

## Mitigation Strategy: [Hide Server Header](./mitigation_strategies/hide_server_header.md)

### 5. Hide Server Information

*   **Mitigation Strategy:** Hide Server Header
*   **Description:**
    1.  **Locate `server.xml`:** Open the `server.xml` file in the Tomcat `conf` directory.
    2.  **Modify Connector Element:** Find the `<Connector port="8443" ... secure="true" scheme="https" ...>` element (and the HTTP connector if enabled).
    3.  **Add `server` Attribute:** Add the `server` attribute to the `<Connector>` element and set it to a custom value or an empty string to suppress the header:
        ```xml
        <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
                   ... secure="true" scheme="https" server="" />
        ```
        Setting `server="" removes the header. You can also set it to a generic value like "Web Server" to further obscure the technology.
    4.  **Save `server.xml`:** Save the changes.
    5.  **Restart Tomcat:** Restart Tomcat.
    6.  **Inspect HTTP Headers:** Use browser developer tools or command-line tools like `curl -I` to inspect the HTTP headers of responses from your application. Verify that the `Server` header is either absent or contains the custom value you set.
*   **Threats Mitigated:**
    *   **Information Disclosure (Low Severity):** Hiding the server version makes it slightly harder for attackers to identify and target version-specific vulnerabilities.
*   **Impact:**
    *   **Information Disclosure:** Low reduction.  Provides a minor layer of obscurity but does not prevent determined attackers from identifying the technology through other means.
*   **Currently Implemented:** Implemented in production and staging environments. `server=""` attribute is set in the HTTPS connector in `server.xml`.
*   **Missing Implementation:** Ensure the `server=""` attribute is consistently applied to all relevant connectors (HTTP and HTTPS) across all environments, including development.

## Mitigation Strategy: [Configure Secure Session Management](./mitigation_strategies/configure_secure_session_management.md)

### 6. Configure Secure Session Management

*   **Mitigation Strategy:** Secure Session Cookies (HTTPS Only, HTTP-Only, Secure Flag)
*   **Description:**
    1.  **Locate `context.xml`:** Open the `context.xml` file for your web application. This is typically located in `$CATALINA_BASE/conf/context.xml` or within your application's `META-INF` directory. If you want to apply it globally, modify `$CATALINA_HOME/conf/context.xml`.
    2.  **Add or Modify `CookieProcessor`:** Inside the `<Context>` element, add or modify the `<CookieProcessor>` element:
        ```xml
        <Context ...>
          <CookieProcessor className="org.apache.tomcat.util.http.Rfc6265CookieProcessor"
                           sameSiteCookies="strict"
                           secure="true"
                           httpOnly="true"/>
        </Context>
        ```
        *   `className="org.apache.tomcat.util.http.Rfc6265CookieProcessor"`:  Specifies the cookie processor.
        *   `sameSiteCookies="strict"`: (Optional but recommended) Helps prevent CSRF attacks.
        *   `secure="true"`: Ensures cookies are only sent over HTTPS.
        *   `httpOnly="true"`: Prevents client-side JavaScript from accessing the cookie.
    3.  **Enforce HTTPS:** Ensure your application and Tomcat are configured to enforce HTTPS for all sensitive operations and session management.
    4.  **Save `context.xml`:** Save the changes.
    5.  **Restart Tomcat:** Restart Tomcat.
    6.  **Inspect Cookies:** Use browser developer tools to inspect the session cookies set by your application. Verify that the `Secure` and `HttpOnly` flags are set and that cookies are only transmitted over HTTPS.
*   **Threats Mitigated:**
    *   **Session Hijacking (High Severity):**  If session cookies are not secure, attackers can intercept them over insecure HTTP connections or through XSS attacks and impersonate legitimate users.
    *   **Cross-Site Scripting (XSS) based Session Theft (High Severity):** `HttpOnly` flag mitigates session theft via XSS by preventing JavaScript access to session cookies.
    *   **Cross-Site Request Forgery (CSRF) (Medium Severity):** `SameSite` attribute (strict mode) provides some protection against CSRF attacks.
*   **Impact:**
    *   **Session Hijacking:** High reduction. `Secure` flag significantly reduces the risk of session hijacking over insecure connections.
    *   **Cross-Site Scripting (XSS) based Session Theft:** High reduction. `HttpOnly` flag effectively prevents JavaScript-based session theft.
    *   **Cross-Site Request Forgery (CSRF):** Medium reduction. `SameSite` provides a good level of CSRF protection in modern browsers.
*   **Currently Implemented:** Partially implemented. `secure="true"` and `httpOnly="true"` are set in the global `context.xml` in production and staging environments. `sameSiteCookies="strict"` is not yet implemented.
*   **Missing Implementation:** Implement `sameSiteCookies="strict"` in `context.xml` across all environments.  Thoroughly review application code to ensure HTTPS is enforced for all session-related operations and sensitive data handling.

## Mitigation Strategy: [Remove Example Web Applications](./mitigation_strategies/remove_example_web_applications.md)

### 7. Remove Example Applications

*   **Mitigation Strategy:** Remove Example Web Applications
*   **Description:**
    1.  **Locate `webapps` Directory:** Navigate to the `webapps` directory in your Tomcat installation (e.g., `$CATALINA_HOME/webapps`).
    2.  **Identify Example Applications:** Identify the directories for example applications, typically named `examples`, `docs`, `manager`, and `host-manager`.
    3.  **Delete Directories:** Delete these directories (`examples`, `docs`, `manager`, `host-manager`) from the `webapps` directory.
    4.  **Restart Tomcat:** Restart Tomcat.
    5.  **Verify Removal:** Attempt to access the example applications in a browser (e.g., `http://your-server:8090/examples/`). Verify that you receive a 404 error.
*   **Threats Mitigated:**
    *   **Vulnerabilities in Example Applications (Medium to High Severity):** Example applications may contain known vulnerabilities or be poorly maintained, providing an easy entry point for attackers.
    *   **Information Disclosure (Low Severity):** Example applications can sometimes inadvertently disclose information about the server environment.
*   **Impact:**
    *   **Vulnerabilities in Example Applications:** High reduction. Removing the applications eliminates the risk of exploiting vulnerabilities within them.
    *   **Information Disclosure:** Low reduction. Reduces potential minor information leaks.
*   **Currently Implemented:** Implemented in production and staging environments. Example applications are removed during the deployment process.
*   **Missing Implementation:** Ensure the removal of example applications is consistently part of the deployment process for all environments.  Document this step in deployment procedures.

## Mitigation Strategy: [Regularly Update Tomcat](./mitigation_strategies/regularly_update_tomcat.md)

### 8. Keep Tomcat Updated

*   **Mitigation Strategy:** Regularly Update Tomcat
*   **Description:**
    1.  **Monitor Security Announcements:** Subscribe to the Apache Tomcat security mailing list and regularly check the Apache Tomcat website for security advisories.
    2.  **Download Latest Version:** When a new stable version or patch is released, download it from the official Apache Tomcat website.
    3.  **Plan Upgrade:** Plan a maintenance window for upgrading Tomcat.
    4.  **Backup Configuration:** Before upgrading, back up your current Tomcat configuration directory (`conf`), web applications (`webapps`), and any other important data.
    5.  **Perform Upgrade:** Follow the official Tomcat upgrade instructions. This usually involves replacing the Tomcat installation directory with the new version while preserving your configuration and web applications (or migrating them as needed).
    6.  **Test Thoroughly:** After upgrading, thoroughly test your applications to ensure compatibility and proper functionality with the new Tomcat version.
    7.  **Rollback Plan:** Have a rollback plan in case the upgrade introduces issues.
*   **Threats Mitigated:**
    *   **Known Tomcat Vulnerabilities (High Severity):**  Outdated Tomcat versions are susceptible to publicly known vulnerabilities that attackers can exploit. Regular updates patch these vulnerabilities.
*   **Impact:**
    *   **Known Tomcat Vulnerabilities:** High reduction. Patching vulnerabilities significantly reduces the risk of exploitation.
*   **Currently Implemented:** Partially implemented. Tomcat is updated periodically, but not on a strict schedule tied to security advisories.
*   **Missing Implementation:** Implement a process for regularly monitoring security advisories and applying Tomcat updates promptly, especially for critical security patches.

## Mitigation Strategy: [Configure Connection Limits](./mitigation_strategies/configure_connection_limits.md)

### 9. Connection Limits

*   **Mitigation Strategy:** Configure Connection Limits
*   **Description:**
    1.  **Locate `server.xml`:** Open the `server.xml` file in the Tomcat `conf` directory.
    2.  **Modify Connector Element:** Find the `<Connector port="8443" ... secure="true" scheme="https" ...>` element (and the HTTP connector if enabled).
    3.  **Set Connection Limit Attributes:** Add or modify the following attributes within the `<Connector>` element:
        *   `maxConnections="200"`: Sets the maximum number of concurrent connections that Tomcat will accept and process at any given time. Adjust the value based on your server capacity and expected traffic.
        *   `acceptCount="100"`: Specifies the maximum queue length for incoming connection requests when `maxConnections` is reached. Requests exceeding this queue will be refused.
        *   `connectionTimeout="20000"`: Sets the timeout in milliseconds for establishing a connection. Connections that take longer than this to establish will be closed.
    4.  **Save `server.xml`:** Save the changes.
    5.  **Restart Tomcat:** Restart Tomcat.
    6.  **Monitor Connections:** Monitor Tomcat's connection metrics to ensure the limits are appropriate and effective in preventing resource exhaustion.
*   **Threats Mitigated:**
    *   **Denial of Service (DoS) Attacks (Medium to High Severity):** Limiting connections prevents attackers from overwhelming the server with excessive connection requests, leading to resource exhaustion and service unavailability.
*   **Impact:**
    *   **Denial of Service (DoS) Attacks:** Medium to High reduction. Connection limits help protect against connection-based DoS attacks.
*   **Currently Implemented:** Partially implemented. `maxConnections` is set to a default value in production and staging environments, but `acceptCount` and `connectionTimeout` might not be explicitly configured or optimally tuned.
*   **Missing Implementation:** Review and explicitly configure `maxConnections`, `acceptCount`, and `connectionTimeout` in `server.xml` across all environments. Tune these values based on performance testing and expected traffic patterns.

## Mitigation Strategy: [Enable Detailed Logging](./mitigation_strategies/enable_detailed_logging.md)

### 10. Enable Detailed Logging

*   **Mitigation Strategy:** Enable Detailed Logging
*   **Description:**
    1.  **Locate `logging.properties`:** Open the `logging.properties` file in the Tomcat `conf` directory (e.g., `$CATALINA_HOME/conf/logging.properties`).
    2.  **Configure Log Levels:** Review and adjust the log levels for different loggers. To increase detail, set log levels to `FINE`, `FINER`, or `FINEST` for relevant loggers. For example, to increase logging for access logs and security-related events:
        ```properties
        org.apache.catalina.level = FINE
        org.apache.coyote.level = FINE
        ```
    3.  **Configure Access Logs (if not already enabled):** Ensure access logs are enabled in `server.xml`. Look for the `<Valve className="org.apache.catalina.valves.AccessLogValve" ...>` element. If it's commented out, uncomment it and configure the `directory`, `prefix`, `suffix`, `pattern`, and other attributes as needed. A common pattern is `%h %l %u %t "%r" %s %b` (for remote host, remote logname, remote user, timestamp, request line, status code, bytes sent).
    4.  **Save `logging.properties` and `server.xml`:** Save the changes.
    5.  **Restart Tomcat:** Restart Tomcat.
    6.  **Review Logs:** Check the Tomcat logs (e.g., `catalina.out`, access logs) to ensure the increased logging detail is captured.
*   **Threats Mitigated:**
    *   **Insufficient Logging for Security Auditing and Incident Response (Medium Severity):**  Lack of detailed logs hinders security investigations, incident response, and the ability to detect and analyze security breaches.
*   **Impact:**
    *   **Insufficient Logging for Security Auditing and Incident Response:** Medium reduction. Detailed logging provides valuable data for security analysis and incident handling.
*   **Currently Implemented:** Basic logging is enabled by default. Access logs are configured in production and staging environments. Detailed logging levels are not consistently configured across all environments.
*   **Missing Implementation:** Review and enhance logging configurations in `logging.properties` to capture more detailed information relevant to security auditing. Ensure consistent logging configurations across all environments. Define specific loggers and levels to monitor for security-related events.

