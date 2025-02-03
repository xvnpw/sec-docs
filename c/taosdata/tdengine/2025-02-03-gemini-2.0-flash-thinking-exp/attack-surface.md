# Attack Surface Analysis for taosdata/tdengine

## Attack Surface: [Unprotected TDengine Server Ports](./attack_surfaces/unprotected_tdengine_server_ports.md)

*   **Description:** TDengine server ports (TCP 6030, UDP 6030, and potentially 6041 for RESTful) are exposed to untrusted networks without proper access control.
*   **TDengine Contribution:** TDengine *requires* these ports to be open for client connections and cluster communication. Default configurations might expose these ports widely without sufficient warning or guidance on secure configuration.
*   **Example:** An attacker from the internet can directly connect to the exposed TDengine port and attempt to exploit vulnerabilities in the TDengine server software itself, brute-force authentication, or launch denial-of-service attacks.
*   **Impact:** Unauthorized access to data, data manipulation, denial of service, potential server compromise and complete system takeover if vulnerabilities in `taosd` are exploited.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Implement strict firewall rules to restrict access to TDengine ports only from trusted networks or specific IP ranges.
    *   Utilize network segmentation to isolate the TDengine server within a dedicated and secured network zone, minimizing exposure to broader networks.
    *   Disable the RESTful API (port 6041) entirely if it is not actively required. If necessary, implement strong authentication and authorization specifically for the REST API and restrict its access.

## Attack Surface: [SQL Injection Vulnerabilities (TDengine SQL Specific)](./attack_surfaces/sql_injection_vulnerabilities__tdengine_sql_specific_.md)

*   **Description:** Applications dynamically construct TDengine SQL queries using unsanitized user input, leading to potential SQL injection attacks *specifically within the context of TDengine SQL syntax and features*.
*   **TDengine Contribution:** TDengine utilizes its own SQL-like query language (TDengine SQL).  Improper handling of user input when constructing these TDengine SQL queries directly creates the vulnerability. The specific syntax and functions of TDengine SQL must be considered during sanitization.
*   **Example:** An application takes user input intended for filtering data based on a tag value and directly concatenates it into a `SELECT` query without proper escaping or parameterization. An attacker injects malicious TDengine SQL code within the input, potentially bypassing intended data access restrictions or extracting sensitive information from other time-series databases within the TDengine instance.
*   **Impact:** Data breach, unauthorized data access across different databases within TDengine, data modification or deletion, potential for limited command execution within the TDengine server context (depending on internal TDengine execution model and any undiscovered vulnerabilities).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Utilize Parameterized Queries/Prepared Statements:**  Employ parameterized queries or prepared statements offered by TDengine client libraries. This method inherently separates SQL code structure from user-provided data, preventing injection.
    *   **Strict Input Sanitization and Validation:**  If parameterized queries are not feasible in certain scenarios, rigorously sanitize and validate *all* user inputs before incorporating them into TDengine SQL queries.  This must be done with awareness of TDengine SQL syntax and potential injection points. Use allow-lists and escape special characters specific to TDengine SQL.
    *   **Principle of Least Privilege (Database Level):**  Configure TDengine user accounts with the minimum necessary privileges required for their intended application functions. This limits the potential damage from a successful SQL injection attack by restricting what actions the compromised user can perform.

## Attack Surface: [Weak or Default Credentials for TDengine Accounts](./attack_surfaces/weak_or_default_credentials_for_tdengine_accounts.md)

*   **Description:** TDengine user accounts, especially administrative accounts, are configured with easily guessable weak passwords or left at default credentials.
*   **TDengine Contribution:** TDengine's authentication system relies on username/password pairs.  The initial setup or lack of enforced password policies within TDengine directly contributes to this vulnerability if administrators do not proactively secure accounts.
*   **Example:** An administrator neglects to change the default password for the 'root' user or sets a simple password like "password123". An attacker can easily guess or brute-force these weak credentials to gain administrative access to the TDengine server.
*   **Impact:** Complete unauthorized access to the TDengine database system, full data breach, unrestricted data manipulation and deletion, denial of service capabilities, and potential for complete server compromise if administrative privileges are exploited to access the underlying operating system (though less direct, initial database access is the primary risk).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Mandatory Strong Password Policy:** Implement and enforce a robust password policy for *all* TDengine user accounts, requiring strong passwords with sufficient complexity, length, and regular rotation.
    *   **Immediate Default Password Changes:**  Force or strongly guide administrators to immediately change all default passwords during the initial TDengine setup process.
    *   **Account Lockout Mechanisms:**  Enable account lockout policies within TDengine to automatically block accounts after a certain number of failed login attempts, effectively mitigating brute-force password attacks.
    *   **Consider Multi-Factor Authentication (MFA) if feasible:** Explore the possibility of integrating MFA for TDengine authentication if supported by TDengine itself or through integration with external authentication providers (though direct TDengine MFA might be limited, explore options at the application level if critical).

