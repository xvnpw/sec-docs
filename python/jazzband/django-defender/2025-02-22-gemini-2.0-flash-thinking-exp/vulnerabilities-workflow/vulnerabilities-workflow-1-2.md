After reviewing the provided list of vulnerabilities and applying the specified filters, here is the updated list in markdown format, including only the vulnerabilities that meet the criteria:

---

- **Vulnerability Name:** Default Admin Credentials Exposed in Documentation  
  **Description:**  
  The project’s README (located at `/code/exampleapp/readme.md`) explicitly documents a default administrator username and password (“admin:password”). An external attacker could retrieve this file from the public repository or even in a deployed instance and then try these hardcoded credentials on the admin login page.  
  **Impact:**  
  If the default credentials are not changed for a production deployment, an attacker would gain administrator access to the application. This could allow full control over the system, data exfiltration, configuration changes, or further lateral movement.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  There are no active code-level mitigations. The default value is documented rather than being securely sourced from a protected configuration.  
  **Missing Mitigations:**  
  – Remove or obscure default credentials from public documentation.  
  – Require secure admin credential configuration (for example, enforcing the use of environment variables for sensitive credentials).  
  **Preconditions:**  
  – The application is deployed in a production environment without replacing the hardcoded test credential.  
  – The attacker is able to access the published documentation (via the public repository or an exposed help page).  
  **Source Code Analysis:**  
  The file `/code/exampleapp/readme.md` contains the line:  
  > admin password is ``admin:password``  
  No subsequent code forces a check for unique administrator credentials. If an instance is launched with these credentials (or if the credentials are not updated during deployment), an attacker can simply navigate to `/admin/` and log in using the provided username “admin” and password “password.”  
  **Security Test Case:**  
  1. Access the public instance of the application and navigate to the `/admin/` login page.  
  2. Use “admin” (username) and “password” (password) to attempt a login.  
  3. Verify that the login is successful and that administrative features are accessible.  
  4. Document the breach of access if the instance accepts the hardcoded credentials.

---