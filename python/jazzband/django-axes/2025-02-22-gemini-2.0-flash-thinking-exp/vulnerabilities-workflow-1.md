Here is the combined list of vulnerabilities from the provided lists, with duplicates removed and formatted as markdown:

## Combined Vulnerability List for django-axes project

This list combines vulnerabilities identified in the django-axes project, removing duplicates and providing detailed information for each.

### 1. IP Spoofing Bypass of Brute Force Protection

- **Description:**
    - The django-axes project relies on the django-ipware package to determine the client's IP address. This process, implemented in `axes/helpers.py` within the `get_client_ip_address` function, inspects HTTP headers such as "X-Forwarded-For" and utilizes configurable settings like `AXES_IPWARE_PROXY_ORDER`, `AXES_IPWARE_PROXY_COUNT`, `AXES_IPWARE_PROXY_TRUSTED_IPS`, and `AXES_IPWARE_META_PRECEDENCE_ORDER`.
    - In scenarios where the application is deployed behind a reverse proxy, but the administrator fails to configure strict and trusted proxy settings, an external attacker gains the ability to manipulate HTTP headers to forge their IP address.
    - By altering the IP address with each login attempt, the attacker can effectively distribute failed login attempts across numerous spoofed IP addresses, preventing the brute-force lockout mechanism from triggering as failure counts are not accumulated on a single, genuine IP.

- **Impact:**
    - The primary impact is the circumvention of the brute-force protection offered by django-axes.
    - This allows an attacker to perform an unlimited number of failed login attempts without triggering account lockout.
    - Consequently, the risk of successful account compromise through credential guessing is significantly increased, as the lockout mechanism designed to thwart such attacks is rendered ineffective. The security of user accounts is weakened due to the bypassed protection.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The `get_client_ip_address` function in `axes/helpers.py` utilizes the django-ipware API with configurable settings to determine the client IP. The relevant code snippet is shown below:
      ```python
      client_ip_address, _ = ipware.ip.get_client_ip(
          request,
          proxy_order=settings.AXES_IPWARE_PROXY_ORDER,
          proxy_count=settings.AXES_IPWARE_PROXY_COUNT,
          proxy_trusted_ips=settings.AXES_IPWARE_PROXY_TRUSTED_IPS,
          request_header_order=settings.AXES_IPWARE_META_PRECEDENCE_ORDER,
      )
      ```
    - When properly configured with strict trusted proxy settings, this mechanism can accurately identify the true client IP address, offering mitigation in correctly set up environments.

- **Missing Mitigations:**
    - The project lacks safe default configurations for proxy-related settings. This absence places the responsibility of correctly determining the "real" client IP entirely on the administrator's configuration, without guiding defaults.
    - There's no built-in validation to automatically reject IP values that originate from untrusted headers. The system relies solely on configuration, which can be error-prone.
    - Additional security measures, such as verifying that header-derived IPs belong to a known proxy range or adhere to a specific pattern, are not implemented. This leaves a gap in defense against sophisticated spoofing attempts.

- **Preconditions:**
    - The application must be deployed behind a reverse proxy to create the conditions for header manipulation.
    - The reverse proxy configuration must not be strictly enforced or is misconfigured, specifically regarding trusted proxy settings. This misconfiguration is key to exploiting the vulnerability.
    - An attacker must have the capability to control or inject HTTP headers, such as "X-Forwarded-For," into login requests directed at the application.

- **Source Code Analysis:**
    - The vulnerability originates in `axes/helpers.py` within the `get_client_ip_address` function:
      ```python
      def get_client_ip_address(request: HttpRequest, use_ipware: Optional[bool] = None) -> Optional[str]:
          if use_ipware is None:
              use_ipware = IPWARE_INSTALLED
          if use_ipware:
              client_ip_address, _ = ipware.ip.get_client_ip(
                  request,
                  proxy_order=settings.AXES_IPWARE_PROXY_ORDER,
                  proxy_count=settings.AXES_IPWARE_PROXY_COUNT,
                  proxy_trusted_ips=settings.AXES_IPWARE_PROXY_TRUSTED_IPS,
                  request_header_order=settings.AXES_IPWARE_META_PRECEDENCE_ORDER,
              )
              return client_ip_address
          return request.META.get("REMOTE_ADDR", None)
      ```
    - The vulnerability arises because the IP address determination is dependent on HTTP headers and administrator-supplied configuration. An attacker can exploit this by varying headers in each login attempt. This manipulation tricks the system into perceiving each failed login as originating from a distinct IP address. Consequently, login failures are not aggregated under a single IP, and the brute-force lockout, which depends on counting failures from a specific IP, is bypassed.

- **Security Test Case:**
    1. **Preparation:**
       - Deploy the application with django-axes enabled. Configure it with default or intentionally misconfigured proxy settings, specifically omitting strict values for `AXES_IPWARE_PROXY_TRUSTED_IPS`.
       - Identify the publicly accessible login endpoint of the application.
    2. **Execution:**
       - Utilize a tool such as cURL or Postman to send an HTTP POST request to the login endpoint. This request should include invalid login credentials to simulate a failed login attempt.
       - Incorporate a custom header in the request to spoof the IP address. For example:
         ```
         X-Forwarded-For: 203.0.113.10
         ```
       - Examine the application logs or database records to confirm that the failed login attempt is registered with the spoofed IP address "203.0.113.10."
       - Repeat the process, sending subsequent login requests with invalid credentials. For each request, modify the "X-Forwarded-For" header to use a different IP address (e.g., "203.0.113.11", "203.0.113.12", and so on).
    3. **Verification:**
       - Verify that each login request is treated by the application as originating from a unique IP address, corresponding to the spoofed IP in the header.
       - Confirm that the failure count associated with any single IP address does not reach the lockout threshold, even after a significant number of failed attempts.
       - Conclude that the brute-force protection mechanism is successfully bypassed through IP spoofing, as the system fails to aggregate failures from the attacker's actual source due to reliance on manipulable headers.

### 2. User Agent Variation Bypass of Brute Force Protection

- **Vulnerability Name:** User Agent Variation Bypass of Brute Force Protection (also known as Inconsistent Lockout Enforcement due to User Agent Parameter not being Considered by Default)

- **Description:**
    - The `AxesDatabaseHandler` in django-axes by default groups failed login attempts using a composite key that includes username, IP address, and user agent.
    - In the `AxesProxyHandler.update_request` function, the user agent value, stored as `request.axes_user_agent`, is directly derived from the HTTP “User-Agent” header using `get_client_user_agent(request)`.
    - An attacker can exploit this by sending failed login attempts, each with a different "User-Agent" header.
    - Consequently, every attempt is logged as a unique combination, even if the username and IP address remain constant. This behavior prevents the system from aggregating failure counts correctly, as each attempt appears distinct, and the configured lockout threshold is never reached for a single attacker.
    - In default configurations of django-axes, the `AXES_LOCKOUT_PARAMETERS` setting does not include `user_agent`. This means lockout is only enforced based on IP address by default. If an attacker changes their user agent after being locked out by IP, they can bypass the lockout and continue making login attempts from the same IP address.

- **Impact:**
    - The brute force protection mechanism's effectiveness is significantly reduced because the system fails to aggregate failed login attempts when the user agent is varied.
    - An attacker can attempt an unlimited number of password guesses by simply changing the “User-Agent” header in each request, or after being locked out by IP in default configurations.
    - This drastically increases the likelihood of successful account compromise through brute-force attacks, as the intended lockout protection is circumvented.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The project does provide configuration options to include `user_agent` in lockout parameters. Administrators can configure `AXES_LOCKOUT_PARAMETERS` to include `user_agent` to enforce lockout based on a combination of parameters, as documented.
    - In `axes/handlers/proxy.py`, the `axes_user_agent` attribute is set using:
      ```python
      request.axes_user_agent = get_client_user_agent(request)
      ```
    - However, by default, `AXES_LOCKOUT_PARAMETERS` is not set to include `user_agent`, and no normalization or validation is performed on the "User-Agent" header before it is used as part of the grouping key, if configured.

- **Missing Mitigations:**
    - The default `AXES_LOCKOUT_PARAMETERS` should be changed to include `user_agent` to provide more robust lockout enforcement out-of-the-box. Relying solely on IP address by default is insufficient.
    - There is no mechanism to normalize or canonicalize the “User-Agent” value to prevent trivial variations. Even if `user_agent` is included in `AXES_LOCKOUT_PARAMETERS`, the system is still vulnerable to slight variations in the User-Agent string.
    - The lockout grouping configuration does not offer options to exclude or safely process the “User-Agent” header when it is not deemed necessary for identifying an attacker.
    - The documentation could be improved to strongly recommend including `user_agent` in `AXES_LOCKOUT_PARAMETERS` and to highlight the security implications of not doing so. It should emphasize the increased risk of brute-force attacks due to this default setting.
    - Additional grouping logic that aggregates attempts regardless of minor user agent differences is missing.

- **Preconditions:**
    - Django-axes is installed and configured.
    - The application’s brute force protection groups failures using the user-supplied “User-Agent” value as part of the key (if `user_agent` is in `AXES_LOCKOUT_PARAMETERS`), or default settings are used where `AXES_LOCKOUT_PARAMETERS` does not include `user_agent`.
    - The attacker can freely set or change the “User-Agent” header on login requests.
    - No additional normalization or filtering of the “User-Agent” header is in place.

- **Source Code Analysis:**
    - In `axes/handlers/proxy.py`, the update routine sets the `axes_user_agent`:
      ```python
      request.axes_user_agent = get_client_user_agent(request)
      ```
    - Subsequently, in `axes/handlers/database.py` within the `user_login_failed` method, the `AccessAttempt` record is created (or updated) using `get_or_create`:
      ```python
      attempt, created = AccessAttempt.objects.select_for_update().get_or_create(
          username=username,
          ip_address=request.axes_ip_address,
          user_agent=request.axes_user_agent,
          defaults={ ... failures_since_start: 1 ... }
      )
      ```
    - The `get_client_parameters` function in `axes/helpers.py` determines the lockout parameters based on `AXES_LOCKOUT_PARAMETERS`. By default, this setting is `["ip_address"]`:
      ```python
      def get_client_parameters(username, ip_address, user_agent, request, credentials):
          """
          Returns a list of client parameters to filter access attempts and lockouts,
          based on AXES_LOCKOUT_PARAMETERS setting.
          """
          lockout_params_raw = settings.AXES_LOCKOUT_PARAMETERS
          if not lockout_params_raw:
              lockout_params_raw = ["ip_address"] # Default lockout parameter is IP address
          ...
      ```
    - Because the `user_agent` field directly reflects the client-provided value without normalization, and by default `user_agent` is not considered in lockout, an attacker can simply vary the “User-Agent” string or change user agent after IP lockout to bypass protection. This leads to multiple records being created rather than consolidating failures, keeping each record’s failure count below the lockout threshold.

- **Security Test Case:**
    1. **Setup:** Configure Django-axes with default settings (ensure `AXES_LOCKOUT_PARAMETERS` is not set in `settings.py`, or explicitly set it to only include `ip_address`).
    2. **Brute-force attempt 1 (User-Agent: UA-A):**
        - From attacker IP `ATTACKER_IP`, send login requests with invalid credentials for a user (e.g., `testuser`) with User-Agent `UA-A` (e.g., `User-Agent: TestAgentA`). Repeat this until the account is locked out based on IP. Verify lockout by attempting login again from `ATTACKER_IP` with UA-A - it should be blocked (e.g., return a 429 status code).
    3. **Bypass attempt (User-Agent: UA-B):**
        - Change User-Agent to `UA-B` (e.g., `User-Agent: TestAgentB`).
        - From the same attacker IP `ATTACKER_IP`, send another login request with invalid credentials for the same user (`testuser`).
        - Observe that the login attempt is *not* blocked (e.g., status 200 or 302, not 429). This demonstrates the bypass of IP-based lockout by changing User-Agent.
    4. **Verification (Optional, if `user_agent` is in `AXES_LOCKOUT_PARAMETERS`):**
        - Repeat steps 2 and 3 with `AXES_LOCKOUT_PARAMETERS` configured to include `user_agent`. In this case, changing User-Agent *should not* bypass the lockout after the threshold is reached for the IP and username combination, regardless of User-Agent variations.
    5. **Expected Result:** With default settings (or `AXES_LOCKOUT_PARAMETERS` not including `user_agent`), the attacker should be able to bypass the IP-based lockout by changing the User-Agent, proving the vulnerability. With `user_agent` included in `AXES_LOCKOUT_PARAMETERS` and assuming no normalization, the attacker *might* still bypass with trivial user-agent changes unless the system is configured to handle user-agent variations robustly.