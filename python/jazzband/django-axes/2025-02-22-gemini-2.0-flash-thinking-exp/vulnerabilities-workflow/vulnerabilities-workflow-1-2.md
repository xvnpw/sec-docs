- **Vulnerability Name:** IP Spoofing Bypass of Brute Force Protection  
  - **Description:**  
    - The module responsible for extracting the client’s IP address (in `axes/helpers.py` via the function `get_client_ip_address`) delegates this task to the django‐ipware package.
    - django‐ipware examines HTTP headers (e.g. “X-Forwarded-For”) along with configuration settings (such as `AXES_IPWARE_PROXY_ORDER`, `AXES_IPWARE_PROXY_COUNT`, `AXES_IPWARE_PROXY_TRUSTED_IPS`, and `AXES_IPWARE_META_PRECEDENCE_ORDER`) to determine the client IP.
    - When the application is deployed behind a reverse proxy but the administrator fails to enforce strict, trusted-proxy settings, an external attacker may supply custom HTTP headers to forge the IP address.
    - By varying the IP address on each login attempt, the attacker can prevent failures from accumulating on a single record and thereby bypass the brute-force lockout mechanism.
  - **Impact:**  
    - An attacker may bypass the brute-force protection provided by Axes and perform unlimited failed login attempts.
    - This can eventually lead to account compromise if the attacker succeeds in guessing the correct credentials.
    - The lockout mechanism is undermined because the failure counter is effectively “split” across many spoofed IP addresses.
  - **Vulnerability Rank:** High  
  - **Currently Implemented Mitigations:**  
    - In the helper function, the project calls the django‐ipware API with configurable settings:
      ```python
      client_ip_address, _ = ipware.ip.get_client_ip(
          request,
          proxy_order=settings.AXES_IPWARE_PROXY_ORDER,
          proxy_count=settings.AXES_IPWARE_PROXY_COUNT,
          proxy_trusted_ips=settings.AXES_IPWARE_PROXY_TRUSTED_IPS,
          request_header_order=settings.AXES_IPWARE_META_PRECEDENCE_ORDER,
      )
      ```
    - When deployed behind a reverse proxy with proper trusted settings, this mechanism can reliably determine the client’s true IP address.
  - **Missing Mitigations:**  
    - No safe defaults are enforced for the proxy-related settings, leaving the determination of the “real” client IP fully dependent on administrator configuration.
    - There is no built-in validation to reject IP values derived from untrusted headers.
    - Additional safeguards (such as checking that header-derived IPs belong to a known proxy range or pattern) are not implemented.
  - **Preconditions:**  
    - The application is deployed behind a reverse proxy.
    - The proxy configuration is not hard‐coded or strictly enforced (i.e. the trusted proxy settings are misconfigured or left at default).
    - An attacker is able to control or inject HTTP headers (e.g. “X-Forwarded-For”) into login requests.
  - **Source Code Analysis:**  
    - In `axes/helpers.py`, the function `get_client_ip_address` uses django‐ipware:
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
    - Because the returned IP depends on HTTP headers and administrator‐supplied configuration, an attacker who varies these headers can force each login failure to be counted from what the system believes is a new IP.
  - **Security Test Case:**  
    1. **Preparation:**  
       - Deploy the application with django-axes enabled and with default (or misconfigured) proxy settings (e.g. without strict values for `AXES_IPWARE_PROXY_TRUSTED_IPS`).
       - Identify the publicly accessible login endpoint.
    2. **Execution:**  
       - Using a tool such as cURL or Postman, send an HTTP POST request to the login endpoint with invalid credentials.
       - Include a custom header, for example:  
         ```
         X-Forwarded-For: 203.0.113.10
         ```
       - Check the logging or the database record to verify that the failed attempt is recorded with IP “203.0.113.10.”
       - Repeat with additional requests, each time changing the “X-Forwarded-For” header (for instance, “203.0.113.11”, “203.0.113.12”, etc.).
    3. **Verification:**  
       - Confirm that each request is treated as coming from a unique IP address.
       - Verify that the failure count on any one IP address never reaches the lockout threshold, even though the total number of failed attempts is high.
       - Conclude that brute-force protection is bypassed by IP spoofing.

- **Vulnerability Name:** User Agent Variation Bypass of Brute Force Protection  
  - **Description:**  
    - The AxesDatabaseHandler groups failed login attempts using a composite key that includes the username, IP address, and user agent.
    - In the `AxesProxyHandler.update_request` function, the value for `request.axes_user_agent` is obtained by calling `get_client_user_agent(request)`, which directly reflects the value of the HTTP “User-Agent” header.
    - An external attacker can submit failed login attempts with a different “User-Agent” header in each attempt.
    - As a result, each attempt is recorded with a distinct combination—even though the username and IP address remain the same—preventing the aggregate failure count from reaching the configured threshold.
  - **Impact:**  
    - The brute force protection mechanism is undermined because the system fails to aggregate failed attempts correctly when the user agent is varied.
    - An attacker can attempt an unlimited number of password guesses by simply changing the “User-Agent” header in each request.
    - This increases the likelihood of successful account compromise via brute-force attacks.
  - **Vulnerability Rank:** High  
  - **Currently Implemented Mitigations:**  
    - The request attribute `axes_user_agent` is set in the proxy handler via:
      ```python
      request.axes_user_agent = get_client_user_agent(request)
      ```
    - However, no normalization or validation is performed on the “User-Agent” header before it is used as part of the grouping key.
  - **Missing Mitigations:**  
    - There is no mechanism to normalize or canonicalize the “User-Agent” value to prevent trivial variations.
    - The lockout grouping configuration does not exclude or safely process the “User-Agent” header, even when it is not needed to identify an attacker.
    - Additional grouping logic that aggregates attempts regardless of user agent differences is missing.
  - **Preconditions:**  
    - The application’s brute force protection groups failures using the user-supplied “User-Agent” value as part of the key.
    - The attacker can freely set or change the “User-Agent” header on login requests.
    - No additional normalization or filtering of the “User-Agent” header is in place.
  - **Source Code Analysis:**  
    - In `axes/handlers/proxy.py`, the update routine sets:
      ```python
      request.axes_user_agent = get_client_user_agent(request)
      ```
    - Later, in `axes/handlers/database.py` within the `user_login_failed` method, the AccessAttempt record is created (or updated) with:
      ```python
      attempt, created = AccessAttempt.objects.select_for_update().get_or_create(
          username=username,
          ip_address=request.axes_ip_address,
          user_agent=request.axes_user_agent,
          defaults={ ... failures_since_start: 1 ... }
      )
      ```
    - Because the `user_agent` field directly reflects the value provided by the client without any normalization, an attacker can use a slightly different “User-Agent” string on each request.
    - This leads to multiple records being created rather than consolidating failures under one identifier, thereby keeping each record’s failure count low.
  - **Security Test Case:**  
    1. **Preparation:**  
       - Deploy the application with brute force lockout enabled and configured such that the grouping of failed attempts takes the “User-Agent” into account.
       - Identify the public login endpoint.
    2. **Execution:**  
       - Using a tool like cURL or Postman, submit a failed login attempt with a specific “User-Agent” header (e.g., “User-Agent: TestAgent1”).
       - Verify that the failure is recorded (via logs or database entries).
       - Send additional failed login attempts using the same username and originating IP but change the “User-Agent” for each attempt (e.g., “TestAgent2”, “TestAgent3”, etc.).
    3. **Verification:**  
       - Check that each login failure is recorded as a separate AccessAttempt record.
       - Confirm that despite the total number of failed attempts exceeding the overall threshold, no single record’s failure count reaches the limit.
       - Conclude that an attacker can bypass the brute force lockout simply by varying the “User-Agent” header.