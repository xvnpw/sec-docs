- **Vulnerability Name:** IP Address Spoofing via Untrusted HTTP Headers

  - **Description:**  
    The core functionality of the library is to determine the “real” IP address of a client by reading HTTP headers from Django’s request object. In its default configuration, the function `get_client_ip` (located in `ipware/ip.py`) extracts client IP information from a set of headers (such as `X_FORWARDED_FOR` and others) without enforcing any additional validation or cryptographic verification of the header contents. An external attacker can craft an HTTP request with a forged header (for example, sending `X-Forwarded-For: 1.2.3.4`) when connecting directly to the publicly accessible instance. This causes the library to return the spoofed IP address. An attacker might trigger this vulnerability by:  
    1. Connecting directly (or via a misconfigured proxy) to the Django instance.  
    2. Injecting malicious header values (e.g. `X-Forwarded-For`) with an arbitrary IP.  
    3. Relying on the returned spoofed IP in application logic (if the application uses it for security-critical decisions such as access control, rate limiting, or IP-based whitelisting).

  - **Impact:**  
    If the application uses the client IP address for authentication, access control, logging, or rate limiting, an attacker can manipulate the value to bypass security measures or hide their true origin. This can lead to unauthorized access, evasion of restrictions, or inaccurate logging that impairs forensic investigations.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**  
    - The README clearly warns that there is “no perfect out-of-the-box solution against fake IP addresses” and advises advanced users to use features like trusted proxies (using `proxy_trusted_ips`) or a known proxy count (`proxy_count`) along with other firewall measures.
    - The library design provides optional parameters (e.g., `proxy_trusted_ips`) that let developers narrow the trust boundary, but these must be explicitly configured.

  - **Missing Mitigations:**  
    - There is no enforced, built-in validation of header values against a secure, connection-based or cryptographically secured source.
    - The library lacks stricter defaults that would—for instance—reject or ignore client-supplied IP headers unless the request is coming from a known and validated proxy.
    - Input sanitation or integrity checks on raw header values are not performed within the library itself.

  - **Preconditions:**  
    - The attacker must be able to directly connect to the Django instance — for example, when it is not properly placed behind a trusted reverse proxy or when the reverse proxy is misconfigured.
    - The application must be using the output of `get_client_ip()` for security-sensitive logic without additional verification.
    - No additional middleware or firewall is in place to filter or validate the incoming headers.

  - **Source Code Analysis:**  
    1. **Location:** In `ipware/ip.py`, the function `get_client_ip` is defined.  
    2. **Header Extraction:** The function retrieves HTTP metadata from `request.META` without performing further sanitation or verification; it relies on the header order given either by a Django setting or a developer-passed argument.  
    3. **IpWare Dependency:** An `IpWare` object is instantiated with parameters such as `precedence` (the header order), `leftmost` (boolean flag based on proxy_order), and optional filtering parameters (`proxy_count` and `proxy_list`).  
    4. **IP Determination:** The call `ip, _ = ipw.get_client_ip(request.META, True)` delegates the IP extraction to the underlying python-ipware, which operates directly on the headers it receives.  
    5. **No Additional Checks:** After obtaining the IP from python-ipware, the library casts it to a string and evaluates its `is_global` property but does not perform any validation to confirm that the header values originated from a trusted source.  
    6. **Visualization Overview:**  
       - **Input:** An HTTP request with a crafted header such as `HTTP_X_FORWARDED_FOR: "1.2.3.4"`.  
       - **Processing:**  
         a. `get_client_ip` reads `request.META` and passes it to an `IpWare` object.  
         b. The `IpWare` instance looks at the header values in the specified order (defaulting to the configuration in settings or provided request) without rejecting any forged values.  
         c. The spoofed IP ("1.2.3.4") is returned as the client IP.  
       - **Outcome:** The application receives an attacker-controlled IP address.
        
  - **Security Test Case:**  
    1. **Deployment:** Set up the Django application using django-ipware in an environment where the application’s endpoint is publicly accessible.  
    2. **Crafting the Request:** Use a tool like curl or Postman to send an HTTP request that includes a forged header. For example:  
       ```
       curl -H "X-Forwarded-For: 1.2.3.4" http://<target-domain>/
       ```  
    3. **Invocation:** The application must expose an endpoint (or testing script) that calls `get_client_ip(request)` and outputs the result. This could be a simple Django view that returns the client IP in the response body.  
    4. **Observation:** Verify that the application’s output shows "1.2.3.4" as the client IP and that the `is_routable` flag reflects the status of the supplied IP (e.g., `True` if globally routable).  
    5. **Conclusion:** The test case demonstrates that an attacker can influence the IP detection logic by manipulating the HTTP headers, proving the presence of the vulnerability.