## Vulnerability List

- Vulnerability Name: Throttling Bypass via X-Forwarded-For Header Manipulation

- Description:
    An attacker can bypass IP-based throttling mechanisms (like `AnonRateThrottle`, `UserRateThrottle`) by manipulating the `X-Forwarded-For` HTTP header. This vulnerability occurs because the application might not be correctly configured to handle requests behind a proxy, specifically regarding the number of proxies (`NUM_PROXIES` setting). If `NUM_PROXIES` is not set or incorrectly set, the system might use the attacker-controlled IP address from the `X-Forwarded-For` header instead of the actual client IP address for throttling.

    Steps to trigger vulnerability:
    1. Application is deployed behind a proxy (e.g., CDN, load balancer).
    2. Throttling is implemented using `AnonRateThrottle` or `UserRateThrottle` which rely on IP address for rate limiting.
    3. Attacker sends multiple requests to the application, including a crafted `X-Forwarded-For` header with a spoofed IP address.
    4. If `NUM_PROXIES` setting is not properly configured to reflect the number of proxies in front of the application, the throttling mechanism will use the spoofed IP from `X-Forwarded-For` instead of the actual client IP.
    5. Attacker can bypass throttling by changing the spoofed IP address in subsequent requests, as the system will treat each request as coming from a different IP.

- Impact:
    Successful exploitation of this vulnerability allows attackers to bypass rate limiting, potentially leading to:
    * Brute-force attacks: Attackers can make unlimited login attempts or other security-sensitive actions without being throttled.
    * Resource exhaustion: Attackers can send a high volume of requests, overwhelming the server and potentially leading to service disruptions or increased operational costs.
    * Circumvention of security measures: Throttling is often used as a security measure to protect against various attacks. Bypassing it weakens the overall security posture of the application.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    The `SimpleRateThrottle` class in `ninja/throttling.py` includes logic to handle proxy headers using the `NUM_PROXIES` setting from `ninja.conf.settings`.
    ```python
    def get_ident(self, request: HttpRequest) -> Optional[str]:
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            xff_hosts = xff.split(",")
            num_proxies = settings.NUM_PROXIES
            if num_proxies is None:
                return xff_hosts[-1].strip()  # default behavior
            elif num_proxies >= 1:
                return xff_hosts[-(num_proxies + 1)].strip()  # last proxy addr in the list
            else:  # num_proxies == 0
                return xff_hosts[0].strip() # client addr (first in the list)

        return request.META.get("REMOTE_ADDR")
    ```
    This code attempts to retrieve the correct client IP based on `NUM_PROXIES`. However, misconfiguration of `NUM_PROXIES` leads to vulnerability.

- Missing Mitigations:
    * **Configuration Guidance and Best Practices:** The project lacks clear documentation and warnings about the importance of correctly configuring `NUM_PROXIES` when deploying behind proxies. This should include guidelines on how to determine the correct value for `NUM_PROXIES` based on the deployment environment.
    * **Automatic Proxy Detection (Optional but Recommended):**  While not always feasible, exploring options for automatic detection of proxy setups or providing tools to help administrators determine the correct `NUM_PROXIES` value could improve security.
    * **Rate Limiting based on other factors:** Consider supplementing or offering alternatives to solely IP-based throttling, such as token-based or user-account based throttling, which are less susceptible to IP spoofing.

- Preconditions:
    1. Django Ninja application is deployed behind at least one proxy server (e.g., CDN, load balancer, reverse proxy).
    2. IP-based throttling is enabled using `AnonRateThrottle` or `UserRateThrottle`.
    3. The `NUM_PROXIES` setting in Django settings is either not set, set to `None` (default, which might be insecure in proxy setups), or incorrectly configured for the actual number of proxies.

- Source Code Analysis:
    1. **`ninja/throttling.py` - `SimpleRateThrottle.get_ident()`:**
        - The `get_ident` method retrieves the client's IP address.
        - It first checks for the `HTTP_X_FORWARDED_FOR` header from `request.META`.
        - If the header is present, it splits the header value by commas into a list of IP addresses (`xff_hosts`).
        - It retrieves the `NUM_PROXIES` setting from `ninja.conf.settings`.
        - **Case 1: `num_proxies is None` (Default):** It returns `xff_hosts[-1].strip()`, which is the *last* IP address in the `X-Forwarded-For` header. In a typical proxy setup, the last IP is usually the *proxy's* IP, not the client's original IP. This is the default behavior and is vulnerable if `NUM_PROXIES` is not configured when behind proxies.
        - **Case 2: `num_proxies >= 1`:** It returns `xff_hosts[-(num_proxies + 1)].strip()`. This attempts to get the client IP by going back `num_proxies + 1` hops in the `X-Forwarded-For` list. For example, if `NUM_PROXIES = 1`, it takes the second to last IP. This is intended for setups with a known number of proxies.
        - **Case 3: `num_proxies == 0`:** It returns `xff_hosts[0].strip()`, which is the *first* IP in the `X-Forwarded-For` list. This is meant to be the client IP when `NUM_PROXIES` is set to 0, assuming the first IP is the originating client.
        - If the `HTTP_X_FORWARDED_FOR` header is not present, it falls back to `request.META.get("REMOTE_ADDR")`, which is the IP address of the immediate connection to the server (typically the proxy in a proxy setup, or the client directly if no proxy).

    2. **`ninja/conf.py` - `Settings.NUM_PROXIES` (Not Provided in PROJECT FILES, but assumed based on description):**
        - The `NUM_PROXIES` setting is defined with a default value of `None`.
        - There is likely no explicit documentation or warning in the code itself about the security implications of misconfiguring `NUM_PROXIES`.

    3. **`tests/test_throttling.py` - `test_proxy_throttle()` (Not Provided in PROJECT FILES, but assumed based on description):**
        - Tests exist that cover different `NUM_PROXIES` configurations. However, these tests primarily focus on the functionality of IP identification and do not explicitly highlight or test for the security vulnerability of throttling bypass via header manipulation when `NUM_PROXIES` is misconfigured or not set in a proxy environment.

- Security Test Case:
    1. **Setup:** Deploy a Django Ninja application with IP-based throttling (`AnonRateThrottle` applied to a publicly accessible endpoint) behind an Nginx reverse proxy. Ensure the Django application is configured to use the default `NUM_PROXIES = None` or explicitly set it to `None`.
    2. **Baseline Test:** Send several requests from a single IP address to the throttled endpoint *without* the `X-Forwarded-For` header. Verify that after exceeding the rate limit, the server correctly applies throttling and returns 429 status codes.
    3. **Throttling Bypass Attempt via X-Forwarded-For:**
        - Use a tool like `curl` or a Python script to send requests to the throttled endpoint from the same source IP address used in the baseline test.
        - For each request, include the `X-Forwarded-For` header, crafting it to contain a list of IPs. The *last* IP in the list should be the IP address of your Nginx proxy server. The IP addresses *before* the proxy IP in the list should be spoofed, unique IP addresses. For example: `X-Forwarded-For: 1.1.1.1, <Nginx_Proxy_IP>`, `X-Forwarded-For: 1.1.1.2, <Nginx_Proxy_IP>`, `X-Forwarded-For: 1.1.1.3, <Nginx_Proxy_IP>`, and so on.  Increment the spoofed IP (1.1.1.x) for each subsequent request.
        - Observe the responses. If the vulnerability is present, the server will continue to respond with 200 OK even after exceeding the intended rate limit. This is because the default `NUM_PROXIES = None` configuration causes `get_ident()` to use the *last* IP in `X-Forwarded-For` (the proxy IP), or in some cases, the attacker-controlled spoofed IP, effectively bypassing the IP-based throttling.
    4. **Verification of Mitigation:**
        - Correctly configure the Django Ninja application by setting `NUM_PROXIES = 1` (assuming there is one reverse proxy in front).
        - Repeat steps 2 and 3 (baseline and bypass attempts).
        - With `NUM_PROXIES = 1`, the throttling should now be correctly applied based on the *actual* client IP address (which Ninja will extract from the `X-Forwarded-For` header). The bypass attempt using spoofed `X-Forwarded-For` headers should no longer be effective. After exceeding the rate limit, the server should return 429 status codes, even with manipulated `X-Forwarded-For` headers.