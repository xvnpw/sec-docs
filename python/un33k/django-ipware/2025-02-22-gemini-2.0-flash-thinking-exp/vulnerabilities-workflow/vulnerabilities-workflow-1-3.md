### Vulnerability List:

#### Vulnerability 1: IP Address Spoofing via HTTP Header Manipulation

- Vulnerability Name: IP Address Spoofing via HTTP Header Manipulation
- Description:
    An attacker can spoof their IP address by manipulating HTTP headers such as `X-Forwarded-For`. The `django-ipware` library, by default, trusts these headers to determine the client's IP address based on a predefined precedence order. If the Django application is deployed without proper configuration of trusted proxies, an attacker can insert a fake IP address into these headers, which `django-ipware` will then incorrectly identify as the client's IP. This can lead to bypassing IP-based access controls, logging systems recording incorrect IP addresses, and potentially other security misconfigurations that rely on accurate IP address identification.

    Steps to trigger:
    1. An attacker sends an HTTP request to the Django application.
    2. The attacker includes a crafted `X-Forwarded-For` header in the request, containing a spoofed IP address. For example: `X-Forwarded-For: <spoofed_ip>`.
    3. The Django application uses `django-ipware` to retrieve the client's IP address from the request.
    4. `django-ipware`, following its default configuration and header precedence order, reads the spoofed IP address from the `X-Forwarded-For` header.
    5. The application incorrectly identifies the spoofed IP address as the client's IP.

- Impact:
    - **High**:  Successful IP address spoofing can lead to several critical security issues:
        - **Bypassing IP-based Access Control:** If the application uses IP addresses for authentication or authorization (e.g., allowlisting specific IPs), an attacker can bypass these controls by spoofing a permitted IP.
        - **Circumventing Rate Limiting:** Attackers can evade rate limiting mechanisms that are based on IP addresses by rotating spoofed IPs in their requests.
        - **Incorrect Logging and Auditing:** Security logs and audit trails will record the spoofed IP address instead of the attacker's actual IP, hindering incident response and forensic analysis.
        - **Session Hijacking Prevention Bypass:** Some applications might use IP address verification as part of session hijacking prevention. IP spoofing can potentially weaken or bypass these mechanisms.

- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The `README.md` provides documentation on how to use `proxy_trusted_ips` and `proxy_count` to mitigate IP spoofing when behind proxies.
    - The documentation also mentions that `django-ipware` should be used as a complement to firewall security measures.

- Missing Mitigations:
    - **Default Secure Configuration:** The default configuration of `django-ipware` is vulnerable to IP spoofing if deployed directly without proxy configuration and trusted proxy settings.  A more secure default configuration could be considered, although this might limit flexibility in certain deployment scenarios.
    - **Clearer Warning in Documentation:** While the documentation mentions the risk, it could be emphasized more prominently, especially for users who might not read the "Advanced users" section. A warning about the default insecure nature of relying solely on HTTP headers should be highlighted in the "How to use" section.
    - **Runtime Warning for Default Configuration:**  The library could potentially include a runtime warning if it detects it's being used without any `proxy_trusted_ips` or `proxy_count` configuration in settings, advising users about the potential IP spoofing vulnerability. However, this might be too intrusive and generate false positives in development environments.

- Preconditions:
    - The Django application must be using `django-ipware` to retrieve client IP addresses.
    - The application must be deployed publicly without a properly configured reverse proxy that sanitizes or controls the relevant HTTP headers.
    - The application must not be configured with `proxy_trusted_ips` or `proxy_count` to validate proxy IPs.
    - The application relies on the IP address for security-sensitive functionalities like access control, rate limiting, logging, or session management.

- Source Code Analysis:
    - File: `/code/ipware/ip.py`
    ```python
    from typing import Iterable, Literal, Optional, Tuple

    from django.conf import settings
    from django.http import HttpRequest
    from python_ipware import IpWare


    def get_client_ip(
        request: HttpRequest,
        proxy_order: Literal['left-most', 'right-most'] = 'left-most',
        proxy_count: Optional[int] = None,
        proxy_trusted_ips: Optional[Iterable[str]] = None,
        request_header_order: Optional[Iterable[str]] = None,
    ) -> Tuple[str, bool]:
        leftmost = proxy_order == 'left-most'
        request_header_order = getattr(settings, 'IPWARE_META_PRECEDENCE_ORDER', request_header_order)

        # Instantiate IpWare with values from the function arguments
        ipw = IpWare(precedence=request_header_order,
                     leftmost=leftmost,
                     proxy_count=proxy_count,
                     proxy_list=proxy_trusted_ips)

        ip, _ = ipw.get_client_ip(request.META, True)

        client_ip = None
        routable = False

        if ip:
            client_ip = str(ip)
            routable = ip.is_global

        return client_ip, routable
    ```
    - The `get_client_ip` function in `ipware/ip.py` directly utilizes the `IpWare` class from the `python-ipware` library.
    - It retrieves the header precedence order from Django settings (`IPWARE_META_PRECEDENCE_ORDER`) or uses the default order if not configured.
    - It initializes `IpWare` with the provided or default precedence order, proxy settings (`proxy_count`, `proxy_trusted_ips`), and proxy order.
    - The core IP retrieval logic is delegated to `ipw.get_client_ip(request.META, True)`, which processes the request headers based on the configured precedence and proxy settings.
    - **Vulnerability point:** If `proxy_trusted_ips` and `proxy_count` are not configured, `python-ipware` (and thus `django-ipware`) will rely solely on the header precedence order. This means if a header like `X-Forwarded-For` is present in the request (which is often the case even without malicious intent, but is easily manipulable), the IP address from this header will be taken as the client IP without proper validation against trusted proxies.

- Security Test Case:
    1. **Setup:** Deploy a Django application that uses `django-ipware` to get the client IP address in a view. The application should display the retrieved IP address on a webpage. Ensure no `IPWARE_META_PRECEDENCE_ORDER`, `IPWARE_TRUSTED_PROXY_LIST`, `proxy_trusted_ips`, or `proxy_count` settings are configured. The application should be accessible publicly.
    2. **Craft Request:** Use a tool like `curl` or a browser's developer tools to send an HTTP GET request to the application's view that displays the IP address.
    3. **Inject Spoofed Header:** Add the header `X-Forwarded-For` to the request with a spoofed public IP address (e.g., `X-Forwarded-For: 1.2.3.4`).
    4. **Send Request and Observe:** Send the crafted request to the application.
    5. **Verify Spoofing:** Check the webpage displaying the IP address. It should display the spoofed IP address `1.2.3.4` instead of your actual public IP address.

    Example `curl` command:
    ```bash
    curl -H "X-Forwarded-For: 1.2.3.4" http://<your_django_app_url>/ip_view/
    ```
    Replace `<your_django_app_url>/ip_view/` with the actual URL of the view in your deployed application that displays the IP address.

    If the displayed IP address is `1.2.3.4`, the vulnerability is confirmed.