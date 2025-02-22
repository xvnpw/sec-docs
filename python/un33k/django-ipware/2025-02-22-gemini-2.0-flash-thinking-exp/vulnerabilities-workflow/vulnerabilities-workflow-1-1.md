### Vulnerability List

- Vulnerability Name: IP Address Spoofing via X-Forwarded-For Header

- Description:
    1. An attacker sends an HTTP request to a Django application that uses `django-ipware`.
    2. The attacker includes an `X-Forwarded-For` header in the request, setting it to a spoofed IP address (e.g., `X-Forwarded-For: 1.2.3.4`).
    3. The Django application uses `get_client_ip(request)` from `django-ipware` to retrieve the client IP address without specifying `proxy_trusted_ips` or `proxy_count`.
    4. By default, `django-ipware` trusts the `X-Forwarded-For` header and returns the left-most IP address from it as the client IP.
    5. The application incorrectly uses the spoofed IP address `1.2.3.4` for security decisions, logging, or other purposes, believing it to be the actual client IP.

- Impact: An attacker can spoof their IP address, potentially bypassing IP-based access controls, impersonating other users, or manipulating logs. This can lead to unauthorized access, data breaches, or other security compromises if the application relies on client IP for security measures without proper validation or configuration of trusted proxies.

- Vulnerability Rank: High

- Currently implemented mitigations:
    - The project provides options `proxy_trusted_ips` and `proxy_count` as parameters to the `get_client_ip` function and as Django settings (`IPWARE_META_PROXY_COUNT`). These options, if configured correctly, can mitigate IP spoofing when the application is behind trusted proxies.
    - The README.md file includes a "Notice" section that warns about IP address spoofing and encourages users to use `trusted_proxies_ips` and/or `proxy_count` features, especially for security-sensitive applications.
    - The documentation in README.md explains how to configure `trusted_proxies_ips` and `proxy_count`.

- Missing mitigations:
    - The default configuration of `django-ipware` is insecure as it trusts the `X-Forwarded-For` header without any explicit configuration to define trusted proxies.
    - There is no prominent warning or error message in the code or during setup to alert developers about the potential IP spoofing vulnerability when using the default configuration in production environments, especially if they are behind proxies.
    - While the README has a notice, it might not be sufficiently prominent to ensure all users, especially those who don't read the documentation thoroughly, are aware of the security implications of the default configuration.

- Preconditions:
    - A Django application is using `django-ipware` to retrieve client IP addresses.
    - The application relies on the client IP address for security-sensitive operations (e.g., authentication, authorization, rate limiting, logging, auditing) without additional validation.
    - The Django application is deployed in an environment where it might be accessible via the internet or through networks where attackers can manipulate HTTP headers.
    - The application is using `get_client_ip(request)` without setting `proxy_trusted_ips` or `proxy_count` parameters, and without configuring `IPWARE_META_PROXY_COUNT` in Django settings.

- Source code analysis:
    - File: `/code/ipware/ip.py`
    ```python
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
    - The `get_client_ip` function in `/code/ipware/ip.py` directly uses the `IpWare` class from the `python-ipware` library.
    - If `proxy_trusted_ips` and `proxy_count` are not provided as arguments to `get_client_ip` or configured via Django settings, `python-ipware` defaults to trusting the `X-Forwarded-For` header and extracting the left-most IP address.
    - The code does not enforce any secure defaults or provide warnings about the risks of relying on `X-Forwarded-For` without proper proxy configuration.
    - The vulnerability arises from the default behavior of `python-ipware` being directly exposed by `django-ipware` without adding a layer of mandatory security configuration or more prominent warnings beyond the README.

- Security test case:
    1. Set up a Django project and install `django-ipware`.
    2. Create a Django view that uses `get_client_ip` to retrieve the client IP and displays it in the response. For example:
    ```python
    from django.http import HttpResponse
    from ipware import get_client_ip

    def view_client_ip(request):
        client_ip, is_routable = get_client_ip(request)
        return HttpResponse(f"Client IP: {client_ip}, Routable: {is_routable}")
    ```
    3. Configure URL routing to access this view.
    4. Deploy the Django application to a publicly accessible server. Ensure that no `IPWARE_META_PROXY_COUNT` setting is configured and you are not passing `proxy_trusted_ips` or `proxy_count` to `get_client_ip` in the view.
    5. As an attacker, use `curl` or a web browser to send a request to the deployed application's URL, adding an `X-Forwarded-For` header with a spoofed IP address:
    ```bash
    curl -H "X-Forwarded-For: 1.2.3.4" http://<your-deployed-app-url>/get_ip/
    ```
    6. Observe the response from the server. If the response displays "Client IP: 1.2.3.4", then the IP address is being spoofed successfully.
    7. To further confirm, send a request without the `X-Forwarded-For` header:
    ```bash
    curl http://<your-deployed-app-url>/get_ip/
    ```
    8. Observe that the IP address displayed now is your actual public IP address (or the IP of the last proxy in the chain if you are behind proxies, but not '1.2.3.4'). This confirms that the `X-Forwarded-For` header is indeed influencing the IP address reported by `django-ipware` and that the default configuration is vulnerable to IP spoofing.