## Combined Vulnerability Report: IP Address Spoofing via HTTP Header Manipulation

This report consolidates information from multiple vulnerability lists to provide a comprehensive description of the IP Address Spoofing vulnerability in applications using `django-ipware` in its default configuration.

### Vulnerability Name: IP Address Spoofing via HTTP Header Manipulation

### Description:
An attacker can spoof their IP address by manipulating HTTP headers, primarily the `X-Forwarded-For` header, when sending requests to a Django application using the `django-ipware` library. By default, `django-ipware` trusts these headers to determine the client's IP address based on a predefined precedence order, without requiring explicit configuration of trusted proxies.  If the Django application is deployed without properly configuring trusted proxies using `proxy_trusted_ips` or `proxy_count`, an attacker can inject a fake IP address into these headers. `django-ipware` will then incorrectly identify and return this spoofed IP address as the client's IP.

To trigger this vulnerability, an attacker can follow these steps:
1. **Send an HTTP request:** The attacker initiates an HTTP request directed to the publicly accessible Django application. This can be a GET or POST request to any endpoint of the application.
2. **Inject a spoofed `X-Forwarded-For` header:** The attacker includes a crafted `X-Forwarded-For` header within the HTTP request. This header contains the attacker's chosen spoofed IP address. For example, the attacker might set `X-Forwarded-For: 1.2.3.4`.
3. **Application retrieves client IP using `django-ipware`:**  The Django application, in its view or middleware, uses the `get_client_ip(request)` function from `django-ipware` to obtain the client's IP address. Critically, the application does not pass `proxy_trusted_ips` or `proxy_count` parameters to `get_client_ip`, nor are these settings configured globally in Django settings (`IPWARE_META_PROXY_COUNT`).
4. **`django-ipware` processes headers and extracts spoofed IP:** Following its default configuration and header precedence order, `django-ipware` processes the incoming request headers. It encounters the `X-Forwarded-For` header and, because no trusted proxies are defined, trusts its content. It extracts the left-most IP address from the `X-Forwarded-For` header, which is the spoofed IP address provided by the attacker.
5. **Application uses the spoofed IP:** The Django application receives the spoofed IP address (e.g., `1.2.3.4`) as the result of `get_client_ip(request)`. It then proceeds to use this incorrect IP address for various purposes, such as security decisions, logging events, or personalizing user experience, mistakenly believing it to be the actual client IP.

### Impact:
The successful spoofing of IP addresses can have significant security implications, potentially leading to:
- **Bypassing IP-based Access Control:** If the application relies on IP addresses for authentication or authorization (e.g., IP whitelisting), an attacker can bypass these controls by spoofing a permitted IP address, gaining unauthorized access to restricted resources or functionalities.
- **Circumventing Rate Limiting:** Attackers can evade rate limiting mechanisms that are based on IP addresses by rotating spoofed IPs in their requests. This allows them to perform actions at a higher frequency than intended, potentially leading to denial of service or brute-force attacks.
- **Incorrect Logging and Auditing:** Security logs and audit trails will record the spoofed IP address instead of the attacker's actual IP. This hinders incident response, forensic analysis, and the ability to track malicious activities back to the true source.
- **Session Hijacking Prevention Bypass:** Applications using IP address verification as part of session hijacking prevention mechanisms can be weakened or bypassed. If session validation incorrectly relies on the spoofed IP, an attacker might be able to hijack or impersonate legitimate user sessions.
- **Impersonating other users:** In scenarios where IP addresses are used to identify or personalize user experiences, attackers could impersonate other users or gain access to their profiles or data by spoofing their IP address.
- **Data Breaches and Unauthorized Access:** Ultimately, the ability to bypass security measures through IP spoofing can lead to unauthorized access to sensitive data, system resources, and critical functionalities, potentially resulting in data breaches and other security compromises.

### Vulnerability Rank: High

### Currently implemented mitigations:
The `django-ipware` library includes features that can mitigate IP address spoofing when properly configured. These mitigations are primarily documented and provided as options for developers to implement:
- **`proxy_trusted_ips` and `proxy_count` parameters:** The `get_client_ip` function accepts optional parameters `proxy_trusted_ips` and `proxy_count`. These parameters, when correctly configured with the IP addresses of trusted reverse proxies and the number of proxies, instruct `django-ipware` to only trust the `X-Forwarded-For` header if the request originates from a trusted proxy.
- **`IPWARE_META_PROXY_COUNT` Django setting:**  The library also supports setting `IPWARE_META_PROXY_COUNT` in Django settings. This setting provides a global configuration for the expected number of proxies, similar to the `proxy_count` parameter.
- **Documentation and Warnings in README.md:** The `README.md` file includes a "Notice" section and documentation that warns users about the risk of IP address spoofing when relying solely on HTTP headers. It encourages users, especially for security-sensitive applications, to utilize the `trusted_proxies_ips` and/or `proxy_count` features to enhance security when deployed behind proxies. The documentation explains how to configure these options.
- **Guidance to use with Firewall Measures:** The documentation also suggests that `django-ipware` should be used as a complement to firewall security measures, implying that relying solely on the library without network-level security controls is not recommended for complete protection against IP spoofing.

### Missing mitigations:
Despite the provided mitigation options, the library has certain shortcomings in its default configuration and lacks proactive security measures:
- **Insecure Default Configuration:** The default configuration of `django-ipware` is inherently vulnerable to IP spoofing. It trusts the `X-Forwarded-For` header without any explicit configuration to define trusted proxies. This means that out-of-the-box, any application using `django-ipware` without further configuration is susceptible to IP spoofing attacks.
- **Lack of Prominent Warning or Error Messages:** There is no prominent warning or error message generated by the library in the code or during setup to alert developers about the potential IP spoofing vulnerability when using the default configuration in production environments, especially if they are behind proxies. Developers might unknowingly deploy the application with the default settings, assuming it is secure without realizing the inherent risks.
- **Insufficient Emphasis on Security Implications in Documentation:** While the README does include a notice about IP spoofing, it might not be sufficiently prominent to ensure all users, particularly those who do not thoroughly read the documentation, are fully aware of the security implications associated with the default configuration. The warning could be made more explicit and placed in more visible sections of the documentation, such as the "Quick Start" or "How to Use" sections.
- **No Built-in Validation or Sanitization:** The library does not perform any built-in validation or sanitation of header values against a secure, connection-based or cryptographically secured source. It directly trusts and processes the header values provided in the request.
- **Absence of Stricter Defaults:** The library lacks stricter default behaviors that could enhance security. For instance, a more secure default could be to reject or ignore client-supplied IP headers unless the request is explicitly validated as originating from a known and validated proxy.
- **No Runtime Warning for Default Configuration:** The library could potentially include a runtime warning if it detects it is being used without any `proxy_trusted_ips` or `proxy_count` configuration in settings, especially in production environments. This warning could advise users about the potential IP spoofing vulnerability and encourage them to configure trusted proxies. However, care must be taken to avoid intrusive warnings in development environments where default configurations might be acceptable for testing.

### Preconditions:
Several conditions must be met for this vulnerability to be exploitable:
- **Django application using `django-ipware`:** The target application must be a Django application that uses the `django-ipware` library to retrieve client IP addresses.
- **Reliance on client IP for security-sensitive operations:** The application must rely on the retrieved client IP address for security-sensitive operations, such as authentication, authorization, rate limiting, logging, auditing, or session management, without additional validation or security measures.
- **Publicly accessible deployment:** The Django application must be deployed in an environment where it is publicly accessible via the internet or through networks where attackers can manipulate HTTP headers. This often occurs when the application is directly exposed without a properly configured reverse proxy in front.
- **Default `django-ipware` configuration:** The application must be using `get_client_ip(request)` without setting the `proxy_trusted_ips` or `proxy_count` parameters, and without configuring `IPWARE_META_PROXY_COUNT` in Django settings. Essentially, it must be using the default, insecure configuration of `django-ipware`.
- **No header sanitization by reverse proxy or middleware:**  There should be no properly configured reverse proxy or middleware in place that sanitizes or validates the incoming HTTP headers, specifically the `X-Forwarded-For` and related headers, before they reach the Django application. If a properly configured reverse proxy removes or validates untrusted headers, the vulnerability might be mitigated at the infrastructure level.

### Source code analysis:
The vulnerability stems from the implementation of the `get_client_ip` function in `/code/ipware/ip.py` (or similar path in the library). Let's analyze the relevant code:

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

**Step-by-step analysis:**
1. **Function `get_client_ip`:** This function is the entry point for retrieving the client IP address. It takes a Django `HttpRequest` object and optional parameters for proxy configuration.
2. **Default Proxy Configuration:**  The `proxy_count` and `proxy_trusted_ips` parameters, responsible for defining trusted proxies, are optional and default to `None` if not provided as arguments to `get_client_ip` or configured via Django settings (`IPWARE_META_PROXY_COUNT`).
3. **Instantiation of `IpWare`:** An instance of the `IpWare` class from the underlying `python-ipware` library is created. This is where the core IP address detection logic resides. The `IpWare` object is initialized with the provided (or default) header precedence order (`request_header_order`), proxy order (`leftmost`), and importantly, the proxy configuration (`proxy_count`, `proxy_list` which corresponds to `proxy_trusted_ips`).
4. **Delegation to `python-ipware`:** The function then calls `ipw.get_client_ip(request.META, True)`. This delegates the actual IP address extraction to the `get_client_ip` method of the `IpWare` instance from `python-ipware`. The `request.META` dictionary, containing HTTP headers, is passed to `python-ipware`. The `True` argument likely relates to whether to return a routable IP address.
5. **IP Extraction in `python-ipware`:** If `proxy_trusted_ips` and `proxy_count` are *not* provided during the instantiation of `IpWare` (as is the case in the default usage of `django-ipware`), the underlying `python-ipware` library defaults to trusting the `X-Forwarded-For` header (and other headers in the precedence list) and extracts the left-most IP address directly from these headers.  It does *not* validate if the request originated from a trusted proxy.
6. **Return Value:** The function returns the extracted IP address and a boolean indicating if it is routable.
7. **Vulnerability Point:** The vulnerability arises because `django-ipware` directly exposes the default behavior of `python-ipware` without enforcing any mandatory security configuration. If developers use `get_client_ip` without explicitly configuring `proxy_trusted_ips` or `proxy_count`, the application becomes vulnerable to IP spoofing. The code in `django-ipware` does not add a layer of mandatory security configuration or issue warnings beyond the documentation in the README.

**Visualization Overview:**

```
[HTTP Request with Spoofed X-Forwarded-For Header] --> [Django Application using django-ipware] --> get_client_ip() function
                                                                    |
                                                                    | (No proxy_trusted_ips or proxy_count configured)
                                                                    V
                                                                 [IpWare Instance (python-ipware) - Default Configuration]
                                                                    |
                                                                    | (Trusts X-Forwarded-For Header)
                                                                    V
                                                                 [Extracts Spoofed IP from X-Forwarded-For] --> [Spoofed IP returned to Application]
                                                                                                                   |
                                                                                                                   V
                                                                 [Application uses Spoofed IP for Security Decisions/Logging etc.]
```

### Security test case:
To verify the IP Address Spoofing vulnerability, follow these steps:

1. **Set up a vulnerable Django application:**
    - Create a new Django project and install `django-ipware` using pip: `pip install django-ipware`.
    - Create a Django app (if you don't have one already).
    - In your app's `views.py`, create a simple view function that uses `get_client_ip` to retrieve the client IP and displays it in the HTTP response. For example:

      ```python
      from django.http import HttpResponse
      from ipware import get_client_ip

      def view_client_ip(request):
          client_ip, is_routable = get_client_ip(request)
          return HttpResponse(f"Client IP: {client_ip}, Routable: {is_routable}")
      ```
    - In your app's `urls.py`, configure a URL pattern to access this view:

      ```python
      from django.urls import path
      from . import views

      urlpatterns = [
          path('get_ip/', views.view_client_ip, name='get_client_ip'),
      ]
      ```
    - Ensure that you **do not** configure `IPWARE_META_PROXY_COUNT` in your `settings.py` and you are **not** passing `proxy_trusted_ips` or `proxy_count` to `get_client_ip` in your view. This ensures you are using the vulnerable default configuration.
    - Migrate your Django app: `python manage.py migrate`.
    - Run the Django development server: `python manage.py runserver 0.0.0.0:8000`.

2. **Deploy the application (optional but recommended for realistic testing):** For a more realistic test, deploy the Django application to a publicly accessible server or a test environment where you can send HTTP requests from outside your local machine. If testing locally, ensure you are accessing the server via `0.0.0.0:8000` or the publicly accessible IP of your machine if applicable.

3. **Craft an HTTP request with a spoofed `X-Forwarded-For` header:** Use `curl` or a similar HTTP client (like Postman or your browser's developer tools) to send a request to the deployed application's URL. Include the `X-Forwarded-For` header with a spoofed IP address. For example, to spoof the IP address `1.2.3.4`, use the following `curl` command:

   ```bash
   curl -H "X-Forwarded-For: 1.2.3.4" http://<your-deployed-app-url>/get_ip/
   ```
   Replace `<your-deployed-app-url>` with the actual URL of your deployed application, e.g., `http://your-server-ip:8000`.

4. **Observe the response:** Examine the response from the server. If the vulnerability is present, the response body should display "Client IP: 1.2.3.4". This indicates that `django-ipware` has successfully extracted and returned the spoofed IP address from the `X-Forwarded-For` header.

5. **Verify without spoofed header (optional):** To confirm that the `X-Forwarded-For` header is indeed causing the spoofing, send another request to the same URL, but this time without the `X-Forwarded-For` header:

   ```bash
   curl http://<your-deployed-app-url>/get_ip/
   ```

6. **Observe the response again:** This time, the response should display your actual public IP address (or the IP address of the last proxy in the chain if you are behind proxies, but definitely not `1.2.3.4`).

7. **Conclusion:** If you observe that the application displays "Client IP: 1.2.3.4" when you send the request with the `X-Forwarded-For: 1.2.3.4` header, and your actual IP address when you send the request without the header, you have successfully demonstrated the IP Address Spoofing vulnerability in the default configuration of `django-ipware`. This confirms that an attacker can control the IP address reported by `django-ipware` by manipulating the `X-Forwarded-For` header when trusted proxies are not configured.