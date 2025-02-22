### Vulnerability List:

*   **Vulnerability Name:** Host Header Injection in Admin Email Link
*   **Description:**
    The `notify_admins` listener in `admin_honeypot/listeners.py` generates a URL to the admin detail page of a login attempt and includes it in the email sent to administrators. This URL is constructed using `request.get_host()`. If the application is behind a proxy or load balancer and doesn't properly validate the Host header, an attacker can manipulate the Host header in their request to the honeypot login page. This will cause `request.get_host()` to return the attacker-controlled host, leading to a malicious link in the admin email. When an administrator clicks this link, they might be redirected to a phishing site or another malicious domain.

    Steps to trigger the vulnerability:
    1.  Attacker sends a request to the honeypot login page (e.g., `/admin/`) with a manipulated `Host` header, for example, `Host: malicious.example.com`.
    2.  Attacker fills in the honeypot login form with arbitrary credentials and submits it.
    3.  The `admin_honeypot` application logs the login attempt and sends an email notification to the administrators.
    4.  The email contains a link to the admin detail page of the login attempt, which is constructed using the manipulated `Host` header from the attacker's request.
    5.  Administrator receives the email with the malicious link. If the administrator clicks on this link, they will be redirected to `malicious.example.com` instead of the legitimate admin site.
*   **Impact:**
    Phishing attack, potential compromise of admin credentials or system through a malicious link. An attacker can trick administrators into visiting a malicious site, potentially leading to credential theft or further attacks if the administrator interacts with the malicious site assuming it's legitimate.
*   **Vulnerability Rank:** high
*   **Currently Implemented Mitigations:**
    None. The code uses `request.get_host()` directly without any validation, which is susceptible to Host header injection if the application is behind a vulnerable proxy or load balancer.
*   **Missing Mitigations:**
    Host header validation should be implemented. This can be done at the Django application level or at the proxy/load balancer level.

    At the Django level, `USE_X_FORWARDED_HOST = True` and `ALLOWED_HOSTS` settings should be properly configured in Django settings. This will instruct Django to use the `X-Forwarded-Host` header (if set by the proxy) and validate the host against `ALLOWED_HOSTS`. If the proxy is not setting `X-Forwarded-Host`, then Django's default host header validation should be sufficient if `ALLOWED_HOSTS` is correctly configured.

    At the proxy/load balancer level, the proxy should be configured to validate and sanitize the Host header before forwarding requests to the Django application.
*   **Preconditions:**
    1.  The Django application is deployed behind a proxy or load balancer that forwards the Host header without proper validation.
    2.  The `ADMIN_HONEYPOT_EMAIL_ADMINS` setting is set to `True` in the Django settings, enabling email notifications to administrators for honeypot login attempts.
    3.  An attacker can send requests to the publicly accessible honeypot login page.
*   **Source Code Analysis:**
    ```python
    # /code/admin_honeypot/listeners.py
    from admin_honeypot.signals import honeypot
    from django.conf import settings
    from django.core.mail import mail_admins
    from django.template.loader import render_to_string
    from django.urls import reverse


    def notify_admins(instance, request, **kwargs):
        path = reverse('admin:admin_honeypot_loginattempt_change', args=(instance.pk,))
        admin_detail_url = 'http://{0}{1}'.format(request.get_host(), path) # Vulnerable line
        context = {
            'request': request,
            'instance': instance,
            'admin_detail_url': admin_detail_url,
        }
        subject = render_to_string('admin_honeypot/email_subject.txt', context).strip()
        message = render_to_string('admin_honeypot/email_message.txt', context).strip()
        mail_admins(subject=subject, message=message)

    if getattr(settings, 'ADMIN_HONEYPOT_EMAIL_ADMINS', True):
        honeypot.connect(notify_admins)
    ```
    The vulnerability lies in the line:
    `admin_detail_url = 'http://{0}{1}'.format(request.get_host(), path)`

    `request.get_host()` retrieves the hostname from the HTTP Host header. If the application is behind a proxy and the Host header is not validated by the proxy or Django itself, an attacker can inject a malicious hostname by manipulating the Host header in their request. This injected hostname will be used to construct the `admin_detail_url`, leading to a malicious link in the admin email.

    **Visualization:**

    Attacker's Browser --> (Manipulated Host Header: `malicious.example.com`) --> Proxy/Load Balancer (No Host Validation) --> Django Application (admin-honeypot) --> Email to Admin (Link contains `malicious.example.com`) --> Admin clicks link --> Redirected to `malicious.example.com`

*   **Security Test Case:**
    1.  **Setup:**
        a.  Set up a Django application with `django-admin-honeypot` installed.
        b.  Ensure `ADMIN_HONEYPOT_EMAIL_ADMINS = True` is set in `settings.py`.
        c.  Configure email backend to `django.core.mail.backends.locmem.EmailBackend` in `settings.py` for testing emails locally.
        ```python
        EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
        ```
    2.  **Action:**
        a.  Access the honeypot login URL (e.g., `/admin/`) in a browser or using `curl`.
        b.  Using `curl` or a similar tool, send a POST request to the honeypot login URL with a manipulated `Host` header and arbitrary username/password:
        ```bash
        curl -X POST -H "Host: malicious.example.com" http://localhost:8000/admin/login/ -d "username=test&password=test"
        ```
        (Replace `http://localhost:8000/admin/login/` with your honeypot login URL if different).
    3.  **Verification:**
        a.  In your Django application, inspect the sent emails using `mail.outbox`. You can do this in a Django shell:
        ```python
        from django.core import mail
        print(mail.outbox)
        ```
        b.  Examine the content of the email. Verify that the `admin_detail_url` within the email message contains the malicious host `http://malicious.example.com` instead of the expected legitimate hostname of your application. For example, the email message might look like:

        ```
        A login attempt to the admin honeypot occurred.

        Username: test
        IP Address: 127.0.0.1
        User Agent: curl/7.64.1
        Timestamp: ...
        URL: /admin/login/
        Admin Detail URL: http://malicious.example.com/admin/admin_honeypot/loginattempt/1/change/
        ```
        If the `Admin Detail URL` points to `http://malicious.example.com`, the vulnerability is confirmed.