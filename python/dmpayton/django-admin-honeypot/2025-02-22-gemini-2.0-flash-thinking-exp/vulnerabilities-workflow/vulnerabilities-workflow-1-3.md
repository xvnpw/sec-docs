### Vulnerability List

- Vulnerability Name: Real Admin URL Leakage via Referer Header in Email Notifications
- Description:
    1. An attacker navigates to the Django admin honeypot login page after visiting the real Django admin login page. This can happen if the attacker accidentally or intentionally clicks a link from the real admin page to the honeypot page, or if they manually modify the URL in their browser.
    2. The browser automatically sends a Referer header in the HTTP request to the honeypot login page. This Referer header contains the URL of the previous page, which in this case is the real Django admin login URL.
    3. The Django admin honeypot application logs this login attempt and sends an email notification to administrators if `ADMIN_HONEYPOT_EMAIL_ADMINS` setting is enabled.
    4. If the email template used for these notifications includes the Referer header from the request, the email will contain the real Django admin login URL.
    5. By examining the email notification, an attacker who triggers the honeypot can learn the actual, intended Django admin login URL, defeating the purpose of the honeypot.
- Impact:
    - Information Leakage: The real Django admin login URL is exposed to potential attackers.
    - Reduced Honeypot Effectiveness: Knowing the real admin URL allows attackers to bypass the honeypot and directly target the legitimate login page, making brute-force attacks or other malicious activities against the real admin panel more focused and potentially successful.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code currently captures and potentially uses the Referer header in email notifications without any sanitization or filtering.
- Missing Mitigations:
    - The email template for admin notifications should be reviewed and modified to exclude the Referer header.
    - If the Referer header is deemed necessary for debugging or other purposes, it should be carefully sanitized or stripped of sensitive information like the domain and path before being included in the email. Alternatively, consider not including the Referer header in emails at all, as it is not essential for the core functionality of a login attempt notification.
- Preconditions:
    - `ADMIN_HONEYPOT_EMAIL_ADMINS` setting is set to `True` (or defaults to `True`).
    - The email template `admin_honeypot/email_message.txt` (or equivalent template used for email body) includes the `request.META.HTTP_REFERER` in its content. (This is an assumption based on common practices for including request information in logs and notifications, but needs to be verified).
    - An attacker is able to navigate from the real Django admin login page to the honeypot login page, causing the Referer header to contain the real admin URL.
- Source Code Analysis:
    1. File: `/code/admin_honeypot/listeners.py`
    ```python
    def notify_admins(instance, request, **kwargs):
        path = reverse('admin:admin_honeypot_loginattempt_change', args=(instance.pk,))
        admin_detail_url = 'http://{0}{1}'.format(request.get_host(), path)
        context = {
            'request': request,
            'instance': instance,
            'admin_detail_url': admin_detail_url,
        }
        subject = render_to_string('admin_honeypot/email_subject.txt', context).strip()
        message = render_to_string('admin_honeypot/email_message.txt', context).strip()
        mail_admins(subject=subject, message=message)
    ```
    - The `notify_admins` function is connected to the `honeypot` signal and is triggered when a login attempt is made on the honeypot login page.
    - It prepares a `context` dictionary that includes the `request` object.
    - This `context` is passed to `render_to_string` to render the email message from the `admin_honeypot/email_message.txt` template.
    - If `admin_honeypot/email_message.txt` template uses `{{ request.META.HTTP_REFERER }}`, the Referer header will be included in the email.

    2. (Assumption) File: `/code/admin_honeypot/templates/admin_honeypot/email_message.txt` (This file is not provided, assuming a common scenario)
    ```html+django
    Login attempt detected!

    Username: {{ instance.username }}
    IP Address: {{ instance.ip_address }}
    User Agent: {{ instance.user_agent }}
    Timestamp: {{ instance.timestamp }}
    Path: {{ instance.path }}
    Referer: {{ request.META.HTTP_REFERER }}  {# Potential vulnerability: Leaks Referer header #}
    Admin Detail URL: {{ admin_detail_url }}
    ```
    - If the template includes `{{ request.META.HTTP_REFERER }}`, it will directly output the Referer header value in the email.

- Security Test Case:
    1. Setup a Django project with `django-admin-honeypot` installed and configured. Ensure that email sending is configured to output to the console or a file for testing purposes (e.g., using Django's `console` email backend or `filebased.EmailBackend`).
    2. Configure `ADMIN_HONEYPOT_EMAIL_ADMINS = True` in your Django settings.
    3. Access the real Django admin login page. Let's assume your real admin URL is `/secret/admin/login/`. Open this URL in a browser.
    4. From the real admin login page (e.g., `/secret/admin/login/`), navigate to the honeypot login page (e.g., `/admin/login/`). You can simulate this by:
        - Right-clicking on the login form and selecting "Inspect" or "Inspect Element".
        - Locate the form's `action` attribute. It should be pointing to the honeypot login URL (e.g., `/admin/login/`).
        - Submit the form from the inspector or manually change the browser's address bar to the honeypot login URL (e.g., `/admin/login/`) while still on the real admin page.
    5. Submit any dummy username and password on the honeypot login form and submit it.
    6. Check the email output in your console or the designated file.
    7. Verify if the email body contains a "Referer" field.
    8. If the "Referer" field is present, check if its value is the real Django admin login URL (e.g., `http://yourdomain.com/secret/admin/login/`). If it is, the vulnerability is confirmed.