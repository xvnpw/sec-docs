### Consolidated Vulnerability List

#### Vulnerability Name: Insecure Certificate URL Validation leading to Signature Bypass

* **Description:**
    The `django-ses` library's `SESEventWebhookView` processes signed requests from AWS for email event handling. A critical aspect of security is the verification of these signatures, which involves retrieving a public certificate from the URL specified in the `SigningCertURL` field of the request. The library aims to validate this URL to ensure it originates from a trusted domain, as configured by the `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` setting (defaulting to `amazonaws.com` and `amazon.com`). However, the validation logic implemented in the `_get_cert_url` function is flawed, leading to a certificate URL validation bypass.

    Specifically, the vulnerability arises from the function checking if the certificate URL's net location merely *ends with* a trusted domain, rather than performing an exact match or a more robust validation against expected patterns. This insecure subdomain check allows an attacker to host a malicious certificate on an arbitrary subdomain of a trusted domain (like an S3 bucket on `amazonaws.com`).

    Furthermore, while a regular expression check (`SES_REGEX_CERT_URL`) is present for domains containing "amazonaws.com", it is not consistently enforced and can be bypassed depending on the configuration of `EVENT_CERT_DOMAINS`. If an administrator configures a full domain (e.g., `"sns.us-east-1.amazonaws.com"`) in `EVENT_CERT_DOMAINS` instead of a broader suffix like `"amazonaws.com"`, the regex check may be bypassed entirely, and the less secure subdomain check becomes the primary validation method.

    **Steps to trigger vulnerability:**
    1. **Attacker Setup:** An attacker sets up an AWS S3 bucket (or similar service) under a subdomain of a trusted domain (e.g., `amazonaws.com`), such as `attacker-controlled-bucket.s3.amazonaws.com`. Alternatively, the attacker can use a subdomain of `sns.us-east-1.amazonaws.com` like `evil.sns.us-east-1.amazonaws.com`.
    2. **Certificate Generation:** The attacker generates a self-signed certificate and a corresponding private key.
    3. **Certificate Hosting:** The attacker uploads the public certificate to the S3 bucket (or their chosen hosting service), making it accessible via HTTPS, for example: `https://attacker-controlled-bucket.s3.amazonaws.com/attacker.cert` or `https://evil.sns.us-east-1.amazonaws.com/evil.pem`.
    4. **Malicious Payload Crafting:** The attacker crafts a malicious webhook payload (e.g., a `SubscriptionConfirmation` or `Notification` type event in JSON format).
    5. **Signature Generation:** The attacker signs the malicious payload using the attacker's generated private key.
    6. **`SigningCertURL` Injection:** The attacker includes the URL of the malicious certificate (e.g., `https://attacker-controlled-bucket.s3.amazonaws.com/attacker.cert` or `https://evil.sns.us-east-1.amazonaws.com/evil.pem`) in the `SigningCertURL` field of the payload.
    7. **Webhook Request Submission:** The attacker sends an HTTP POST request to the `/event-webhook/` endpoint (or `/ses/event-webhook/` depending on URL configuration) of the Django application with the crafted payload, setting `Content-Type: application/json`.
    8. **Bypass and Verification:** The `django-ses` library fetches the certificate from the attacker-controlled URL. Due to the flawed validation, the URL is incorrectly deemed trusted because it ends with a trusted domain or shares tail segments with a configured full domain. The library then uses the attacker's certificate to verify the signature. As the payload was signed with the corresponding private key, the signature verification incorrectly succeeds.
    9. **Forged Event Processing:** The application processes the forged webhook request as if it were a legitimate AWS event, potentially leading to unintended actions.

* **Impact:**
    Successful exploitation of this vulnerability allows an attacker to bypass signature verification and inject forged webhook requests into the application. This can lead to several critical impacts:

    - **Spoofing/Bypassing Signature Verification:** Attackers can send arbitrary, attacker-controlled webhook event messages that are processed as legitimate events, completely circumventing the intended security mechanism of signature verification.
    - **Potential Server-Side Request Forgery (SSRF):** In the case of `SubscriptionConfirmation` events, the application might make an HTTP request to an attacker-controlled URL specified in the `SubscribeURL` parameter within the forged event. This can lead to a Blind SSRF vulnerability, potentially allowing attackers to probe internal network resources or interact with external services on behalf of the server.
    - **Abuse of Event Handling Logic:** Depending on how the application processes different webhook events (bounce, complaint, delivery, etc.), an attacker could trigger unintended actions or manipulate application state. For example, they could forge bounce or complaint events to blacklist legitimate email addresses, or manipulate data based on delivery events to alter application logic.
    - **False Data Injection:** An attacker can inject false data into the application through forged notifications. This could lead to incorrect application state, business logic errors, or even data corruption, depending on how the application processes the event data.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - The `_get_cert_url` function checks if the certificate URL starts with `https://`.
    - The `_get_cert_url` function checks if the domain of the certificate URL is in the `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` list using a vulnerable subdomain check (i.e., checking if the URL's netloc ends with any of the trusted domains).
    - For domains containing `amazonaws.com`, there's a regex check (`SES_REGEX_CERT_URL`) intended for stricter validation. However, this regex is not consistently enforced for all trusted domains and can be bypassed if a full domain name is configured in `EVENT_CERT_DOMAINS`.
    - Signature verification is enabled by default if `VERIFY_EVENT_SIGNATURES` setting is `True`.

* **Missing Mitigations:**
    - **Enforce Strict Regex-based Certificate URL Validation for all trusted domains:** The regex-based validation using `SES_REGEX_CERT_URL` should be consistently applied and strictly enforced for all domains listed in `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS`, not just for `amazonaws.com` domains when configured broadly. It should be the primary and mandatory validation method, replacing or superseding the insecure subdomain check.
    - **Remove or Downgrade Subdomain Check:** The vulnerable subdomain check (`url_obj.netloc.split(".")[-len(parts) :] == parts:`) should be removed entirely or made a secondary, less permissive check only after a strict regex validation fails.
    - **Strict Certificate URL Format Enforcement:** Validation should ensure that the certificate URL *exactly* matches the expected AWS SNS certificate URL format using a robust regular expression, preventing any bypasses via subdomains, manipulated paths, or other URL deviations. A recommended regex for `amazonaws.com` is `^https://sns\.[a-z0-9\-]+\.amazonaws\.com(\.cn)?/SimpleNotificationService\-[a-z0-9]+\.pem$`.
    - **Consider Certificate Pinning or Fingerprint Verification:** For enhanced security, consider implementing certificate pinning or fingerprint verification. This would involve storing the expected certificate fingerprint or the certificate itself and verifying the retrieved certificate against this known good value, adding an extra layer of security beyond URL validation.

* **Preconditions:**
    - `VERIFY_EVENT_SIGNATURES` setting is set to `True` (default).
    - The application exposes the webhook endpoint (e.g., `/event-webhook/` or `/ses/event-webhook/`) publicly.
    - `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` includes `amazonaws.com` or `amazon.com` (default) or is configured with a full domain name like `sns.us-east-1.amazonaws.com`.
    - An attacker is able to host files on a subdomain of a trusted domain (e.g., by taking over an S3 bucket) or control a subdomain of a configured full domain.

* **Source Code Analysis:**
    - **File:** `/code/django_ses/utils.py`
    - **Function:** `EventMessageVerifier._get_cert_url`

    ```python
    def _get_cert_url(self):
        """
        Get the signing certificate URL.
        Only accept urls that match the domains set in the
        AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS setting. Sub-domains
        are allowed. i.e. if amazonaws.com is in the trusted domains
        then sns.us-east-1.amazonaws.com will match.
        """
        cert_url = self._data.get("SigningCertURL")
        if not cert_url:
            logger.warning('No signing certificate URL: "%s"', cert_url)
            return None

        if not cert_url.startswith("https://"):
            logger.warning('Untrusted certificate URL: "%s"', cert_url)
            return None

        url_obj = urlparse(cert_url)
        for trusted_domain in settings.EVENT_CERT_DOMAINS:
            parts = trusted_domain.split(".")
            if "amazonaws.com" in trusted_domain:
                if not SES_REGEX_CERT_URL.match(cert_url): # Regex check for amazonaws.com, but not enforced strictly
                    if len(parts) < 4:
                        return None
                    else:
                        logger.warning('Possible security risk for: "%s"', cert_url)
                        logger.warning(
                            "It is strongly recommended to configure the full domain in EVENT_CERT_DOMAINS. "
                            "See v3.5.0 release notes for more details."
                        )

            if url_obj.netloc.split(".")[-len(parts) :] == parts: # Vulnerable subdomain check
                return cert_url

        return None
    ```

    **Analysis:**
    1. **Certificate URL Extraction:** The function starts by extracting the certificate URL from the webhook message data using `self._data.get("SigningCertURL")`.
    2. **HTTPS Check:** It checks if the URL starts with `https://`. Non-HTTPS URLs are rejected.
    3. **Domain Validation Loop:** The code iterates through each trusted domain specified in `settings.EVENT_CERT_DOMAINS`.
    4. **`amazonaws.com` Regex Check (Conditional and Weak):** If a trusted domain contains "amazonaws.com", a regex check using `SES_REGEX_CERT_URL` is performed. However, this check is not strictly enforced. If the regex fails, and the trusted domain has 4 or more parts (e.g., `sns.us-east-1.amazonaws.com`), the code only logs a warning but proceeds with the less secure subdomain check. If the trusted domain has fewer than 4 parts (e.g., just `amazonaws.com`), the regex failure correctly leads to rejection.
    5. **Vulnerable Subdomain Check:** The core vulnerability lies in this line: `if url_obj.netloc.split(".")[-len(parts) :] == parts:`. This line checks if the netloc (domain name) of the certificate URL *ends with* the parts of the trusted domain. This allows subdomains to pass validation, e.g., `attacker-controlled.amazonaws.com` is considered valid if `amazonaws.com` is in `EVENT_CERT_DOMAINS`.  This check is performed *after* the weak regex check for `amazonaws.com` when a long domain is configured, and always if the regex check is not triggered or bypassed due to configuration.
    6. **Return Valid URL or None:** If the subdomain check passes, the function returns the `cert_url`, considering it valid. Otherwise, it returns `None`, indicating an invalid URL.

    **Visualization:**

    ```
    Start --> Get cert_url from request --> HTTPS check --> Domain Validation Loop (for each trusted_domain)
          |
          |-- No HTTPS --> Reject URL
          |
          Domain Validation Loop --> Is "amazonaws.com" in trusted_domain?
               |
               |-- Yes --> Regex Check (SES_REGEX_CERT_URL) --> Regex Fails?
               |       |                                      |
               |       |-- No (Regex Pass) --> Subdomain Check --> Subdomain Pass? --> Accept URL
               |       |                                      |                     |
               |       |                                      |-- No (Subdomain Fail)--> Reject URL
               |       |                                      |
               |       |-- Yes (Regex Fail) --> Domain Parts < 4?
               |             |                               |
               |             |-- Yes --> Reject URL          |
               |             |                               |
               |             |-- No --> Warning Log --> Subdomain Check --> Subdomain Pass? --> Accept URL
               |                                                |                     |
               |                                                |-- No (Subdomain Fail)--> Reject URL
               |
               |-- No ("amazonaws.com" not in trusted_domain) --> Subdomain Check --> Subdomain Pass? --> Accept URL
                                                                    |                     |
                                                                    |-- No (Subdomain Fail)--> Reject URL
    ```


* **Security Test Case:**
    1. **Setup:**
        - Deploy a Django application using `django-ses` with signature verification enabled (`VERIFY_EVENT_SIGNATURES = True`).
        - **Configuration for Subdomain Bypass (Scenario 1):** Use default `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` or set it to include `amazonaws.com`.
        - **Configuration for Regex Bypass (Scenario 2):** Set `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS = ['sns.us-east-1.amazonaws.com']` in `settings.py`. This will bypass the intended strict regex validation when the trusted domain is configured as a full domain.
        - Configure URL patterns to include the webhook view, e.g., `path('ses/event-webhook/', SESEventWebhookView.as_view(), name='handle-event-webhook')`.
        - Run the Django development server.
        - **Attacker Controlled Infrastructure:** Setup an attacker-controlled AWS S3 bucket (or any web server), e.g., `django-sns-poc.s3.ap-southeast-2.amazonaws.com` or `evil.sns.us-east-1.amazonaws.com`.
        - **Certificate Generation:** Generate a self-signed certificate and private key using OpenSSL:
          ```bash
          openssl genrsa -out private.key 2048
          openssl req -new -x509 -key private.key -out publickey.cer -days 365 -subj '/CN=attacker-controlled.domain'
          ```
        - **Certificate Hosting:** Upload `publickey.cer` to the S3 bucket, e.g., `https://django-sns-poc.s3.ap-southeast-2.amazonaws.com/publickey.cer` or `https://evil.sns.us-east-1.amazonaws.com/evil.pem`.
        - Keep `private.key` locally for signing requests.
        - Install required Python packages: `pip install cryptography requests`.
        - Create a Python script `poc.py` (as provided in List 3 Security Test Case) or adapt it to target either subdomain bypass or regex bypass scenario by modifying `cert_url` and potentially `EVENT_CERT_DOMAINS` configuration in your Django test setup. For Regex bypass scenario, ensure `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS = ['sns.us-east-1.amazonaws.com']` and `cert_url = 'https://evil.sns.us-east-1.amazonaws.com/evil.pem'`. For subdomain bypass, use default `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` and `cert_url = 'https://django-sns-poc.s3.ap-southeast-2.amazonaws.com/publickey.cer'`.

    2. **Attack Execution:**
        - Run the Python script `python poc.py` from your local machine where `private.key` is located. Ensure the Django server is running and accessible (e.g., at `http://localhost:8000`).

    3. **Verification:**
        - Observe the output of the Python script. If the script outputs `Status code: 200` and `Response content:` is empty or "OK", it indicates the forged webhook request was successfully processed. This confirms the vulnerability, as a 200 status code means signature verification passed despite using an attacker-controlled certificate.
        - Check the Django application logs. In the Regex bypass scenario, you should observe warning messages like "Possible security risk for: ..." indicating the regex check failed but the subdomain check still passed.

    4. **Expected Outcome:**
        - The application should return an HTTP 200 OK response, indicating that the forged webhook event was accepted and processed.
        - In the Regex bypass scenario, application logs should contain warnings about potential security risks, but the request is still processed successfully.

    5. **Conclusion:**
        - A successful 200 OK response confirms that the certificate URL validation is bypassed, and an attacker can inject forged webhook events by hosting a malicious certificate on a subdomain of a trusted domain or by exploiting the weak regex enforcement when full domains are configured in `EVENT_CERT_DOMAINS`.

This test case demonstrates that the subdomain-based validation and the conditional regex enforcement can be bypassed, allowing an attacker to inject forged webhook events into the application under various configuration scenarios.