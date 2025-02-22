### Vulnerability List

* Vulnerability Name: Certificate URL Validation Bypass in Webhook Event Handling
* Description:
    1. An attacker can host a certificate on a subdomain of a trusted domain (e.g., `amazonaws.com`) by taking over an S3 bucket.
    2. The attacker crafts a malicious webhook event message, including a `SigningCertURL` pointing to their hosted certificate.
    3. The attacker sends this malicious webhook event message to the `/event-webhook/` endpoint.
    4. The `EventMessageVerifier._get_cert_url` function checks if the certificate URL's netloc ends with any of the domains listed in `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS`.
    5. Due to the subdomain check, the attacker's malicious certificate URL is considered valid.
    6. The `verify_event_message` function uses the attacker's certificate to verify the signature of the malicious webhook event message.
    7. Since the attacker generated the signature using the private key corresponding to the hosted public certificate, the signature verification succeeds.
    8. The webhook event is processed as a valid event, potentially leading to unintended consequences depending on how the application handles webhook events.
* Impact:
    - **Spoofing/Bypassing Signature Verification:** An attacker can bypass the signature verification mechanism, allowing them to send arbitrary, attacker-controlled webhook event messages that are processed as legitimate events.
    - **Potential SSRF:** In the case of SubscriptionConfirmation events, the application might make an HTTP request to an attacker-controlled URL specified in the `SubscribeURL` parameter, leading to a Server-Side Request Forgery (SSRF) vulnerability.
    - **Abuse of Event Handling Logic:** Depending on how the application processes different webhook events (bounce, complaint, delivery, etc.), an attacker might be able to trigger unintended actions or manipulate application state by sending forged events.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - The `_get_cert_url` function checks if the certificate URL starts with `https://` and if the domain is in the `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` list. However, the domain check is vulnerable to subdomain bypass.
    - For domains containing `amazonaws.com`, there is a regex check (`SES_REGEX_CERT_URL`) that is intended to enforce stricter URL format. However, this regex check is not consistently applied to all trusted domains, and the subdomain check still takes precedence if the regex check fails but the subdomain matches.
    - Signature verification is enabled by default if `VERIFY_EVENT_SIGNATURES` setting is True.
* Missing Mitigations:
    - **Enforce Regex-based Certificate URL Validation for all trusted domains:** The regex-based validation using `SES_REGEX_CERT_URL` should be enforced for all domains listed in `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS`, not just for `amazonaws.com` domains, and it should be the primary validation method instead of the subdomain check. The subdomain check should be removed or made secondary to the regex validation.
    - **Strict Certificate URL Format:** The validation should ensure that the certificate URL exactly matches the expected AWS SNS certificate URL format using a robust regular expression, preventing any deviations or bypasses via subdomains or other URL manipulations.
* Preconditions:
    - `VERIFY_EVENT_SIGNATURES` setting is set to `True` (default).
    - `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` includes `amazonaws.com` or `amazon.com` (default).
    - An attacker is able to host files on a subdomain of `amazonaws.com` (e.g., by taking over an S3 bucket).
* Source Code Analysis:
    - File: `/code/django_ses/utils.py`
    - Function: `EventMessageVerifier._get_cert_url`

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
                if not SES_REGEX_CERT_URL.match(cert_url): # Regex check for amazonaws.com, but not enforced
                    if len(parts) < 4:
                        return None
                    else:
                        logger.warning('Possible security risk for: "%s"', cert_url)
                        logger.warning(
                            "It is strongly recommended to configure the full domain in EVENT_CERT_DOMAINS. "
                            "See v3.5.0 release notes for more details."
                        )

            if url_obj.netloc.split(".")[-len(parts) :] == parts: # Vulnerable subdomain check - still in place and used primarily
                return cert_url

        return None
    ```
    The vulnerability still lies in this line: `if url_obj.netloc.split(".")[-len(parts) :] == parts:`. This code checks if the netloc *ends with* the trusted domain parts, which allows for subdomains to be considered valid.

    The `SES_REGEX_CERT_URL` regex is introduced, but it's used conditionally only when "amazonaws.com" is in `trusted_domain` and the regex check failure is not a hard failure. The code still proceeds to the vulnerable subdomain check `if url_obj.netloc.split(".")[-len(parts) :] == parts:`, making the regex check ineffective in preventing the subdomain bypass.

* Security Test Case:
    1. **Setup:**
        - Deploy a Django application using `django-ses` with default settings (specifically `VERIFY_EVENT_SIGNATURES = True` and `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` including `amazonaws.com`).
        - Set up the webhook receiver endpoint `/event-webhook/` as defined in `tests/test_urls.py` and `django_ses/views.py`.
        - Obtain a private key and generate a corresponding self-signed public certificate.
        - Host the public certificate at a URL on an `amazonaws.com` subdomain that you control (e.g., using an S3 bucket like `https://attacker-controlled.s3.amazonaws.com/attacker_cert.pem`).
        - Have the private key available locally.
    2. **Craft Malicious Payload:**
        - Create a JSON payload for a `SubscriptionConfirmation` event (or any other event type).
        - Include the `SigningCertURL` in the payload, pointing to the hosted malicious certificate URL (e.g., `https://attacker-controlled.s3.amazonaws.com/attacker_cert.pem`).
        - Generate a signature for the payload using the private key, following the signing process used in `django_ses.utils._get_bytes_to_sign`.
        - Include the generated `Signature` in the payload.
    3. **Send Malicious Request:**
        - Send an HTTP POST request to the `/event-webhook/` endpoint of the deployed Django application.
        - Set the `Content-Type` header to `application/json`.
        - Include the crafted malicious JSON payload in the request body.
    4. **Verification:**
        - Observe the application logs. If the vulnerability is present, the application should process the webhook event without raising a signature verification error (HTTP 200 OK response).
        - If the event type is `SubscriptionConfirmation` and the `SubscribeURL` in the malicious payload points to an attacker-controlled server, check if the application makes an HTTP request to this attacker-controlled URL, confirming the SSRF vulnerability.

This test case will demonstrate that the subdomain-based validation can be bypassed, allowing an attacker to inject forged webhook events into the application.