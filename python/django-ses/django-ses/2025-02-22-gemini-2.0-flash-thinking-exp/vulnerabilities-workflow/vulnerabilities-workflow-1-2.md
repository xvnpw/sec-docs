- **Vulnerability Name:** Inadequate Certificate URL Validation in Event Message Verification

- **Description:**
  The application processes incoming SES/SNS event notifications by verifying their signatures. To do so, it retrieves a public certificate from a URL passed in the notification’s “SigningCertURL” field. In the `EventMessageVerifier._get_cert_url` function (in `django_ses/utils.py`), the certificate URL is first checked for an “https://” prefix and then compared against trusted domains defined in the setting `EVENT_CERT_DOMAINS`. For trusted domains that include the string “amazonaws.com” (which is provided by default), the code applies a regular‐expression check using `SES_REGEX_CERT_URL`. However, if an administrator chooses to configure the trusted domains as a full domain (for example, `"sns.us-east-1.amazonaws.com"`) rather than a broad suffix (like the default tuple `("amazonaws.com", "amazon.com")`), then the extra strictness of the regex check can be bypassed. In this case, the URL is accepted if its domain’s final segments match those of the configured trusted domain—even if the URL does not precisely follow the expected AWS SNS certificate URL pattern. An external attacker who is aware of such a misconfiguration can craft a notification with a malicious “SigningCertURL” (for example, one pointing to an attacker‑controlled server or S3 bucket) that will pass certificate validation. This may let the attacker cause the notification’s signature verification to succeed despite its fraudulent origin and furthermore may allow the application to indirectly make HTTP requests to attacker‑controlled endpoints (i.e. an SSRF scenario).

- **Impact:**
  - An attacker who can exploit this weakness may be able to send falsified SES/SNS notifications that pass signature verification.
  - In a worst‑case scenario, this could lead to false bounce or complaint events being processed (for example, causing legitimate email addresses to be blacklisted automatically).
  - In addition, if the certificate retrieval itself is exploited, the attacker might trigger unwanted HTTP requests from the server (an SSRF), which in turn could be leveraged to scan internal resources.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - In the `EventMessageVerifier._get_cert_url` method, several checks are applied:
    - The URL must start with “https://”.
    - The URL’s domain is compared segment‐by‐segment against each value in the trusted domains list specified by `EVENT_CERT_DOMAINS`.
    - For domains containing “amazonaws.com”, a regular expression (`SES_REGEX_CERT_URL`) is used to enforce that the certificate URL matches the expected AWS SNS certificate format.
    - If the URL does not match the regex and if the trusted domain (when split by “.”) has fewer than four parts, the function returns `None`, effectively rejecting the URL.
    - When the trusted domain string is long (four parts or more), a warning is logged if the URL does not exactly match the strict regex but the URL is still accepted provided its terminal components match the trusted domain.

- **Missing Mitigations:**
  - The fallback path for trusted domains configured with full domains (with four or more parts) does not enforce the regular‐expression check strictly—it only logs warnings.
  - There is no hard denial (error) if the certificate URL does not match exactly the AWS SNS expected format. This means that if the administrator misconfigures the trusted domains (for example by specifying `"sns.us-east-1.amazonaws.com"`), then an attacker can supply a malicious certificate URL such as:
    `https://evil.sns.us-east-1.amazonaws.com/evil.pem`
    which would pass the “ends‑with” check even though it does not meet the strict pattern—and thus be used to verify a forged signature.
  - No additional application‑side whitelist or certificate fingerprint check is performed after retrieval.

- **Preconditions:**
  - The application is deployed publicly and exposes the event‐webhook endpoint (for example, via the `SESEventWebhookView` route).
  - Event signature verification is enabled (the default is to verify signatures using the certificate retrieved).
  - The trusted domains setting (`EVENT_CERT_DOMAINS` or its aliases) is configured with a full domain (e.g. `"sns.us-east-1.amazonaws.com"`) rather than using a broad suffix (e.g. `"amazonaws.com"`).
  - An attacker is able to supply an arbitrary JSON payload containing a forged “SigningCertURL”.

- **Source Code Analysis:**
  - In **`django_ses/utils.py` → `_get_cert_url`**:
    1. The certificate URL is extracted from the notification (`self._data.get("SigningCertURL")`).
    2. The code immediately rejects URLs not beginning with “https://”.
    3. The URL is parsed via `urlparse`.
    4. The function then iterates over each domain specified in `settings.EVENT_CERT_DOMAINS`.
       - For each trusted domain that includes “amazonaws.com”, the URL is checked against the regex `SES_REGEX_CERT_URL`.
       - If this regex check fails and the trusted domain (split by “.”) is short (fewer than four segments), the function returns `None`.
       - If the trusted domain is longer (four segments or more), the function logs warnings about a “possible security risk” but continues to check whether the end segments of the URL’s netloc match those of the trusted domain.
    5. If a match is found by comparing the tail segments (using `url_obj.netloc.split(".")[-len(parts):] == parts`), the certificate URL is accepted and returned.
    6. Thus, the strictness of the certificate URL check relies on both the regex and the exact value (and number of segments) of the trusted domains setting—a misconfiguration here can allow attacker‑controlled URLs to be accepted.

- **Security Test Case:**
  1. **Setup:**
     - Deploy the application in a test environment with event signature verification enabled (`AWS_SES_VERIFY_EVENT_SIGNATURES=True` or the equivalent alias).
     - Set the trusted domains setting to a full domain value—for example:
       ```python
       EVENT_CERT_DOMAINS = ("sns.us-east-1.amazonaws.com",)
       ```
       (instead of the broader default role such as `"amazonaws.com"`).
  2. **Craft the Malicious Request:**
     - Create a JSON payload that mimics an SNS notification but with a forged `"SigningCertURL"` value. For example:
       ```json
       {
         "Type": "Notification",
         "MessageId": "test-id-1234",
         "TopicArn": "arn:aws:sns:us-east-1:123456789012:TestTopic",
         "Subject": "Test",
         "Message": "{\"eventType\":\"Bounce\", \"mail\": {...}, \"bounce\": {...}}",
         "Timestamp": "2024-10-27T17:00:00Z",
         "SignatureVersion": "1",
         "Signature": "Base64EncodedSignature==",
         "SigningCertURL": "https://evil.sns.us-east-1.amazonaws.com/evil.pem",
         "UnsubscribeURL": "https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=..."
       }
       ```
     - (For the purposes of the test, you may mock the cryptographic verification to always return valid even if the signature isn’t correctly generated.)
  3. **Execution:**
     - Using a tool such as cURL or Postman, send a POST request to the `/event-webhook/` endpoint with the JSON payload.
     - For example, using cURL:
       ```sh
       curl -X POST https://your-test-instance.example.com/event-webhook/ \
         -H "Content-Type: application/json" \
         -d '{"Type": "Notification", "MessageId": "test-id-1234", "TopicArn": "arn:aws:sns:us-east-1:123456789012:TestTopic", "Subject": "Test", "Message": "{\"eventType\":\"Bounce\", \"mail\": {}, \"bounce\": {}}", "Timestamp": "2024-10-27T17:00:00Z", "SignatureVersion": "1", "Signature": "Base64EncodedSignature==", "SigningCertURL": "https://evil.sns.us-east-1.amazonaws.com/evil.pem", "UnsubscribeURL": "https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=..."}'
       ```
  4. **Expected Outcome:**
     - **Log Inspection:** Verify that the application logs warnings indicating that the certificate URL does not strictly match the expected pattern (a “possible security risk” warning).
     - **Response:** Observe that the webhook returns an HTTP 200 response (i.e. the forged notification is accepted).
     - **Further Verification:** If possible, check that the application proceeds to process the event (for example, emitting a bounce signal) despite the malicious origin.
  5. **Conclusion:**
     - The test confirms that if the trusted domain is configured with a full domain string, an attacker‑controlled certificate URL (with matching tail segments) may bypass strict validation.

*Note:* This vulnerability would be prevented by using the broad default configuration (e.g. `"amazonaws.com"`) or by enforcing stricter checks (for example, rejecting any certificate URL that does not exactly conform to the regex or by hardcoding the acceptable certificate URL format). Administrators are strongly advised to audit their `EVENT_CERT_DOMAINS` settings to ensure the certificate URL validation cannot be bypassed.