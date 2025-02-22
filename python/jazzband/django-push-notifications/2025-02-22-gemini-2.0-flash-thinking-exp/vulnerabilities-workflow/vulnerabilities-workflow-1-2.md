- **Vulnerability Name:** Broken Access Control in Push Notification Device API Endpoints
  **Description:**
  The REST API viewsets for device registrations (for APNS, GCM, WNS, and WebPush) are implemented as plain ModelViewSets (via the DeviceViewSetMixin) without built‐in authentication or per–user filtering. Although separate “Authorized” viewsets exist (by mixing in an AuthorizedMixin that filters the queryset to devices belonging only to the current user), the default endpoints do not enforce any such restrictions. An external attacker who discovers these endpoints on a publicly accessible instance might register new devices, update existing records, or enumerate and delete other users’ device tokens.
  **Impact:**
  An attacker may modify (or view) device registration records belonging to arbitrary users. This can lead to:
  - Sending unauthorized or malicious notifications.
  - Tampering with push notification settings and privacy breaches.
  - Disruption of the notification functionality for legitimate users.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The project does provide “Authorized” viewset variants (for example, APNSDeviceAuthorizedViewSet, GCMDeviceAuthorizedViewSet) that use an AuthorizedMixin to restrict querysets to the current user.
  **Missing Mitigations:**
  - The default API endpoints (e.g. APNSDeviceViewSet, GCMDeviceViewSet, etc.) do not enforce any authentication or access control by default.
  - No whitelist or default permission settings are applied to limit access, forcing integrators to manually use the “Authorized” variants.
  **Preconditions:**
  - The push notifications API endpoints are exposed to the public (or accessible without required authentication).
  - An attacker can send HTTP requests (POST, PATCH, GET, DELETE) against the device endpoints.
  **Source Code Analysis:**
  - In **/code/push_notifications/api/rest_framework.py** the base viewsets (e.g. APNSDeviceViewSet, GCMDeviceViewSet, etc.) simply set `queryset = …objects.all()` and inherit from ModelViewSet without enforcing authentication.
  - Only by explicitly using the AuthorizedMixin (as in APNSDeviceAuthorizedViewSet, etc.) is the queryset filtered by `user=self.request.user`.
  **Security Test Case:**
  1. Using an HTTP client (e.g. curl or Postman), send a POST request to the (for example) `/api/apnsdevices/` endpoint with JSON data containing arbitrary device details (e.g. “registration_id”, “application_id”, “name”) without providing any credentials.
  2. Confirm that the new device record is created.
  3. Send a GET request to the same endpoint and verify that the attacker can retrieve the complete list of registered devices—even those belonging to other users.
  4. Attempt a PATCH or DELETE on an existing device record (possibly one registered to another user) and verify that the operation succeeds.

- **Vulnerability Name:** Arbitrary XML Injection in WNS Notification Payloads
  **Description:**
  When sending WNS (Windows Notification Service) notifications, the function `dict_to_xml_schema` converts a user‐provided dictionary into an XML tree by using the dictionary’s keys directly as XML tag names and the “attrs” and “children” values to build sub–elements. There is no sanitization or whitelist of allowed tags. If an attacker controls the “xml_data” parameter (for example, via an API call or admin tool that triggers a WNS message), they can craft input with malicious tag names or attributes to inject arbitrary XML.
  **Impact:**
  The attacker may be able to manipulate the XML payload in unexpected ways. Downstream, the WNS service (or any intermediary XML processor) may misinterpret the data—leading to:
  - Bypassing validation checks or altering notification content.
  - Triggering errors that reveal internal system details.
  - In worst‐case scenarios, if processed by vulnerable XML parsers, the injected content may be used for further attacks (although Python’s built–in ElementTree is generally safe against external entity injection).
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The implementation simply uses ElementTree methods without any sanitization. No built–in whitelist or strict schema enforcement is provided.
  **Missing Mitigations:**
  - Input validation and sanitization should be implemented to restrict dictionary keys (and thus XML tag names) to a known safe set.
  - Alternatively, use an XML builder or schema validator that enforces the expected WNS format and rejects unexpected or dangerous tag names.
  **Preconditions:**
  - The attacker must be able to invoke the WNS notification functionality and supply an “xml_data” payload.
  - The endpoint that uses `wns_send_message` (or its bulk variant) must be accessible for such manipulation.
  **Source Code Analysis:**
  - In **/code/push_notifications/wns.py**, the function `dict_to_xml_schema` loops over the input dictionary and for each key calls `ET.Element(key)`. There is no check that the key is a valid or expected tag name.
  - The unsanitized XML is then converted to bytes using `ET.tostring(xml)` and passed along as the notification payload.
  **Security Test Case:**
  1. Craft a JSON payload for the WNS notification API that uses the “xml_data” parameter. For example, pass:
     ```json
     {
	   "xml_data": {
         "<script>alert('XSS')</script>": {
           "children": "Injected content"
         }
       }
     }
     ```
  2. Submit the payload via the API endpoint (or via an admin tool that triggers `wns_send_message`).
  3. Observe (via logging or by capturing the outgoing HTTP request) that the generated XML payload contains the unsanitized tag name.
  4. Verify that the WNS service responds with an error or unexpected behavior that confirms the payload was not sanitized.

- **Vulnerability Name:** SSRF via Malicious WNS Notification URIs
  **Description:**
  The function `_wns_send` is used to send notifications to WNS devices. It accepts a “uri” parameter that is provided (directly from the WNSDevice’s registration_id field) without strict validation. Although a simple check is made in some parts of the code (for example, testing whether the URI begins with “https://”), an attacker who can register or update a WNS device may supply an arbitrary URI (for example, an internal URL). When a notification is sent using such a record, the server will perform an outbound HTTP request (via `urlopen`) to that URI.
  **Impact:**
  An attacker may abuse this lack of validation to cause the server to send HTTP requests to internal network addresses or services that are not otherwise accessible from outside, resulting in a Server–Side Request Forgery (SSRF). This could lead to:
  - Scanning or interacting with internal resources (potential pivot point for further attacks).
  - Data leakage from internal services.
  - Abuse of the server as a proxy to attack other networks.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - A very basic check is made in parts of the WNS logic (for example, in `get_subscription_info` for webpush, a scheme check is performed). However, no strict whitelist or validation is done for WNS URIs.
  **Missing Mitigations:**
  - Strict validation of the “uri” parameter in functions such as `_wns_send` should be added. For a WNS notification, the registration_id should be checked against an expected pattern (for example, it must start with “https://” and belong to a trusted domain such as “notify.windows.com”).
  **Preconditions:**
  - The attacker must be able to register (or update) a WNSDevice record with a custom “registration_id” value.
  - The push notification send function is later triggered so that the value in registration_id is used as the target URI for an outbound HTTP request.
  **Source Code Analysis:**
  - In **/code/push_notifications/wns.py** the function `_wns_send` builds an HTTP Request by directly passing the “uri” parameter received from upstream. No sanitization or validation is performed on this URI.
  - The higher–level function `wns_send_message` simply passes its “uri” argument (usually the device’s registration_id) to `_wns_send` without further verification.
  **Security Test Case:**
  1. Register a new WNS device via the (or via the REST API endpoint or admin interface) by supplying a registration_id value such as `http://127.0.0.1:80/internal/admin` instead of a valid WNS URI.
  2. Trigger a WNS notification send (for example, using the provided API or admin action).
  3. On the server side, monitor outbound HTTP requests (or use network logging) to confirm that a request is made to `http://127.0.0.1:80/internal/admin`.
  4. Confirm that the request reaches an internal endpoint—demonstrating that SSRF is possible.