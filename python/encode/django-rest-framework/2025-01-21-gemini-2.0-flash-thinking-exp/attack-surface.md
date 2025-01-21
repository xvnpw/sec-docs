# Attack Surface Analysis for encode/django-rest-framework

## Attack Surface: [Insecure Deserialization](./attack_surfaces/insecure_deserialization.md)

*   **Description:** A vulnerability where untrusted data is deserialized, potentially leading to arbitrary code execution or other malicious actions.
*   **How Django REST Framework Contributes:** DRF's serializers automatically handle deserialization of incoming data. If custom serializers or fields are used without proper sanitization, or if formats like `pickle` are used directly within DRF serializers, it can become a vector for attack.
*   **Example:** An attacker sends a request with a malicious `pickle` payload in the request body. A custom serializer field deserializes this payload without proper checks, leading to code execution on the server.
*   **Impact:** Arbitrary code execution, server compromise, data breach.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Avoid using insecure deserialization formats like `pickle` directly in DRF serializers.
    *   Sanitize and validate all incoming data before deserialization within custom serializer logic.
    *   Use safer serialization formats like JSON or YAML with DRF's built-in support.
    *   Implement robust input validation within custom serializer fields.
    *   Regularly audit custom serializer code for potential deserialization vulnerabilities.

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

*   **Description:** A vulnerability where an attacker can modify unintended model fields by including them in the request data.
*   **How Django REST Framework Contributes:** DRF serializers can automatically map request data to model fields. If `fields` or `exclude` attributes are not explicitly defined in the serializer, or if `read_only` fields are not properly configured within the DRF serializer, attackers might be able to modify sensitive fields.
*   **Example:** A user sends a PATCH request to update their profile, including an `is_staff` field in the request data. If the DRF serializer doesn't explicitly exclude this field or mark it as `read_only`, the attacker could potentially elevate their privileges.
*   **Impact:** Data corruption, privilege escalation, unauthorized access.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Explicitly define the `fields` or `exclude` attributes in DRF serializers to control which fields can be modified.
    *   Mark sensitive fields as `read_only` in the DRF serializer definition.
    *   Use `extra_kwargs` in the `Meta` class of the serializer to further control field behavior within DRF.
    *   Regularly review DRF serializer definitions to ensure proper field control.

## Attack Surface: [Authorization Bypass](./attack_surfaces/authorization_bypass.md)

*   **Description:** A vulnerability where an attacker can access or modify resources they are not authorized to access.
*   **How Django REST Framework Contributes:** DRF's permission classes control access to API endpoints. Misconfigured or poorly implemented DRF permission classes can lead to authorization bypass. This includes issues with object-level permissions handled by DRF.
*   **Example:** An API endpoint uses a DRF permission class that only checks if a user is authenticated but doesn't verify if they own the specific resource they are trying to access. An attacker could then access or modify resources belonging to other users.
*   **Impact:** Unauthorized data access, data modification, privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use DRF's built-in permission classes appropriately (e.g., `IsAuthenticated`, `IsAdminUser`, `IsAuthenticatedOrReadOnly`).
    *   Implement custom DRF permission classes for more granular control, especially for object-level permissions.
    *   Thoroughly test DRF permission logic to ensure it behaves as expected.
    *   Avoid relying solely on client-side checks for authorization when using DRF.

## Attack Surface: [XML External Entity (XXE) Attacks](./attack_surfaces/xml_external_entity__xxe__attacks.md)

*   **Description:** A vulnerability that allows an attacker to interfere with an application's processing of XML data, potentially leading to information disclosure or denial of service.
*   **How Django REST Framework Contributes:** If the API, configured through DRF's parsers, accepts XML input and uses a vulnerable XML parser (either directly or through a third-party library integrated with DRF), it can be susceptible to XXE attacks.
*   **Example:** An attacker sends an XML payload containing an external entity definition that points to a local file on the server. If the XML parser configured within DRF is not set up to prevent external entity resolution, the attacker can read the contents of that file.
*   **Impact:** Information disclosure, denial of service, server-side request forgery (SSRF).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Disable external entity processing in XML parsers used by DRF. Configure the parser securely within the DRF parser settings.
    *   Prefer safer data formats like JSON if possible, and configure DRF to prioritize these.
    *   Sanitize and validate XML input thoroughly before it's processed by DRF.
    *   Keep XML parsing libraries used by DRF up to date.

