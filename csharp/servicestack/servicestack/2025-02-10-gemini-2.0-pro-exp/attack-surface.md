# Attack Surface Analysis for servicestack/servicestack

## Attack Surface: [Unintentional Service Exposure (via ServiceStack Routing)](./attack_surfaces/unintentional_service_exposure__via_servicestack_routing_.md)

*   **Description:** Exposing internal methods, data, or entire services that were not intended for public access due to ServiceStack's routing mechanisms.
*   **ServiceStack Contribution:** ServiceStack's convention-over-configuration and automatic routing (especially AutoQuery) can lead to unintended exposure if developers are not *extremely* explicit about what should be accessible.  This is a *direct* consequence of ServiceStack's design.
*   **Example:** A developer creates a service class `InternalDataService` with a method `GetSensitiveData()`. Without explicit `[Route]` attributes or `[Restrict]` attributes, this method might become accessible.  A simple `[AutoQuery]` attribute on an entity, without careful `Include`/`Exclude` configuration, exposes the entire table.
*   **Impact:** Data breaches, unauthorized data modification, potential for privilege escalation.
*   **Risk Severity:** High to Critical.
*   **Mitigation Strategies:**
    *   **Explicit Routing (Mandatory):** Use `[Route]` attributes on *every* service and method to define *exactly* which routes are exposed and which HTTP verbs are allowed.  *Never* rely on naming conventions alone.
    *   **Restrict Attribute (Mandatory):** Use `[Restrict]` to limit access based on roles, permissions, or IP addresses. Apply this *proactively* to *all* services.
    *   **DTOs (Mandatory):** Use Data Transfer Objects (DTOs) to define the precise input and output.  *Never* expose domain models directly.
    *   **AutoQuery Control (Mandatory):** For AutoQuery, *always* use `Include` and `Exclude` to whitelist/blacklist fields. Implement custom `ICreateDb`, `IUpdateDb`, `IDeleteDb` interfaces for fine-grained control, validation, and authorization.
    *   **Code Reviews (Mandatory):** Thorough code reviews, focusing on service contracts, routing, and AutoQuery configurations, are *essential*.

## Attack Surface: [Type-Hinting Deserialization Vulnerabilities (JSV/JSON)](./attack_surfaces/type-hinting_deserialization_vulnerabilities__jsvjson_.md)

*   **Description:** Attackers injecting malicious type information during ServiceStack's JSON or JSV deserialization to instantiate arbitrary objects and potentially execute code.
*   **ServiceStack Contribution:** This is a *direct* vulnerability related to how ServiceStack's serializers *can* be configured to handle type hints (e.g., `__type`). The vulnerability exists *because* of ServiceStack's serialization features.
*   **Example:** An attacker sends a JSON payload with a `__type` property set to a malicious class. If ServiceStack is configured to allow this (without a strict whitelist), it can lead to RCE.
*   **Impact:** Remote Code Execution (RCE), complete system compromise.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Disable Type Hints (Mandatory):** Set `JsConfig.ExcludeTypeInfo = true;` globally. This is the *primary and most effective* mitigation.
    *   **Strict Whitelisting (Fallback, Only If Absolutely Necessary):** If (and *only if*) type hints are *absolutely required*, use `JsConfig.AllowRuntimeType` with a *very restrictive* whitelist of allowed types.  This is a *less secure* option and should be avoided if possible.

## Attack Surface: [XML External Entity (XXE) Attacks (via ServiceStack XML Support)](./attack_surfaces/xml_external_entity__xxe__attacks__via_servicestack_xml_support_.md)

*   **Description:** Attackers exploiting vulnerabilities in ServiceStack's XML parser to access local files or internal network resources.
*   **ServiceStack Contribution:** ServiceStack's support for XML serialization/deserialization *directly* introduces this vulnerability if not properly configured.
*   **Example:** An attacker sends an XML payload containing an external entity declaration that points to a sensitive local file.
*   **Impact:** Data exfiltration, denial of service, potential for server-side request forgery (SSRF).
*   **Risk Severity:** High to Critical.
*   **Mitigation Strategies:**
    *   **Disable XML (Preferred):** If XML support is not needed, disable it entirely within ServiceStack.
    *   **Disable DTD Processing (Mandatory if XML is Used):** If XML is required, configure ServiceStack's XML parser to *disable* Document Type Definition (DTD) processing. Ensure `DtdProcessing` is set to `Prohibit` or `Ignore`. This is a *direct* configuration change within ServiceStack.

## Attack Surface: [Authentication and Authorization Bypass (within ServiceStack)](./attack_surfaces/authentication_and_authorization_bypass__within_servicestack_.md)

* **Description:** Attackers bypassing ServiceStack's authentication or authorization mechanisms to gain unauthorized access.
* **ServiceStack Contribution:** Vulnerabilities or misconfigurations *within* ServiceStack's authentication providers (JWT, Credentials, OAuth, etc.) or its authorization attributes (`[Authenticate]`, `[RequiredRole]`) *directly* lead to this risk.
* **Example:**
    * A weak JWT secret allows attackers to forge valid JWT tokens, bypassing ServiceStack's JWT authentication.
    * Incorrectly configured `[Authenticate]` or `[RequiredRole]` attributes on ServiceStack services allow unauthorized access.
* **Impact:** Unauthorized access to sensitive data and functionality, potential for privilege escalation.
* **Risk Severity:** High to Critical.
* **Mitigation Strategies:**
    * **Strong Secrets (Mandatory):** Use strong, randomly generated secrets for ServiceStack's JWT and other authentication mechanisms.
    * **Proper Attribute Usage (Mandatory):** Carefully and *correctly* apply `[Authenticate]`, `[RequiredRole]`, and `[RequiredPermission]` attributes to *all* relevant ServiceStack services and methods.
    * **Secure Session Management (Mandatory):** Configure ServiceStack to use secure, HTTP-only cookies. Set appropriate session timeouts. Regenerate session IDs after authentication (using ServiceStack's session management features).

