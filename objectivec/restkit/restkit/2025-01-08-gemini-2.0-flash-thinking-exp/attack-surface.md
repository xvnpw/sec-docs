# Attack Surface Analysis for restkit/restkit

## Attack Surface: [Insecure HTTPS Configuration](./attack_surfaces/insecure_https_configuration.md)

**Description:** The application fails to properly configure HTTPS *within RestKit*, leaving communication vulnerable to interception and manipulation.

**How RestKit Contributes:** RestKit handles the underlying HTTP communication. If the application doesn't configure RestKit's `RKObjectManager` or the underlying `AFNetworking` to enforce certificate validation or explicitly ignores certificate errors, it directly creates the opportunity for MITM attacks.

**Example:** An attacker intercepts communication because the application initialized `RKObjectManager` without setting up proper certificate pinning or validation, allowing a proxy with a forged certificate to be accepted.

**Impact:** Data breaches, unauthorized access, manipulation of API requests and responses.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Ensure RestKit's `RKObjectManager` or `AFNetworking` configuration explicitly enables and enforces strict server certificate validation.
* Implement certificate pinning within RestKit's configuration to trust only specific certificates.
* Thoroughly review RestKit's initialization code to avoid disabling certificate validation, even for development purposes.

## Attack Surface: [Server-Side Request Forgery (SSRF) Potential](./attack_surfaces/server-side_request_forgery__ssrf__potential.md)

**Description:** An attacker can induce the application to make requests to arbitrary internal or external resources *by manipulating URLs used within RestKit requests*.

**How RestKit Contributes:** If the application allows user-controlled data to directly influence the URLs used by RestKit's methods for making API requests (e.g., in `getObjectsAtPath:parameters:` or similar methods) without proper validation, it creates a direct path for SSRF.

**Example:** User input is directly used to construct the `path` parameter in `getObjectsAtPath:parameters:`, allowing an attacker to inject an internal URL, forcing the application to make a request to an internal service.

**Impact:** Access to internal resources, port scanning, potential for further attacks on internal systems.

**Risk Severity:** High

**Mitigation Strategies:**
* Strictly validate and sanitize any user input that is used to construct URLs passed to RestKit's request methods.
* Implement allow-lists for permitted API domains or endpoints that RestKit is allowed to access.
* Avoid directly using user input to build the base URL or path components for RestKit requests. Use predefined and validated paths where possible.

