# Attack Surface Analysis for restsharp/restsharp

## Attack Surface: [Deserialization of Untrusted Data](./attack_surfaces/deserialization_of_untrusted_data.md)

*   **Description:**  The process of converting data from a serialized format (like JSON or XML) back into objects. If the application deserializes data from untrusted sources without proper validation, attackers can inject malicious payloads that execute code.
*   **RestSharp Contribution:** RestSharp provides built-in support for various serializers and deserializers, making it easy to handle different data formats. This convenience, if misused, *directly* increases the risk of insecure deserialization because RestSharp is the component handling the deserialization process.
*   **Example:** An attacker sends a crafted JSON payload. RestSharp, using a configured (potentially vulnerable) deserializer, processes this payload. The deserialization process triggers the execution of malicious code embedded within the payload.
*   **Impact:** Remote Code Execution (RCE), complete system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Use Safe Deserializers:** Prefer modern, secure deserializers like `System.Text.Json` (for JSON). Avoid older or less-maintained libraries.  Explicitly configure RestSharp to use the secure deserializer.
    *   **Strict Type Handling:** Define specific classes for expected data structures. Avoid using `dynamic`, `object`, or loosely-typed objects during deserialization with RestSharp.
    *   **Input Validation (Post-Deserialization):** After RestSharp deserializes the data, thoroughly validate the *contents* of the resulting objects. Check for unexpected values, out-of-range data, etc.
    *   **Type Allow List:** Implement an allow list of permitted types for deserialization within RestSharp's configuration. Reject any attempt to deserialize types not on the list.
    *   **Avoid Custom Deserializers:** Unless absolutely necessary and thoroughly audited, avoid using custom deserializers with RestSharp.

## Attack Surface: [XML External Entity (XXE) Attacks (When Using XML)](./attack_surfaces/xml_external_entity__xxe__attacks__when_using_xml_.md)

*   **Description:**  Exploits vulnerabilities in XML parsers to access local files, make internal network requests, or cause denial of service.
*   **RestSharp Contribution:** RestSharp can handle XML responses and *directly* uses an XML parser (either built-in or a custom one provided to it) for this purpose.  If this parser is misconfigured, RestSharp's XML handling becomes the direct attack vector.
*   **Example:** An attacker sends an XML payload containing an external entity reference. RestSharp, using its configured XML deserializer, processes this payload.  The vulnerable XML parser resolves the external entity, leading to file disclosure or SSRF.
*   **Impact:** Local File Disclosure, Server-Side Request Forgery (SSRF), Denial of Service (DoS).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable DTDs and External Entities:** *Crucially*, configure the XML parser used by RestSharp (or the custom serializer provided to RestSharp) to disable Document Type Definitions (DTDs) and the resolution of external entities. This is the primary mitigation and must be done within RestSharp's configuration or through the chosen serializer's settings.
    *   **Use a Secure XML Parser:** Ensure the underlying XML parser used by (or provided to) RestSharp is known to be secure and up-to-date.

## Attack Surface: [Client-Side Request Manipulation (Direct Parameter Handling)](./attack_surfaces/client-side_request_manipulation__direct_parameter_handling_.md)

*   **Description:** Although RestSharp aims to prevent this, improper use of its parameter handling *can* directly lead to vulnerabilities.
*   **RestSharp Contribution:** If developers bypass RestSharp's recommended parameterization methods (`AddParameter`, `AddBody`, etc.) and *instead* directly construct URLs or request bodies by string concatenation with user input, RestSharp becomes the conduit for the attack, even though the root cause is improper coding practice. This is a *direct* involvement because RestSharp is the library being used to send the manipulated request.
*   **Example:** A developer uses string concatenation to build a URL: `restClient.Get(new RestRequest("https://api.example.com/items?id=" + userInput));`. If `userInput` is not properly sanitized, an attacker could inject malicious values. While the vulnerability is in the application code, RestSharp is the *direct* mechanism used to send the vulnerable request.
*   **Impact:** Varies depending on the backend vulnerability (e.g., SQL Injection, command injection), but can be High.
*   **Risk Severity:** High (depending on the backend vulnerability it enables)
*   **Mitigation Strategies:**
    *   **Mandatory Parameterization:** *Always* use RestSharp's built-in parameterization methods (`AddParameter`, `AddBody`, `AddQueryParameter`, etc.) for *all* user-supplied data.  *Never* construct URLs or request bodies through string concatenation with unsanitized user input. This is the most critical mitigation.
    *   **Input Validation:** Even when using parameterization, thoroughly validate and sanitize all user-supplied data as a defense-in-depth measure.

