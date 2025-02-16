# Attack Surface Analysis for typhoeus/typhoeus

## Attack Surface: [Server-Side Request Forgery (SSRF)](./attack_surfaces/server-side_request_forgery__ssrf_.md)

*   **Description:**  An attacker causes the server-side application (using Typhoeus) to make requests to unintended destinations, including internal systems, cloud metadata services, or other servers.  This is the *primary* direct Typhoeus vulnerability.
*   **Typhoeus Contribution:** Typhoeus *is* the mechanism for making the HTTP requests.  Its core functionality, when given attacker-controlled input, enables the SSRF.
*   **Example:**
    *   User input: `http://example.com/fetch?url=file:///etc/passwd`
    *   Typhoeus code (vulnerable): `Typhoeus.get(params[:url])`
    *   Result: The application attempts to fetch and potentially expose the contents of `/etc/passwd`.
*   **Impact:**
    *   Access to sensitive internal services and data.
    *   Data exfiltration.
    *   Potential for remote code execution on internal systems.
    *   Bypassing firewalls.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict URL Whitelisting:**  The *best* defense.  Define allowed URLs/hosts and *reject* all others.
    *   **Input Validation and Sanitization:** If user input *must* be used, rigorously validate and sanitize it.  Use a URL parsing library to decompose the URL and check each component (scheme, host, port, path) against an allowlist.
    *   **Network Segmentation:**  Limit the application server's access to internal resources.
    *   **Disable Connection Reuse (for DNS Rebinding):** Set `forbid_reuse: true` in Typhoeus options (performance impact).
    * **Limit allowed protocols**: Restrict the allowed protocols to `http` and `https`.

## Attack Surface: [Redirect Handling Issues (Leading to SSRF)](./attack_surfaces/redirect_handling_issues__leading_to_ssrf_.md)

*   **Description:**  Exploiting Typhoeus's automatic redirect following to cause SSRF.  While redirects are a standard HTTP feature, Typhoeus's *automatic* handling makes this easier to exploit.
*   **Typhoeus Contribution:** Typhoeus, by default (`followlocation: true`), automatically follows HTTP redirects. This is the direct contribution.
*   **Example:**
    *   Initial request: `http://example.com/safe`
    *   Server responds with: `302 Found` and `Location: http://localhost/admin`
    *   Typhoeus automatically follows the redirect to the internal `localhost/admin` endpoint.
*   **Impact:**
    *   Access to sensitive internal resources (same as direct SSRF).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Limit Redirects:** Use `:maxredirs` to limit the number of redirects.
    *   **Validate Redirect URLs:** *Crucially*, validate the URL *after each redirect* using the `on_complete` callback to ensure it's still within the allowed domain/URLs. This is the *most important* mitigation for redirect-based SSRF.
    *   **Disable Automatic Redirects (If Possible):** Set `followlocation: false` if redirects are not needed.

## Attack Surface: [Request Smuggling/Splitting (Indirectly via Misconfiguration)](./attack_surfaces/request_smugglingsplitting__indirectly_via_misconfiguration_.md)

*   **Description:** Exploiting vulnerabilities in how HTTP requests are parsed, leading to the injection of unintended requests. While primarily a backend or application-level issue, Typhoeus's handling of headers is a factor.
*   **Typhoeus Contribution:** Typhoeus transmits the headers provided to it. If the application doesn't sanitize headers *before* passing them to Typhoeus, and the backend is vulnerable, Typhoeus is the conduit.
*   **Example:**
    *   Application code (vulnerable): Fails to validate `Transfer-Encoding` and `Content-Length` headers.
    *   Attacker sends a crafted request with conflicting headers.
    *   Backend server misinterprets, processing a smuggled request. Typhoeus was used to send the malformed request.
*   **Impact:**
    *   Bypassing security controls.
    *   Accessing unauthorized resources.
    *   Cache poisoning.
*   **Risk Severity:** High (but contingent on backend vulnerability *and* application-level header mishandling)
*   **Mitigation Strategies:**
    *   **Strict Header Validation (Application-Level):** The application *must* rigorously validate and sanitize *all* HTTP headers *before* passing them to Typhoeus. Use a well-vetted HTTP header parsing library. This is the *primary* mitigation.
    *   **Secure Backend Servers:** Ensure backend servers are patched and configured to prevent request smuggling.

