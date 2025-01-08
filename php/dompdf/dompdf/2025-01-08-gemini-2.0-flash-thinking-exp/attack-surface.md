# Attack Surface Analysis for dompdf/dompdf

## Attack Surface: [Server-Side Request Forgery (SSRF) via Remote URL Inclusion](./attack_surfaces/server-side_request_forgery__ssrf__via_remote_url_inclusion.md)

*   **Description:** If Dompdf is configured to allow fetching remote resources (images, stylesheets) via URLs in the input HTML, an attacker can provide malicious URLs to force the server running Dompdf to make requests to internal or external resources.
*   **How Dompdf Contributes:** Dompdf's ability to fetch external resources based on URLs in the HTML is the direct contributor to this attack surface.
*   **Example:**  An attacker provides HTML like `<img src="http://internal.network/admin/sensitive_data.txt">`. If remote URL fetching is enabled, the server running Dompdf will attempt to fetch this resource.
*   **Impact:**
    *   **Internal Network Scanning:** Attackers can probe internal network infrastructure.
    *   **Access to Internal Resources:** Attackers can potentially access sensitive data on internal systems.
    *   **Bypassing Access Controls:**  Attackers can interact with internal services that are not exposed to the public internet.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable Remote URL Fetching:**  The most effective mitigation is to disable the ability for Dompdf to fetch remote URLs. Configure Dompdf to only use locally available resources.
    *   **Whitelist Allowed Hosts/Domains:** If remote fetching is necessary, implement a strict whitelist of allowed hosts or domains that Dompdf is permitted to access.
    *   **Input Validation for URLs:**  If remote URLs are allowed, rigorously validate the format and content of the provided URLs to prevent access to internal or malicious endpoints.

