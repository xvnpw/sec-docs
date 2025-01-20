# Attack Surface Analysis for freshrss/freshrss

## Attack Surface: [Cross-Site Scripting (XSS) via Malicious Feed Content](./attack_surfaces/cross-site_scripting__xss__via_malicious_feed_content.md)

- **Description:** Attackers inject malicious scripts into feed content (titles, descriptions, content) that are then executed in the browsers of users viewing those feeds within FreshRSS.
- **How FreshRSS Contributes:** FreshRSS fetches and renders feed content. If it doesn't properly sanitize this content before displaying it to users, it becomes vulnerable to XSS.
- **Example:** A malicious feed includes an item with a title like `<script>alert('XSS')</script>`. When a user views this feed in FreshRSS, the script will execute in their browser.
- **Impact:**  Account takeover (session hijacking), redirection to malicious sites, information theft, defacement of the FreshRSS interface for the victim.
- **Risk Severity:** High
- **Mitigation Strategies:**
    - **Developers:**
        - Implement robust HTML sanitization on all feed content before rendering it to users. Utilize a well-vetted and regularly updated sanitization library.
        - Employ Content Security Policy (CSP) to restrict the sources from which the browser is allowed to load resources, mitigating the impact of injected scripts.
        - Use templating engines that offer automatic escaping of output by default.

## Attack Surface: [XML External Entity (XXE) Injection via Feed Parsing](./attack_surfaces/xml_external_entity__xxe__injection_via_feed_parsing.md)

- **Description:** Attackers craft malicious XML feed content that causes the XML parser used by FreshRSS to access local files or internal network resources, potentially disclosing sensitive information or leading to denial of service.
- **How FreshRSS Contributes:** FreshRSS uses XML parsing libraries to process RSS and Atom feeds. If these libraries are not configured securely, they can be vulnerable to XXE.
- **Example:** A malicious feed contains an XML entity definition that references a local file (e.g., `/etc/passwd`) or an internal network resource. When FreshRSS parses this feed, it attempts to access the specified resource.
- **Impact:** Disclosure of sensitive files, internal network reconnaissance, denial of service.
- **Risk Severity:** High
- **Mitigation Strategies:**
    - **Developers:**
        - Disable external entity processing in the XML parsing library configuration. This is the most effective mitigation.
        - If external entities are absolutely necessary, implement strict input validation and sanitization of entity declarations.
        - Use a modern XML parser that offers better security features and is regularly updated.

## Attack Surface: [Server-Side Request Forgery (SSRF) via Feed Processing](./attack_surfaces/server-side_request_forgery__ssrf__via_feed_processing.md)

- **Description:** Attackers manipulate feed content or feed URLs to force the FreshRSS server to make requests to unintended internal or external resources.
- **How FreshRSS Contributes:** FreshRSS fetches feed content from URLs provided by users. If not properly validated, these URLs can be manipulated. Additionally, some feed content might contain references to external resources (e.g., images) that FreshRSS attempts to fetch.
- **Example:** A malicious feed URL points to an internal service on the server's network (e.g., `http://localhost:8080/admin`). When FreshRSS attempts to fetch this "feed," it interacts with the internal service. Alternatively, a feed item might contain an `<img>` tag with a `src` attribute pointing to an internal resource.
- **Impact:** Access to internal services, port scanning of internal networks, potential for further exploitation of internal systems, data exfiltration from internal resources.
- **Risk Severity:** High
- **Mitigation Strategies:**
    - **Developers:**
        - Implement strict validation and sanitization of feed URLs. Use allow-lists of allowed protocols and domains if possible.
        - When fetching external resources referenced in feed content, use a proxy or a dedicated service with restricted network access.
        - Implement network segmentation to limit the impact of SSRF by restricting the resources the FreshRSS server can access.

