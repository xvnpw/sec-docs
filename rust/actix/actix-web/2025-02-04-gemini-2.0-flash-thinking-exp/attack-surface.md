# Attack Surface Analysis for actix/actix-web

## Attack Surface: [HTTP Header Parsing Vulnerabilities](./attack_surfaces/http_header_parsing_vulnerabilities.md)

*   **Description:** Flaws in Actix-web's HTTP header parsing logic can lead to attacks due to incorrect handling of header formats, encodings, or sizes.

    *   **Actix-web Contribution:** Actix-web is responsible for parsing incoming HTTP requests, including headers. Vulnerabilities in its header parsing code are directly exploitable.

    *   **Example:** An attacker sends a request with an excessively long or malformed header that exploits a buffer overflow or other parsing flaw in Actix-web. This could lead to Denial of Service (DoS), HTTP Request Smuggling/Splitting, or potentially Remote Code Execution (RCE) if memory corruption is exploitable.

    *   **Impact:** Denial of Service (DoS), HTTP Request Smuggling/Splitting, Header Injection, potentially Remote Code Execution (RCE).

    *   **Risk Severity:** High to Critical

    *   **Mitigation Strategies:**
        *   **Keep Actix-web Updated:** Regularly update Actix-web to the latest version to benefit from security patches in header parsing.
        *   **Use a Reverse Proxy:** Employ a reverse proxy (like Nginx or Apache) in front of Actix-web. Reverse proxies often have robust header parsing and can filter out malformed requests.
        *   **Limit Header Sizes (Application Level):** Configure Actix-web's server settings to limit the maximum allowed header size.
        *   **Careful Header Handling in Application Code:** Avoid directly using unsanitized header values in responses or further requests to prevent header injection.

## Attack Surface: [Route Overlap/Confusion](./attack_surfaces/route_overlapconfusion.md)

*   **Description:** Incorrectly defined or overly complex route patterns in Actix-web can lead to unintended route matching, allowing access to unauthorized handlers.

    *   **Actix-web Contribution:** Actix-web's routing system, based on path matching, can be susceptible to confusion if route definitions are ambiguous or overlapping.

    *   **Example:** Consider routes `/admin/users` and `/admin/{resource}`. If `/admin/{resource}` is defined before `/admin/users`, a request to `/admin/users` might be incorrectly routed to the more general `/admin/{resource}` handler, potentially bypassing specific access controls intended for `/admin/users`.

    *   **Impact:** Authorization bypass, access to sensitive functionality.

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Careful Route Definition:** Design routes with clarity, avoiding overlapping patterns. Be explicit in route definitions.
        *   **Route Ordering:** Understand Actix-web's route matching order (first-match wins) and place more specific routes before more general ones.
        *   **Route Testing:** Thoroughly test route definitions to ensure requests are routed as intended and there are no unexpected overlaps.
        *   **Use Route Guards/Extractors for Authorization:** Implement robust authorization checks within route handlers using Actix-web's guards and extractors, independent of route matching logic, to enforce access control.

## Attack Surface: [Regular Expression Denial of Service (ReDoS) in Route Matching](./attack_surfaces/regular_expression_denial_of_service__redos__in_route_matching.md)

*   **Description:** Vulnerable regular expressions used in Actix-web route definitions can be exploited for ReDoS attacks. Crafted input strings can cause excessive CPU consumption by the regex engine.

    *   **Actix-web Contribution:** Actix-web allows using regular expressions in route paths for flexible matching, which introduces ReDoS risk if regexes are not carefully designed.

    *   **Example:** A route defined with a vulnerable regex like `/api/items/{item_id:.*(a+)+c}`. An attacker sends a request with a long string like `/api/items/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac`. This input can trigger excessive backtracking in the regex engine, leading to CPU exhaustion and DoS.

    *   **Impact:** Denial of Service (DoS).

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Avoid Complex Regular Expressions in Routes:** Prefer simpler route patterns. If regex is necessary, keep them concise and avoid nested quantifiers and alternations.
        *   **Regex Testing and Analysis:** Test regular expressions used in routes with various inputs, including potentially malicious ones, to identify ReDoS vulnerabilities. Use regex analyzers or online tools.
        *   **Limit Request Processing Time (Server Level):** Configure timeouts in Actix-web's server settings to limit the maximum time spent processing a single request, mitigating the impact of ReDoS.

