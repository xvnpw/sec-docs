# Attack Surface Analysis for urllib3/urllib3

## Attack Surface: [Header Injection/Smuggling](./attack_surfaces/header_injectionsmuggling.md)

*   **Description:** Attackers inject malicious HTTP headers by manipulating user input that is used to construct headers sent via `urllib3`.
*   **`urllib3` Contribution:** `urllib3` provides the mechanism for setting HTTP headers; the vulnerability arises from *how* the application uses this mechanism, making it a direct interaction point.
*   **Example:** An application uses `headers = {'User-Agent': user_input}` without sanitizing `user_input`.  An attacker provides `user_input = "MyBrowser\r\nEvil-Header: evil_value"` to inject the `Evil-Header`.
*   **Impact:** Can lead to HTTP request smuggling, bypassing security controls, cache poisoning, and potentially session hijacking.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Sanitize and validate all user-supplied data before using it in HTTP headers. Use `urllib3`'s structured header input (dictionaries) rather than string concatenation. Employ a dedicated header validation library if complex header manipulation is needed.

## Attack Surface: [Request Splitting/Smuggling (CRLF Injection in URL)](./attack_surfaces/request_splittingsmuggling__crlf_injection_in_url_.md)

*   **Description:** Attackers inject CRLF (`\r\n`) characters into the URL passed to `urllib3` to manipulate the HTTP request.
*   **`urllib3` Contribution:** `urllib3` processes the provided URL; the vulnerability stems from the application's failure to properly encode/validate the URL, making the URL parsing and request formation within `urllib3` a direct point of attack.
*   **Example:** An application uses `urllib3.request('GET', f'http://example.com/{user_input}')` without URL-encoding `user_input`. An attacker provides `user_input = "page\r\nGET / HTTP/1.1\r\nHost: attacker.com\r\n\r\n"` to send a second request to `attacker.com`.
*   **Impact:** Can lead to request smuggling, bypassing security controls, and potentially accessing unauthorized resources.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Always URL-encode user-supplied data before incorporating it into a URL using functions like `urllib.parse.quote`. Validate the URL's structure before passing it to `urllib3`.

## Attack Surface: [Proxy Bypass](./attack_surfaces/proxy_bypass.md)

*   **Description:** If proxy settings are influenced by user input, attackers might bypass the configured proxy or connect to a malicious proxy.
*   **`urllib3` Contribution:** `urllib3` uses the provided proxy settings for connection establishment; the vulnerability lies in how those settings are determined and passed to `urllib3`, making this a direct interaction.
*   **Example:** An application allows users to specify a proxy server, and an attacker provides a malicious proxy address or manipulates parameters to bypass the intended proxy.
*   **Impact:** Bypassing security controls, traffic interception, and potential man-in-the-middle attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Hardcode proxy settings whenever possible. If dynamic configuration is necessary, strictly validate and sanitize user input influencing proxy settings *before* passing them to `urllib3`.

## Attack Surface: [Unsafe Deserialization (Post-Response)](./attack_surfaces/unsafe_deserialization__post-response_.md)

*    **Description:** Although `urllib3` itself doesn't perform deserialization, it's the component fetching the potentially malicious data. The critical vulnerability arises when the *application* using `urllib3` deserializes the response data unsafely.  This is included because `urllib3` is the *direct source* of the untrusted data.
*   **`urllib3` Contribution:** `urllib3` retrieves the data that is then (unsafely) deserialized by the application.  It is the *conduit* for the malicious payload.
*   **Example:** An application uses `pickle.loads(response.data)` on data fetched from an untrusted source via `urllib3`.
*   **Impact:** Remote code execution.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Avoid unsafe deserialization methods like `pickle` with untrusted data received from `urllib3`. Use safer alternatives like `json.loads` for JSON. Thoroughly review custom deserialization implementations.  *Never* deserialize data from an untrusted source without extreme caution and robust validation.

