# Attack Surface Analysis for ampproject/amphtml

## Attack Surface: [<amp-script> Sandbox Escape](./attack_surfaces/amp-script_sandbox_escape.md)

**Description:** Exploiting vulnerabilities within the isolated JavaScript environment provided by `<amp-script>` to break out of the sandbox and gain access to the main page's context or browser APIs.

**How AMPHTML Contributes:** `<amp-script>` allows for custom JavaScript, but restricts its capabilities within a sandboxed iframe. Vulnerabilities in the sandbox implementation itself, which is part of the AMP HTML framework, can allow attackers to bypass these restrictions.

**Example:** A crafted script within `<amp-script>` leverages a browser bug or an oversight in the AMP sandbox implementation to access `window.top` or execute arbitrary JavaScript on the main page.

**Impact:** Critical. Successful sandbox escape can lead to full compromise of the user's session on the main page, enabling actions like stealing cookies, performing actions on behalf of the user, or redirecting to malicious sites (XSS).

**Risk Severity:** Critical

**Mitigation Strategies:**

* **Developers:**
    * Keep the AMP HTML library updated to benefit from security patches addressing sandbox vulnerabilities.
    * Minimize the use of `<amp-script>` if possible. Consider alternative AMP components for desired functionality.
    * Thoroughly test any custom JavaScript within `<amp-script>` for potential vulnerabilities, even within the sandbox constraints.

## Attack Surface: [<amp-iframe> Malicious Content Injection](./attack_surfaces/amp-iframe_malicious_content_injection.md)

**Description:** Embedding an iframe using `<amp-iframe>` that loads malicious content from an attacker-controlled domain.

**How AMPHTML Contributes:** The `<amp-iframe>` component in AMP HTML allows embedding external content. If the source URL is not carefully controlled or validated, attackers can inject iframes pointing to malicious sites.

**Example:** An attacker compromises a data source used to populate the `src` attribute of `<amp-iframe>`, replacing a legitimate URL with a link to a phishing site or a site hosting malware.

**Impact:** High. Users visiting the AMP page could be exposed to phishing attacks, drive-by downloads, or other malicious content within the iframe.

**Risk Severity:** High

**Mitigation Strategies:**

* **Developers:**
    * Strictly control and validate the source URLs used in `<amp-iframe>` tags. Use allowlists of trusted domains.
    * Avoid dynamically generating `<amp-iframe>` `src` attributes based on user input or untrusted data sources.
    * Consider using the `sandbox` attribute on `<amp-iframe>` to further restrict the capabilities of the embedded content.

## Attack Surface: [<amp-bind> Expression Injection](./attack_surfaces/amp-bind_expression_injection.md)

**Description:** Exploiting vulnerabilities in how `<amp-bind>` expressions are evaluated to inject malicious code or manipulate the page's state in unintended ways.

**How AMPHTML Contributes:** The `<amp-bind>` component in AMP HTML allows dynamic updates to page elements based on data and expressions. If these expressions are not properly sanitized or validated, attackers can inject malicious JavaScript or manipulate the application's logic through AMP's data binding mechanism.

**Example:** An attacker crafts a malicious URL parameter that is used in an `<amp-bind>` expression, causing the execution of arbitrary JavaScript when the page loads or when a state change occurs.

**Impact:** High. Successful expression injection can lead to XSS, allowing attackers to steal user data, perform actions on their behalf, or deface the page.

**Risk Severity:** High

**Mitigation Strategies:**

* **Developers:**
    * Avoid using user-supplied data directly within `<amp-bind>` expressions.
    * If user data must be used, implement strict input validation and sanitization on the server-side before it's used in AMP pages.
    * Be cautious when using complex or dynamic expressions in `<amp-bind>`.

## Attack Surface: [AMP Cache Poisoning](./attack_surfaces/amp_cache_poisoning.md)

**Description:** Exploiting vulnerabilities in the Google AMP Cache or other AMP caches to serve malicious content to users.

**How AMPHTML Contributes:** AMP pages are often served from a CDN cache (like the Google AMP Cache) for performance. This caching mechanism, inherent to the AMP ecosystem, can be exploited to serve malicious content if the cache is poisoned.

**Example:** An attacker finds a way to manipulate the origin server's response for an AMP page, and this malicious response is then cached by the Google AMP Cache, affecting all subsequent users accessing the page through the cache.

**Impact:** High. A successful cache poisoning attack can affect a large number of users, potentially exposing them to XSS, malware, or phishing attacks.

**Risk Severity:** High

**Mitigation Strategies:**

* **Developers:**
    * Implement robust security measures on the origin server to prevent unauthorized modifications of content.
    * Use HTTPS for all communication between the origin server and the AMP cache.
    * Implement proper cache control headers to manage caching behavior.
    * Monitor AMP cache status and report any suspicious activity.

## Attack Surface: [High/Critical Vulnerabilities in Specific AMP Components/Extensions](./attack_surfaces/highcritical_vulnerabilities_in_specific_amp_componentsextensions.md)

**Description:** Security flaws discovered in specific AMP components or extensions that have a high or critical severity and can be exploited by attackers.

**How AMPHTML Contributes:** The AMP ecosystem includes various components and extensions that add functionality. Vulnerabilities within the code of these specific AMP features can introduce new, potentially severe, attack vectors.

**Example:** A newly discovered remote code execution vulnerability exists within a specific version of the `<amp-ad>` component. Attackers can craft AMP pages that exploit this vulnerability to execute arbitrary code on users' browsers.

**Impact:** High to Critical. Depending on the vulnerability, this could lead to remote code execution, significant data breaches, or complete compromise of the user's system within the context of the browser.

**Risk Severity:** High to Critical (depending on the specific vulnerability)

**Mitigation Strategies:**

* **Developers:**
    * Stay informed about security advisories and updates for the AMP HTML library and its components/extensions.
    * Regularly update the AMP HTML library and all used extensions to the latest versions.
    * Avoid using deprecated or outdated components.
    * Carefully evaluate the security implications of using third-party AMP extensions.

