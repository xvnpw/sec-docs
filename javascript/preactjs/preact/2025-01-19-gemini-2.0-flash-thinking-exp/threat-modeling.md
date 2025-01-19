# Threat Model Analysis for preactjs/preact

## Threat: [Cross-Site Scripting (XSS) via Unsafe HTML Rendering](./threats/cross-site_scripting__xss__via_unsafe_html_rendering.md)

**Description:** An attacker can inject malicious scripts into the application if user-provided data is directly rendered as HTML without proper sanitization within Preact components. This script will then execute in the victim's browser when the component is rendered, potentially allowing the attacker to steal cookies, session tokens, or perform actions on behalf of the user.

**Impact:** Account takeover, data theft, redirection to malicious sites, defacement of the application.

**Affected Preact Component:** JSX rendering process within components. Specifically when using properties like `dangerouslySetInnerHTML` or directly embedding unsanitized strings in JSX.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Always sanitize user-provided data before rendering it in JSX.
* Utilize Preact's built-in mechanisms for escaping HTML entities when rendering dynamic content.
* Avoid using `dangerouslySetInnerHTML` unless absolutely necessary and the content is from a trusted source.
* Employ Content Security Policy (CSP) headers to restrict the sources from which the browser is allowed to load resources.

## Threat: [Supply Chain Attacks via Compromised Dependencies](./threats/supply_chain_attacks_via_compromised_dependencies.md)

**Description:** Attackers could compromise dependencies used by the Preact application, *including Preact itself*, by injecting malicious code. This malicious code would then be included in the application's build and could execute in users' browsers.

**Impact:** Wide-ranging impact, including data theft, malware distribution, and application compromise.

**Affected Preact Component:** The entire application build process and any dependencies used, *including Preact itself*.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Regularly audit project dependencies for known vulnerabilities.
* Use dependency scanning tools to detect vulnerable packages.
* Implement Software Bill of Materials (SBOM) practices.
* Verify the integrity of downloaded dependencies using checksums.
* Consider using dependency pinning or lock files to ensure consistent dependency versions.

