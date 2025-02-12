# Attack Surface Analysis for ampproject/amphtml

## Attack Surface: [Vulnerable Third-Party AMP Components](./attack_surfaces/vulnerable_third-party_amp_components.md)

*   **Description:** AMP's reliance on pre-built components, especially those from third-party sources, introduces a significant risk if those components contain vulnerabilities.
*   **How AMP HTML Contributes:** AMP *requires* the use of specific, pre-approved components for most functionality. This inherently limits developer control and increases the impact of vulnerabilities in these components.  The "walled garden" nature of AMP makes it difficult to add custom security layers around these components.
*   **Example:** An `amp-ad` component from a compromised ad network contains an XSS vulnerability, allowing the injection of malicious scripts into any AMP page using that network.
*   **Impact:**
    *   Cross-Site Scripting (XSS)
    *   Data Exfiltration
    *   Session Hijacking
    *   Defacement (of the AMP page)
*   **Risk Severity:** High to Critical (depending on the component's privileges and the nature of the vulnerability).
*   **Mitigation Strategies:**
    *   **Strict Component Vetting:**  *Only* use officially supported and thoroughly vetted third-party components.  Prioritize components from well-known, reputable providers with a strong security track record.
    *   **Automated Updates:** Implement *automated* updates for all AMP components.  This is crucial to ensure rapid patching of vulnerabilities.
    *   **Security Audits (of Components):** If possible, conduct independent security audits of critical third-party components, including code review.  This is especially important for components handling sensitive data.
    *   **Strong Content Security Policy (CSP):**  Implement the *strictest possible* CSP, even within the AMP context.  This can limit the damage from XSS vulnerabilities, even if a component is compromised.
    *   **Minimize Component Usage:**  Use the absolute *minimum* number of components required.  Each additional component increases the attack surface.
    *   **Self-Hosting (High-Risk Components):** For *extremely* high-risk components (e.g., those handling financial transactions), consider self-hosting if feasible and if your security infrastructure is robust enough.  This gives you full control over the component's security.

## Attack Surface: [Exploiting AMP Validator Bypasses or Specification Flaws](./attack_surfaces/exploiting_amp_validator_bypasses_or_specification_flaws.md)

*   **Description:** New vulnerabilities in the AMP validator itself, or ambiguities/flaws in the AMP specification, could allow attackers to bypass validation and inject malicious code that *should* have been blocked.
*   **How AMP HTML Contributes:** The AMP validator is the *core* security mechanism of AMP.  Any bypass completely undermines the security guarantees of the framework.  The rapidly evolving nature of the AMP specification increases the risk of new vulnerabilities being introduced.
*   **Example:** A newly discovered zero-day vulnerability in the AMP validator allows an attacker to inject a specially crafted `amp-script` tag that bypasses all restrictions and executes arbitrary JavaScript in the main browser context.
*   **Impact:**
    *   Full Cross-Site Scripting (XSS) – escaping the AMP sandbox.
    *   Complete Data Exfiltration
    *   Bypassing *all* AMP security restrictions
    *   Potential for full site compromise (if the attacker can leverage the XSS to attack the origin server)
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Immediate Updates:**  Apply *all* AMP runtime and validator updates *immediately* upon release.  This is the *most critical* mitigation.  Monitor AMP security announcements closely.
    *   **Continuous Re-validation:**  Implement a system for *continuously* re-validating AMP pages against the latest validator version.  This helps detect bypasses that may have been introduced by specification changes.
    *   **Security Monitoring:**  Actively monitor security advisories and mailing lists related to the AMP Project.  Be prepared to react quickly to any reported vulnerabilities.
    *   **Defense in Depth:**  Do *not* rely solely on the AMP validator for security.  Implement additional security measures on the origin server, as a compromised AMP page could be used as a stepping stone to attack the main site.
    * **Report Suspected Issues:** If a developer suspects or finds a potential bypass, they should immediately and responsibly disclose it to the AMP Project.

