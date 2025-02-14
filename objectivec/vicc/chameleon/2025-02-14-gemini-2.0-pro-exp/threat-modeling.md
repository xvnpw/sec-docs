# Threat Model Analysis for vicc/chameleon

## Threat: [Malicious XSLT Injection (Configuration)](./threats/malicious_xslt_injection__configuration_.md)

*   **Description:**
    *   **What the attacker might do:** The attacker gains control over the XSLT configuration used by Chameleon. This is the *primary* attack vector against Chameleon itself. The attacker can inject malicious XSLT code.
    *   **How:** The attacker leverages XSLT's capabilities (especially with extensions) to execute arbitrary code, read files, make network requests, or manipulate data. This happens because Chameleon *executes* the provided XSLT.
*   **Impact:**
    *   **Arbitrary Code Execution (ACE/RCE):** Full system compromise. The attacker can run any command on the server. This is the most severe outcome.
    *   **Information Disclosure:** Access to sensitive data, files, environment variables, and potentially other systems.
    *   **Denial of Service (DoS):** The server becomes unresponsive.
    *   **Data Corruption/Manipulation:** Output data is altered, potentially leading to security bypasses or data integrity issues.
    *   **Server-Side Request Forgery (SSRF):** The server makes requests to attacker-controlled or internal resources.
*   **Chameleon Component Affected:**
    *   `chameleon.PageTemplate` (and related classes like `PageTemplateFile`): These are the core components that load and *execute* the XSLT. This is where the vulnerability manifests.
    *   Any custom extensions or functions registered with the Chameleon template engine: If these extensions are vulnerable, they can be exploited via the injected XSLT.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Never allow user-supplied XSLT:** Configurations should be static and loaded from a trusted, read-only location. This is the most important mitigation.
    *   **Strictly validate any dynamic configuration:** If *absolutely* necessary (and it almost never is), use an extremely restrictive allowlist for any dynamic parts of the configuration.  *Never* construct XSLT directly from user input.
    *   **Disable XSLT extensions:** Unless strictly required and thoroughly audited, disable all XSLT extensions. This significantly reduces the attack surface.
    *   **Disable external entity loading:** Prevent the use of `document()` and similar functions that load external resources within the XSLT.
    *   **Secure file system permissions:** Ensure that configuration files are read-only for the application user and not writable by any untrusted process.
    *   **Sandboxing:** Consider running the transformation in a sandboxed environment (e.g., a container with limited privileges). This limits the damage an attacker can do even if they achieve code execution.
    *   **Least Privilege:** Run the application with the minimum necessary system privileges.

## Threat: [XXE via Input XML (Input Processing - *If Chameleon is configured to allow it*)](./threats/xxe_via_input_xml__input_processing_-_if_chameleon_is_configured_to_allow_it_.md)

*   **Description:**
    *   **What the attacker might do:** The attacker provides a malicious XML document as input, containing XML External Entities (XXE). *This threat is only relevant if Chameleon is not configured to use a secure XML parser.*
    *   **How:** The attacker crafts an XML document with a `DOCTYPE` declaration that defines external entities. If Chameleon uses an insecure XML parser (or is misconfigured), these entities will be processed. Chameleon itself doesn't *inherently* prevent XXE; it relies on the underlying parser.
*   **Impact:**
    *   **Information Disclosure:** Reading local files (e.g., `/etc/passwd`, configuration files).
    *   **Server-Side Request Forgery (SSRF):** Accessing internal network resources or making requests to external servers.
    *   **Denial of Service (DoS):** Potentially through resource exhaustion.
*   **Chameleon Component Affected:**
    *   `chameleon.PageTemplate` (and related): While Chameleon doesn't *parse* the XML, it *passes* the input XML to the underlying parser. Therefore, it's indirectly involved. The *critical* component is the underlying XML parser (e.g., `lxml.etree`), but Chameleon's configuration determines *which* parser and *how* it's used.
*   **Risk Severity:** High (but *only* if Chameleon is misconfigured; by default, with `lxml`, it should be safe)
*   **Mitigation Strategies:**
    *   **Disable DTD processing:** This is the *primary* mitigation. Configure the XML parser used by Chameleon to *completely* disable Document Type Definition (DTD) processing. With `lxml` (the common choice), use `lxml.etree.XMLParser(resolve_entities=False)`.  Ensure this is the default parser configuration used by Chameleon.
    *   **Use a secure XML parser configuration:** Explicitly configure Chameleon to use a secure XML parser with external entity resolution disabled.  Don't rely on defaults without verifying them.

