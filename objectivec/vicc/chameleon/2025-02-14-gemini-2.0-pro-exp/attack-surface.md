# Attack Surface Analysis for vicc/chameleon

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

*   **Description:** Attackers inject malicious code into Chameleon templates, leading to arbitrary code execution on the server.
    *   **Chameleon Contribution:** Chameleon's core functionality is template rendering. If templates are sourced from untrusted locations or user input is improperly handled within templates, Chameleon becomes the *direct vehicle* for the attack. The vulnerability lies in how the application *uses* Chameleon, making Chameleon the execution engine for the injected code.
    *   **Example:** An attacker uploads a template containing `{{ system('rm -rf /') }}` (or equivalent Python code) disguised as a valid template directive.
    *   **Impact:** Complete server compromise, data theft, data destruction, potential for lateral movement within the network.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Template Source Control:** Load templates *only* from trusted, read-only locations (e.g., the application's codebase).  *Never* load templates directly from user uploads, databases, or external APIs without rigorous validation.
        *   **Input Validation (Whitelist):** If templates *must* be loaded from external sources, implement a strict whitelist-based validation process. Define a very limited set of allowed template structures and characters. Reject any template that doesn't conform precisely.
        *   **Sandboxing:** Consider running the Chameleon rendering process in a sandboxed environment (e.g., a container with limited privileges and resource access) to contain the impact of a successful injection.
        *   **Regular Updates:** Keep Chameleon and its dependencies updated to the latest versions to patch any known vulnerabilities in the templating engine.
        *   **Disable Unsafe Features:** If possible, disable any Chameleon features that allow direct execution of Python code within templates. Investigate configuration options to restrict the capabilities of the templating engine.  This is crucial.

## Attack Surface: [Cross-Site Scripting (XSS) via Context Variables](./attack_surfaces/cross-site_scripting__xss__via_context_variables.md)

*   **Description:** Attackers inject malicious JavaScript into context variables that are then rendered unsafely within Chameleon templates.
    *   **Chameleon Contribution:** Chameleon is *directly responsible* for rendering the context variables within the HTML output. If Chameleon's escaping mechanisms are bypassed, insufficient, or misconfigured, it *directly facilitates* the XSS attack by inserting the malicious script into the rendered page.
    *   **Example:** A user enters `<script>alert('XSS')</script>` into a profile field. If this field is rendered in a Chameleon template without proper escaping, the script will execute in the browser of other users viewing the profile.
    *   **Impact:** Session hijacking, defacement, phishing, malware distribution, data theft (cookies, local storage).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Context-Aware Escaping:** Use Chameleon's built-in escaping functions *correctly* and consistently. Ensure that the escaping method used is appropriate for the context (e.g., HTML escaping for HTML attributes, JavaScript escaping for inline scripts).  This is the *primary* defense and relies on Chameleon's correct implementation.
        *   **Input Validation (Sanitization):** Sanitize all user-supplied data *before* it's passed as a context variable. Remove or encode potentially dangerous characters. This is a defense-in-depth measure.
        *   **Content Security Policy (CSP):** Implement a strong CSP to restrict the sources from which scripts can be loaded, mitigating the impact of successful XSS injections. This is an external mitigation, but important.
        *   **Type Validation:** Validate the *type* of context variables. For example, if a variable is expected to be a number, ensure it's actually a number before passing it to the template.

## Attack Surface: [Path Traversal via Template Selection](./attack_surfaces/path_traversal_via_template_selection.md)

*   **Description:** Attackers manipulate template selection mechanisms to access files outside the intended template directory.
    *   **Chameleon Contribution:** Chameleon *directly* loads and renders templates based on the path provided by the application logic. If this logic is vulnerable to path traversal, Chameleon becomes the *tool* used to access unauthorized files, even if Chameleon itself doesn't have the vulnerability. The vulnerability is in the application's *use* of Chameleon.
    *   **Example:** A URL parameter like `?template=../../etc/passwd` attempts to load the system's password file.
    *   **Impact:** Information disclosure (sensitive files), potential for code execution if an attacker can load a malicious template (which would then trigger SSTI).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid User Input in Template Paths:** *Never* use user-supplied data directly in template paths passed to Chameleon.
        *   **Whitelist Allowed Templates:** Maintain a predefined list of allowed template names or paths. Reject any request that attempts to load a template outside this list. This is the most robust defense.
        *   **Normalize Paths:** If user input *must* be used indirectly to influence template selection, normalize the resulting path to remove any `../` sequences *before* passing it to Chameleon. Use secure path manipulation functions provided by the operating system or programming language.
        *   **Chroot or Jail:** Consider running the application (or at least the template rendering component, including Chameleon) in a chroot jail or similar restricted environment to limit the files it can access.

