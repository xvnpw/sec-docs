# Attack Surface Analysis for denoland/deno

## Attack Surface: [Overly Permissive Permissions](./attack_surfaces/overly_permissive_permissions.md)

*   **Description:**  The application is granted more Deno-specific permissions than it needs, allowing attackers to leverage compromised code to access sensitive resources or execute system commands *through Deno's APIs*.
*   **How Deno Contributes:** Deno's core security model relies on explicit permissions.  Misconfiguration (granting too many permissions) is a direct Deno-specific risk. This is the *defining* security feature of Deno.
*   **Example:** An application with `--allow-all` or `--allow-run` allows injected code to execute arbitrary shell commands via `Deno.run`.  Or, `--allow-write=/` allows writing to any file on the system.
*   **Impact:**  Complete system compromise, data exfiltration, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:** Grant *only* the absolute minimum Deno permissions required.
    *   **Specific Flags:** Use specific paths/domains for `--allow-read`, `--allow-write`, `--allow-net` (e.g., `--allow-net=example.com:443`, `--allow-read=/tmp/data`).  Avoid wildcards.
    *   **Environment-Specific Permissions:** Use environment variables to control permissions differently in development, staging, and production.
    *   **Regular Audits:**  Periodically review and reduce granted permissions.
    *   **`--deny-*` Flags:** Explicitly deny permissions to specific modules, even if they request them.

## Attack Surface: [Malicious/Compromised Dependencies (URL Import Focus)](./attack_surfaces/maliciouscompromised_dependencies__url_import_focus_.md)

*   **Description:** A third-party Deno module, *specifically imported via a URL*, contains malicious code or is compromised after being imported.
*   **How Deno Contributes:** Deno's *primary* module resolution mechanism is via URLs. This decentralized approach, while flexible, introduces a higher risk of pulling in compromised code if not managed correctly, compared to traditional package managers with central registries (although those are not immune).
*   **Example:** An attacker publishes a module at a URL that mimics a legitimate module, and a developer accidentally imports the malicious URL.
*   **Impact:**  Code execution, data exfiltration, system compromise (depending on granted permissions).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Lock Files:** Use `deno.lock` to pin dependency versions *and their content hashes* to ensure integrity.  This is crucial for URL imports.
    *   **Import Maps:** Use explicit import maps to *strictly control* where modules are fetched from, preventing dependency confusion attacks and unauthorized URL imports.
    *   **Careful Selection:**  Choose well-maintained and reputable modules.  Review the source code of critical dependencies if feasible (especially if importing directly from a URL).

## Attack Surface: [Remote Code Execution via URL Imports](./attack_surfaces/remote_code_execution_via_url_imports.md)

*   **Description:** An attacker injects a malicious URL into a Deno `import` statement, causing the application to fetch and execute arbitrary code.
*   **How Deno Contributes:** This is a *direct consequence* of Deno's URL-based import system.  It's the primary mechanism for code execution attacks specific to Deno.
*   **Example:** If user input is used directly in an import statement (e.g., `import * as mod from "${userInput}";`), an attacker can provide a URL to their own server hosting malicious code.
*   **Impact:**  Complete code execution, system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid User Input in Imports:**  *Never* use user-supplied data directly in Deno import statements.
    *   **Sanitize and Validate:** If user input *must* influence import paths, rigorously sanitize and validate it against a *strict whitelist* of allowed URLs/paths.
    *   **Lock Files:**  Use `deno.lock` to ensure that only known and verified code (with matching hashes) is fetched.
    *   **Import Maps:** Use import maps to *completely restrict* the sources from which modules can be loaded, preventing any unexpected URL imports.

## Attack Surface: [Man-in-the-Middle (MITM) Attacks on Imports (HTTPS Bypass)](./attack_surfaces/man-in-the-middle__mitm__attacks_on_imports__https_bypass_.md)

*   **Description:** An attacker intercepts the network traffic between the Deno application and a remote server hosting a module, injecting malicious code, *specifically bypassing or exploiting weaknesses in HTTPS*.
*   **How Deno Contributes:**  Deno's reliance on fetching modules over the network, and *specifically its handling of HTTPS*, makes it susceptible to MITM attacks if certificate validation is misconfigured or bypassed.
*   **Example:** An attacker uses a compromised or self-signed certificate, and Deno's certificate validation is either disabled or improperly configured, allowing the attacker to inject malicious code into a module being fetched.
*   **Impact:**  Code execution, system compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **HTTPS Only:**  Always use HTTPS for remote imports.  *Enforce* this.
    *   **Certificate Validation:** Ensure Deno's certificate validation is *enabled and functioning correctly*.  Do *not* disable certificate checks.
    *   **Lock Files:**  Use `deno.lock` to verify the integrity of fetched modules (via hashes), preventing the execution of modified code even if HTTPS is compromised.
    *   **Trusted Root CAs:** Ensure Deno is using a trusted set of root Certificate Authorities.

## Attack Surface: [Unsafe FFI Usage](./attack_surfaces/unsafe_ffi_usage.md)

*   **Description:**  Incorrect or insecure use of Deno's Foreign Function Interface (FFI) to call native code (C/C++, Rust) introduces vulnerabilities, *bypassing Deno's sandbox*.
*   **How Deno Contributes:** Deno's FFI provides a powerful way to extend functionality, but it *explicitly bypasses* Deno's sandboxing and permission model, creating a direct and significant security risk if misused.
*   **Example:**  A Deno application uses FFI to call a vulnerable C library function that has a buffer overflow, allowing an attacker to execute arbitrary code *outside* of Deno's sandbox.
*   **Impact:**  Arbitrary code execution, system compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Memory-Safe Languages:** Prefer using memory-safe languages like Rust for native extensions.
    *   **Careful Validation:**  Thoroughly validate and sanitize *all* data passed to native code through FFI.
    *   **Audited Libraries:**  Use well-vetted and audited native libraries.
    *   **Secure Bindings:**  Ensure that the FFI bindings are used correctly and securely, preventing common vulnerabilities like buffer overflows.
    *   **`--allow-ffi-unsafe-`:** Use with *extreme caution*, and only after a thorough security review.  Consider alternatives if possible.

## Attack Surface: [Deno Runtime/Standard Library Vulnerabilities (Zero-Days)](./attack_surfaces/deno_runtimestandard_library_vulnerabilities__zero-days_.md)

*   **Description:**  *Zero-day* vulnerabilities in the Deno runtime itself (`Deno.core`) or the standard library (`std`) are exploited.
*   **How Deno Contributes:**  This is a risk inherent to *any* runtime environment, but it's listed here because it's a Deno-specific component.
*   **Example:** A zero-day vulnerability in Deno's `fetch` implementation allows an attacker to bypass security checks and access arbitrary files, *before a patch is available*.
*   **Impact:**  Varies depending on the vulnerability, but can range from denial of service to arbitrary code execution.
*   **Risk Severity:** High to Critical (depending on the specific vulnerability)
*   **Mitigation Strategies:**
    *   **Rapid Patching:**  Update to the latest stable version of Deno *immediately* upon the release of security patches.
    *   **Monitor Advisories:**  Actively follow Deno's security advisories and announcements.
    *   **Defense in Depth:** Implement other security measures (e.g., network segmentation, least privilege) to limit the impact of a potential zero-day exploit.

